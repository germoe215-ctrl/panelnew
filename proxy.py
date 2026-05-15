"""ProxyManager — pool, rotation, health checks, and SOCKS support for aiohttp.

Supported schemes:
  http://, https://      — HTTP CONNECT proxy (DNS resolved at proxy)
  socks4://              — SOCKS4 (no auth)
  socks5://              — SOCKS5 (DNS resolved locally — leaks targets!)
  socks5h://             — SOCKS5 (DNS resolved at proxy — preferred)

Usage:
    pm = ProxyManager(["socks5h://user:pass@host:1080"])
    await pm.health_check()
    async with pm.request("GET", url, headers=h) as resp:
        text = await resp.text()
    await pm.close()

A single ProxyManager owns one shared aiohttp.ClientSession for HTTP/direct
traffic plus one cached session per SOCKS proxy (since each SOCKS connector is
bound to a single proxy URL).
"""

from __future__ import annotations

import asyncio
import random
import re
from contextlib import asynccontextmanager
from typing import Optional
from urllib.parse import urlparse

import aiohttp


# aiohttp_socks errors do NOT inherit from any aiohttp class — they inherit
# directly from Exception. This means they won't be caught by the aiohttp
# error handlers in request() and would silently be attributed to probe
# targets rather than the proxy. Build a unified tuple at import time.
_PROXY_ERROR_TYPES: tuple = (
    aiohttp.ClientProxyConnectionError,
    aiohttp.ClientHttpProxyError,
)
try:
    from aiohttp_socks import ProxyConnectionError as _SocksConnErr
    from aiohttp_socks import ProxyTimeoutError as _SocksTimeoutErr
    from aiohttp_socks import ProxyError as _SocksErr
    _PROXY_ERROR_TYPES = _PROXY_ERROR_TYPES + (_SocksConnErr, _SocksTimeoutErr, _SocksErr)
except ImportError:
    pass


_SOCKS_SCHEMES = ("socks4://", "socks5://", "socks5h://")
_HTTP_SCHEMES = ("http://", "https://")
ALL_SCHEMES = _HTTP_SCHEMES + _SOCKS_SCHEMES
_VALID_ROTATIONS = ("round-robin", "random")


def is_socks(url: str) -> bool:
    return url.startswith(_SOCKS_SCHEMES)


# Strip "user:password@" credentials from any string for safe logging /
# error messages — works on bare URLs and embedded URLs in error text.
# The character class excludes URL-path/query separators and whitespace;
# greedy matching with backtracking lands on the LAST '@' in the userinfo,
# so passwords containing literal '@' get fully scrubbed.
_CRED_RE = re.compile(r"(?P<scheme>\w+://)[^/?#\s]*@")


def scrub_credentials(text: str) -> str:
    """Remove ``user:pass@`` from any URLs found in ``text``."""
    if not text:
        return text
    return _CRED_RE.sub(lambda m: m.group("scheme") + "***@", text)


def parse_proxy_list(text: str) -> list[str]:
    """Parse a string containing one or more proxy URLs (newline or comma
    separated). Strips comments (# …) and whitespace. Returns deduped list."""
    if not text:
        return []
    raw = text.replace(",", "\n").splitlines()
    seen: set[str] = set()
    out: list[str] = []
    for line in raw:
        url = line.strip()
        if not url or url.startswith("#"):
            continue
        if url in seen:
            continue
        seen.add(url)
        out.append(url)
    return out


def validate_proxy_url(url: str) -> Optional[str]:
    """Return None if valid, error message otherwise.

    Validates both the scheme prefix and the URL structure (host + port).
    Catches malformed URLs upfront so they don't crash deep inside the
    request loop where the error gets swallowed by ``except Exception``.
    """
    safe = scrub_credentials(url)
    if not url.startswith(ALL_SCHEMES):
        return (
            f"Proxy must start with one of "
            f"{', '.join(ALL_SCHEMES)} — got {safe!r}"
        )
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        return f"Proxy URL is malformed: {safe!r}"
    if not parsed.hostname:
        return f"Proxy URL missing host: {safe!r}"
    # urlparse raises ValueError on .port access if the port is out of range,
    # so fetch it inside a try/except.
    try:
        port = parsed.port
    except ValueError:
        return f"Proxy URL port out of range (1–65535): {safe!r}"
    if port is None:
        return f"Proxy URL missing port (e.g. host:1080): {safe!r}"
    if port == 0:
        return f"Proxy URL port 0 is not a valid connect target: {safe!r}"
    return None


class ProxyManager:
    """Pool of proxies with rotation, health checks, and per-request failover."""

    def __init__(
        self,
        urls: Optional[list[str]] = None,
        *,
        retries: int = 2,
        rotation: str = "round-robin",  # or "random"
        connection_limit: int = 200,
    ):
        self.urls: list[str] = list(urls) if urls else []
        self.dead: set[str] = set()
        self.retries = max(0, retries)
        if rotation not in _VALID_ROTATIONS:
            raise ValueError(
                f"rotation must be one of {_VALID_ROTATIONS}; got {rotation!r}"
            )
        self.rotation = rotation
        self.connection_limit = connection_limit
        self._idx = 0
        self._lock = asyncio.Lock()
        self._http_session: Optional[aiohttp.ClientSession] = None
        self._socks_sessions: dict[str, aiohttp.ClientSession] = {}
        # Diagnostic counters — surfaced in caller heartbeats so the user can
        # see at a glance whether proxy data is actually being burned through.
        self.requests_routed: int = 0  # successful proxy connects (excl. direct)
        self.requests_direct: int = 0  # direct connects when no proxy configured

    # ── pool state ────────────────────────────────────────────────────────────

    @property
    def total(self) -> int:
        return len(self.urls)

    @property
    def alive_count(self) -> int:
        return len(self.urls) - len(self.dead)

    def alive(self) -> list[str]:
        return [u for u in self.urls if u not in self.dead]

    async def _next(self, exclude: Optional[set[str]] = None) -> Optional[str]:
        """Pick the next live proxy not in ``exclude``. None if pool exhausted."""
        skip = exclude or set()
        async with self._lock:
            if not self.urls:
                return None
            live = [u for u in self.urls if u not in self.dead and u not in skip]
            if not live:
                return None
            if self.rotation == "random":
                return random.choice(live)
            # Round-robin: scan from current index, skipping dead and excluded
            n = len(self.urls)
            for _ in range(n):
                p = self.urls[self._idx % n]
                self._idx = (self._idx + 1) % n
                if p not in self.dead and p not in skip:
                    return p
            return None

    async def _mark_dead(self, url: str) -> None:
        async with self._lock:
            self.dead.add(url)

    async def reset_dead(self) -> None:
        async with self._lock:
            self.dead.clear()

    # ── session management ────────────────────────────────────────────────────

    def _ensure_http_session(self) -> aiohttp.ClientSession:
        if self._http_session is None or self._http_session.closed:
            self._http_session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(
                    ssl=False,
                    limit=self.connection_limit,
                    # Disable keep-alive pooling across unique hosts — scanning
                    # thousands of distinct IPs accumulates idle sockets in the
                    # pool which hold file descriptors and kernel memory.
                    enable_cleanup_closed=True,
                    keepalive_timeout=5,
                )
            )
        return self._http_session

    def _ensure_socks_session(self, proxy_url: str) -> aiohttp.ClientSession:
        existing = self._socks_sessions.get(proxy_url)
        if existing is not None and not existing.closed:
            return existing
        try:
            from aiohttp_socks import ProxyConnector, ProxyType
        except ImportError as e:
            raise RuntimeError(
                "aiohttp-socks is required for SOCKS proxy support. "
                "Install with: pip install aiohttp-socks"
            ) from e

        # aiohttp_socks doesn't accept the `socks5h://` scheme directly. Parse
        # the URL ourselves and build the connector with rdns=True to route
        # DNS resolution through the proxy (closing the DNS leak).
        parsed = urlparse(proxy_url)
        if parsed.scheme == "socks5h":
            proxy_type, rdns = ProxyType.SOCKS5, True
        elif parsed.scheme == "socks5":
            proxy_type, rdns = ProxyType.SOCKS5, False
        elif parsed.scheme == "socks4":
            proxy_type, rdns = ProxyType.SOCKS4, False
        else:
            raise ValueError(f"Unsupported SOCKS scheme: {parsed.scheme!r}")
        if not parsed.hostname or not parsed.port:
            raise ValueError(
                f"SOCKS proxy URL missing host or port: "
                f"{scrub_credentials(proxy_url)!r}"
            )

        connector = ProxyConnector(
            host=parsed.hostname,
            port=parsed.port,
            proxy_type=proxy_type,
            username=parsed.username,
            password=parsed.password,
            rdns=rdns,
            ssl=False,
            limit=self.connection_limit,
        )
        session = aiohttp.ClientSession(connector=connector)
        self._socks_sessions[proxy_url] = session
        return session

    async def close(self) -> None:
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()
        for s in list(self._socks_sessions.values()):
            if not s.closed:
                await s.close()
        self._socks_sessions.clear()

    # ── request with auto-failover ────────────────────────────────────────────

    # Proxy-side failures → mark this proxy dead and rotate to the next.
    # Includes aiohttp_socks errors which do NOT inherit from aiohttp classes
    # and would otherwise fall through uncaught, silently blaming targets.
    _PROXY_ERRORS = _PROXY_ERROR_TYPES
    # Other connection-time failures (target side or ambiguous) → retry via
    # next proxy but DON'T mark dead. Must be caught AFTER _PROXY_ERRORS.
    _OTHER_CONNECT_ERRORS = (
        aiohttp.ClientConnectorError,
        aiohttp.ServerDisconnectedError,
        ConnectionResetError,
        asyncio.TimeoutError,
    )

    @asynccontextmanager
    async def request(self, method: str, url: str, **kwargs):
        """Issue a request through the pool with auto-rotation on proxy failure.

        Two distinct phases:
          1. Connect with retry — try proxies until one establishes the
             connection. Connection-level errors are caught here.
          2. Yield the response — caller-side errors (timeout during read,
             JSON parse, etc.) propagate normally and do NOT trigger retry.
             This is required for correctness: a request that reached the
             target may have side-effects, so silently retrying is unsafe.
        """
        # Direct connection if no proxies configured
        if not self.urls:
            session = self._ensure_http_session()
            async with session.request(method, url, **kwargs) as resp:
                self.requests_direct += 1
                yield resp
            return

        last_err: Optional[BaseException] = None
        tried: set[str] = set()
        max_attempts = max(1, min(self.retries + 1, max(self.alive_count, 1)))

        cm = None
        resp = None
        for _ in range(max_attempts):
            proxy = await self._next(exclude=tried)
            if proxy is None:
                break  # pool exhausted for this request
            tried.add(proxy)

            req_kwargs = dict(kwargs)
            if is_socks(proxy):
                session = self._ensure_socks_session(proxy)
            else:
                session = self._ensure_http_session()
                req_kwargs["proxy"] = proxy

            cm = session.request(method, url, **req_kwargs)
            try:
                resp = await cm.__aenter__()
                self.requests_routed += 1  # confirms proxy actually carried this request
                break  # connection established — exit retry loop
            except self._PROXY_ERRORS as e:
                last_err = e
                tag = proxy.split("@")[-1]
                msg = scrub_credentials(str(e))[:120] or type(e).__name__
                print(f"[proxy] ✗ {tag} — {msg} (marking dead)", flush=True)
                await self._mark_dead(proxy)
                cm = None
                continue
            except self._OTHER_CONNECT_ERRORS as e:
                last_err = e
                cm = None
                continue

        if cm is None or resp is None:
            alive = self.alive_count
            if alive == 0:
                raise RuntimeError(
                    "ProxyManager: all proxies are dead — check credentials, "
                    "host reachability, or use --skip-proxy-health-check to debug"
                )
            if last_err is not None:
                raise last_err
            raise RuntimeError("ProxyManager: no live proxies available")

        # Phase 2: yield response. Caller exceptions propagate; we just clean up.
        try:
            yield resp
        finally:
            try:
                await cm.__aexit__(None, None, None)
            except Exception:
                pass

    # ── health check ──────────────────────────────────────────────────────────

    # Fallback URLs tried in order when the primary check URL fails.
    # Residential proxies sometimes have inconsistent access to specific hosts.
    _CHECK_URLS = [
        "https://api.ipify.org/?format=json",
        "https://checkip.amazonaws.com/",
        "https://ifconfig.me/ip",
    ]

    async def health_check(
        self,
        test_url: str = "https://api.ipify.org/?format=json",
        timeout: float = 20.0,
    ) -> dict[str, dict]:
        """Probe every proxy in parallel. Mark unreachable ones as dead.

        Resets the dead set first so re-running ``health_check`` gives a
        live re-evaluation rather than carrying forward prior failures.

        Uses a 20 s default timeout — residential rotating proxies acquire a
        new IP per connection and routinely take 10–15 s. Tries two attempts
        before marking dead so transient pool rotation errors don't kill the
        proxy permanently.
        """
        await self.reset_dead()

        async def _attempt(url: str, check_url: str) -> tuple[bool, str, dict]:
            """Single probe attempt. Returns (success, egress_ip_or_'?', info)."""
            req_kwargs: dict = {"timeout": aiohttp.ClientTimeout(total=timeout)}
            try:
                if is_socks(url):
                    session = self._ensure_socks_session(url)
                else:
                    session = self._ensure_http_session()
                    req_kwargs["proxy"] = url
                async with session.get(check_url, **req_kwargs) as resp:
                    if resp.status >= 400:
                        return False, "?", {"ok": False, "status": resp.status}
                    try:
                        text = await resp.text()
                        # ipify returns JSON; others return a bare IP string
                        try:
                            import json as _json
                            ip = _json.loads(text).get("ip", text.strip())
                        except Exception:
                            ip = text.strip()
                    except Exception:
                        ip = "?"
                    return True, ip, {"ok": True, "status": resp.status, "ip": ip}
            except Exception as e:
                msg = scrub_credentials(str(e))[:140] or type(e).__name__
                return False, "?", {"ok": False, "error": msg}

        async def probe(url: str) -> tuple[str, dict]:
            # Two attempts across fallback URLs before giving up.
            # Residential proxies rotate IPs; first attempt may hit a
            # temporarily overloaded exit node.
            urls_to_try = [test_url] + [u for u in self._CHECK_URLS if u != test_url]
            last_info: dict = {"ok": False, "error": "no attempt made"}
            for check_url in urls_to_try[:2]:  # at most 2 attempts
                ok, ip, info = await _attempt(url, check_url)
                if ok:
                    return url, info
                last_info = info

            await self._mark_dead(url)
            return url, last_info

        pairs = await asyncio.gather(*[probe(u) for u in self.urls])
        return dict(pairs)

    def __repr__(self) -> str:
        return (
            f"ProxyManager(total={self.total}, alive={self.alive_count}, "
            f"rotation={self.rotation!r})"
        )
