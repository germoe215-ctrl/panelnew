#!/usr/bin/env python3
"""
EnvHarvester – Web API server
Run: python api.py  →  open http://localhost:8000
"""

import asyncio
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Optional

import uuid

import uvicorn
from fastapi import FastAPI, File, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from harvester import init_db as _init_schema
from proxy import ProxyManager, parse_proxy_list, validate_proxy_url

try:
    import aiomysql as _aiomysql  # type: ignore
except Exception:
    _aiomysql = None  # type: ignore

try:
    import asyncpg as _asyncpg  # type: ignore
except Exception:
    _asyncpg = None  # type: ignore

# ── paths ──────────────────────────────────────────────────────────────────────

BASE_DIR   = Path(__file__).resolve().parent
DB_PATH    = BASE_DIR / "research_results.db"
STATIC_DIR = BASE_DIR / "static"
HARVESTER  = BASE_DIR / "harvester.py"
LOG_DIR    = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

# ── app ────────────────────────────────────────────────────────────────────────

app = FastAPI(title="EnvHarvester", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── state ──────────────────────────────────────────────────────────────────────

_proc: Optional[subprocess.Popen] = None
_start_mono: Optional[float] = None
_log_path: Optional[Path] = None
_proc_lock: Optional[asyncio.Lock] = None
_tee_thread: Optional[threading.Thread] = None
_tee_stop = threading.Event()
# "finished" — process exited on its own; "stopped" — user clicked Stop;
# None — never run / currently running.
_last_run_state: Optional[str] = None


def _get_lock() -> asyncio.Lock:
    """Lazy-construct the proc lock so it binds to the running event loop."""
    global _proc_lock
    if _proc_lock is None:
        _proc_lock = asyncio.Lock()
    return _proc_lock

# In-memory ring buffer of harvester log lines for real-time UI streaming.
# Each entry is (sequence_id, line). Older entries are evicted past _LOG_MAX.
_LOG_MAX = 1000
_log_lines: list[tuple[int, str]] = []
_log_seq: int = 0
_log_lock = threading.Lock()


def _push_log_line(line: str) -> None:
    global _log_seq
    with _log_lock:
        _log_seq += 1
        _log_lines.append((_log_seq, line.rstrip()))
        if len(_log_lines) > _LOG_MAX:
            del _log_lines[: len(_log_lines) - _LOG_MAX]


def _get_log_lines_after(after_seq: int) -> tuple[int, list[tuple[int, str]]]:
    with _log_lock:
        latest = _log_seq
        out = [e for e in _log_lines if e[0] > after_seq]
        return latest, out


# ── database ───────────────────────────────────────────────────────────────────

def _open_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=3000")
    return conn


# Single source of truth for schema lives in harvester.init_db. We just call
# it at startup to materialise the tables/indexes; the harvester subprocess
# also calls it on each launch (idempotent).
try:
    _init_schema(DB_PATH).close()
except Exception as _schema_err:
    print(
        f"[api] FATAL: cannot initialise database at {DB_PATH}: {_schema_err}",
        file=sys.stderr,
    )
    sys.exit(1)

# ── targets token store ────────────────────────────────────────────────────────
# Maps UUID token → (temp_file_path, created_monotonic).
# Tokens are consumed (popped) when /api/start runs, and otherwise reaped
# automatically: any token older than _TOKEN_TTL is purged on next access,
# and the dict is hard-capped at _TOKEN_MAX entries (oldest evicted first).
_TOKEN_TTL = 60 * 60   # 1 hour
_TOKEN_MAX = 50
_targets_tokens: dict[str, tuple[str, float]] = {}
_tokens_lock = threading.Lock()


def _reap_tokens() -> None:
    """Remove expired tokens (best-effort: also unlinks their temp files)."""
    now = time.monotonic()
    with _tokens_lock:
        expired = [
            t for t, (_, ts) in _targets_tokens.items()
            if now - ts > _TOKEN_TTL
        ]
        for t in expired:
            path, _ = _targets_tokens.pop(t)
            try:
                os.unlink(path)
            except OSError:
                pass


def _store_token(path: str) -> str:
    """Register a temp file under a fresh UUID token. Enforces TTL + size cap."""
    _reap_tokens()
    token = str(uuid.uuid4())
    with _tokens_lock:
        # Hard cap: evict oldest until we're below the limit
        while len(_targets_tokens) >= _TOKEN_MAX:
            oldest = min(_targets_tokens.items(), key=lambda kv: kv[1][1])[0]
            old_path, _ = _targets_tokens.pop(oldest)
            try:
                os.unlink(old_path)
            except OSError:
                pass
        _targets_tokens[token] = (path, time.monotonic())
    return token


def _consume_token(token: str) -> Optional[str]:
    """Pop a token. Returns the temp file path or None if missing/expired."""
    _reap_tokens()
    with _tokens_lock:
        entry = _targets_tokens.pop(token, None)
    if entry is None:
        return None
    path, _ = entry
    return path if os.path.exists(path) else None


# ── models ─────────────────────────────────────────────────────────────────────

class StartRequest(BaseModel):
    concurrency: int = 200
    laravel_targets: Optional[str] = None
    targets_token: Optional[str] = None  # token from /api/upload-targets
    proxy: Optional[str] = None  # one URL or newline/comma-separated list
    proxy_rotation: Optional[str] = "round-robin"  # or "random"
    proxy_retries: Optional[int] = 2
    skip_proxy_health_check: bool = False
    enable_crtsh: bool = False
    enable_verify: bool = False
    auto_expand_subnet: bool = False
    asns: Optional[str] = None          # newline-separated AS numbers from UI textarea
    ipinfo_token: Optional[str] = None  # prefer IPINFO_TOKEN env var over this field
    fast_paths: Optional[bool] = None   # None=auto, True=force fast (3 paths), False=force all
    max_hosts_per_run: int = 100_000    # 0 = unlimited
    enable_tcp_prefilter: bool = True   # eliminate dark IPs before HTTP probing
    enable_subnet_expand: bool = True   # deep-scan /24 neighbors of confirmed hit IPs
    scan_mode: str = "laravel"          # "laravel" | "cpanel" | "github" | "wordpress" | "backlink" | "cleanup_backlinks"
    github_token: Optional[str] = None
    enable_urlscan: bool = False
    urlscan_key: Optional[str] = None


class ProxyTestRequest(BaseModel):
    proxy: str  # newline/comma-separated proxy URLs


# ── routes ─────────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    index = STATIC_DIR / "index.html"
    if not index.exists():
        return HTMLResponse("<h1>static/index.html not found</h1>", status_code=404)
    return FileResponse(str(index))


@app.post("/api/upload-targets")
async def upload_targets(file: UploadFile = File(...)):
    """Accept a plain-text file of targets (one per line, ≤100 MB).

    Returns a token to pass as ``targets_token`` in /api/start.
    Tokens are single-use — consumed when the scan starts.
    """
    MAX_UPLOAD = 100 * 1024 * 1024  # 100 MB

    def _safe_unlink(path: str) -> None:
        try:
            os.unlink(path)
        except OSError:
            pass

    tf = tempfile.NamedTemporaryFile(mode="wb", suffix=".txt", delete=False)
    targets_path = tf.name
    try:
        total = 0
        while True:
            chunk = await file.read(256 * 1024)  # 256 KB chunks
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD:
                tf.close()
                _safe_unlink(targets_path)
                return {"ok": False, "error": "File too large (max 100 MB)"}
            tf.write(chunk)
        tf.close()

        # Count non-empty, non-comment lines
        with open(targets_path, "r", errors="replace") as fh:
            line_count = sum(
                1 for ln in fh
                if ln.strip() and not ln.strip().startswith("#")
            )

        if line_count == 0:
            _safe_unlink(targets_path)
            return {"ok": False, "error": "Uploaded file contains no targets (empty or only comments)"}

        token = _store_token(targets_path)
        return {"ok": True, "token": token, "lines": line_count, "bytes": total}
    except Exception as e:
        try:
            tf.close()
        except OSError:
            pass
        _safe_unlink(targets_path)
        # Don't leak raw exception text to the client.
        return {"ok": False, "error": f"Upload failed ({type(e).__name__})"}


@app.post("/api/proxy-test")
async def proxy_test(req: ProxyTestRequest):
    """Health-check one or more proxies. Returns per-proxy status + egress IP."""
    urls = parse_proxy_list(req.proxy or "")
    if not urls:
        return {"ok": False, "error": "No proxy URLs provided"}
    for url in urls:
        err = validate_proxy_url(url)
        if err:
            return {"ok": False, "error": err}

    pm = ProxyManager(urls)
    try:
        results = await pm.health_check(timeout=20.0)
    finally:
        await pm.close()

    out = []
    for url, info in results.items():
        # Strip credentials from displayed URL
        safe = url.split("@")[-1] if "@" in url else url
        out.append({
            "proxy": safe,
            "ok": bool(info.get("ok")),
            "egress_ip": info.get("ip"),
            "status": info.get("status"),
            "error": info.get("error"),
        })
    return {"ok": True, "results": out, "alive": pm.alive_count, "total": pm.total}


def _terminate_proc(proc: subprocess.Popen, timeout: float = 15.0) -> None:
    """Terminate a Popen process group, escalating to SIGKILL if needed.

    15-second grace period: the harvester has a SIGTERM handler that flushes
    the in-memory probed_hosts batch (up to 50 hosts) to the DB before exit.
    A short timeout would SIGKILL it before flush completes, losing resume
    progress for those hosts on the next run.
    """
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        try:
            proc.terminate()
        except Exception:
            return
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


@app.post("/api/start")
async def start_harvester(req: StartRequest):
    global _proc, _start_mono, _log_path, _tee_thread, _last_run_state

    # Up-front validation — runs BEFORE consuming any token or writing any
    # temp file, so a bad input doesn't waste the user's upload.
    # All errors here include token_consumed:false so the UI knows it can
    # reuse the previously uploaded file rather than forcing a re-upload.
    if req.concurrency < 1 or req.concurrency > 500:
        return {"ok": False, "error": "concurrency must be between 1 and 500", "token_consumed": False}

    proxy_urls: list[str] = []
    if req.proxy:
        proxy_urls = parse_proxy_list(req.proxy.strip())
        for url in proxy_urls:
            err = validate_proxy_url(url)
            if err:
                return {"ok": False, "error": err, "token_consumed": False}

    if req.proxy_rotation is not None and req.proxy_rotation not in ("round-robin", "random"):
        return {"ok": False, "error": "proxy_rotation must be 'round-robin' or 'random'", "token_consumed": False}

    if req.proxy_retries is not None and not (
        isinstance(req.proxy_retries, int) and 0 <= req.proxy_retries <= 10
    ):
        return {"ok": False, "error": "proxy_retries must be an integer between 0 and 10", "token_consumed": False}

    if req.proxy and not proxy_urls and req.proxy.strip():
        return {"ok": False, "error": "Proxy field set but no valid URLs parsed", "token_consumed": False}

    async with _get_lock():
        if _proc is not None and _proc.poll() is not None:
            _proc = None

        if _proc is not None:
            return {"ok": False, "error": f"Already running (pid {_proc.pid})", "token_consumed": False}

        # Resolve targets source: pre-uploaded token takes priority over textarea text.
        token_consumed = False  # tracks whether the upload token was popped from the store
        targets_path: Optional[str] = None
        if req.targets_token:
            targets_path = _consume_token(req.targets_token)
            token_consumed = True  # popped from store regardless of whether the file exists
            if not targets_path:
                return {"ok": False, "error": "Invalid or expired targets token — re-upload the file", "token_consumed": True}
        elif req.scan_mode == "cleanup_backlinks":
            # Cleanup reads from the DB — write an empty targets file as a placeholder
            try:
                tf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
                targets_path = tf.name
                tf.write("")
                tf.close()
            except OSError as e:
                return {"ok": False, "error": f"Could not write targets file ({type(e).__name__})", "token_consumed": False}
        elif req.laravel_targets and req.laravel_targets.strip():
            try:
                tf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
                targets_path = tf.name
                tf.write(req.laravel_targets.strip())
                tf.close()
            except OSError as e:
                if targets_path:
                    try:
                        os.unlink(targets_path)
                    except OSError:
                        pass
                return {"ok": False, "error": f"Could not write targets file ({type(e).__name__})", "token_consumed": False}
        else:
            return {"ok": False, "error": "No targets provided", "token_consumed": False}

        try:
            # Secrets go through environment, never argv — argv is world-readable
            # via /proc/<pid>/cmdline and `ps aux`. Harvester.py reads each one
            # via its argparse `default=os.getenv(...)` fallback.
            proc_env = os.environ.copy()
            cmd = [
                sys.executable, "-u", str(HARVESTER),
                "--laravel-targets-file", targets_path,
                "--concurrency", str(req.concurrency),
                "--db", str(DB_PATH),
            ]
            if proxy_urls:
                proc_env["HARVESTER_PROXY"] = "\n".join(proxy_urls)
                if req.proxy_rotation:
                    cmd += ["--proxy-rotation", req.proxy_rotation]
                if req.proxy_retries is not None:
                    cmd += ["--proxy-retries", str(req.proxy_retries)]
                if req.skip_proxy_health_check:
                    cmd += ["--skip-proxy-health-check"]
            if req.enable_crtsh:
                cmd += ["--enable-crtsh"]
            if req.enable_verify:
                cmd += ["--enable-verify"]
            if req.auto_expand_subnet:
                cmd += ["--auto-expand-subnet"]
            if req.asns:
                for asn_line in req.asns.splitlines():
                    asn = asn_line.strip()
                    if asn and not asn.startswith("#"):
                        cmd += ["--asn", asn]
            ipinfo_token = req.ipinfo_token or os.getenv("IPINFO_TOKEN", "")
            if ipinfo_token:
                proc_env["IPINFO_TOKEN"] = ipinfo_token
            if req.fast_paths is True:
                cmd += ["--fast-paths"]
            elif req.fast_paths is False:
                cmd += ["--no-fast-paths"]
            # None → omit flag, let harvester auto-decide
            if not req.enable_tcp_prefilter:
                cmd += ["--no-tcp-prefilter"]
            if not req.enable_subnet_expand:
                cmd += ["--no-subnet-expand"]
            cmd += ["--max-hosts-per-run", str(max(0, req.max_hosts_per_run))]
            if req.scan_mode in ("cpanel", "github", "wordpress", "backlink", "cleanup_backlinks"):
                cmd += ["--scan-mode", req.scan_mode]
            github_token = req.github_token or os.getenv("GITHUB_TOKEN", "")
            if github_token:
                proc_env["GITHUB_TOKEN"] = github_token
            if req.enable_urlscan:
                cmd += ["--enable-urlscan"]
            urlscan_key = req.urlscan_key or os.getenv("URLSCAN_API_KEY", "")
            if urlscan_key:
                cmd += ["--urlscan-key", urlscan_key]

            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            _log_path = LOG_DIR / f"harvester_{ts}.log"

            # Signal any prior tee thread to exit. If a stale process is still
            # alive, kill it first so the stdout iterator unblocks and the
            # thread can observe the stop signal — otherwise the stale thread
            # would outlive the join and bleed lines into this new run.
            _tee_stop.set()
            if _tee_thread is not None and _tee_thread.is_alive():
                if _proc is not None and _proc.poll() is None:
                    _terminate_proc(_proc, timeout=2)
                _tee_thread.join(timeout=5)
                if _tee_thread.is_alive():
                    # Stale thread refused to exit. Leaving _tee_stop set is
                    # the only safe move — clearing it now would un-signal the
                    # stale thread, which would then bleed lines into this run.
                    return {
                        "ok": False,
                        "error": "Previous tee thread is stuck — try again in a few seconds",
                        "token_consumed": token_consumed,
                    }
            _tee_stop.clear()

            try:
                new_proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env=proc_env,
                    start_new_session=True,
                    bufsize=1,
                    text=True,
                )
            except (OSError, ValueError) as e:
                return {"ok": False, "error": f"Could not start harvester subprocess: {e}"}
            try:
                log_fh = open(_log_path, "a")
            except OSError as e:
                _terminate_proc(new_proc, timeout=2)
                return {"ok": False, "error": f"Could not open log file: {e}"}

            def _tee_output(proc, fh, targets_file: str, stop_event: threading.Event):
                try:
                    for line in proc.stdout:
                        if stop_event.is_set():
                            break
                        sys.stdout.write(line)
                        sys.stdout.flush()
                        fh.write(line)
                        fh.flush()
                        _push_log_line(line)
                finally:
                    # Surface why the subprocess ended — the user can't tell from
                    # the UI alone whether it was a clean finish, a crash, or an
                    # OOM kill. Wait briefly for the process to settle so poll()
                    # returns the actual exit code.
                    try:
                        proc.wait(timeout=3)
                    except Exception:
                        pass
                    rc = proc.poll()
                    if rc is None:
                        marker = "[api] ⚠ Harvester stdout closed but process still alive — investigating"
                    elif rc == 0:
                        marker = "[api] ✓ Harvester exited cleanly (code 0)"
                    elif rc < 0:
                        # Negative = killed by signal. -9 = SIGKILL (likely OOM).
                        sig_name = {9: "SIGKILL/OOM", 15: "SIGTERM", 2: "SIGINT", 11: "SIGSEGV"}.get(-rc, f"signal {-rc}")
                        marker = f"[api] ✗ Harvester killed by {sig_name} (rc={rc})"
                    else:
                        marker = f"[api] ✗ Harvester exited with code {rc} (non-zero — likely an error)"
                    sys.stdout.write(marker + "\n")
                    sys.stdout.flush()
                    try:
                        fh.write(marker + "\n")
                        fh.flush()
                    except Exception:
                        pass
                    _push_log_line(marker + "\n")
                    fh.close()
                    try:
                        os.unlink(targets_file)
                    except OSError:
                        pass

            try:
                _tee_thread = threading.Thread(
                    target=_tee_output,
                    args=(new_proc, log_fh, targets_path, _tee_stop),
                    daemon=True,
                )
                _tee_thread.start()
            except Exception:
                log_fh.close()
                _terminate_proc(new_proc, timeout=2)
                raise

            _proc = new_proc
            _start_mono = time.monotonic()
            _last_run_state = None  # actively running
            targets_path = None  # ownership transferred to tee thread
        finally:
            if targets_path is not None:
                try:
                    os.unlink(targets_path)
                except OSError:
                    pass

    await asyncio.sleep(0.5)
    async with _get_lock():
        if _proc is None:
            return {"ok": True, "note": "completed during launch"}
        rc = _proc.poll()
        if rc is not None:
            try:
                tail = _log_path.read_text(errors="replace").splitlines()[-10:]
            except Exception:
                tail = []
            if rc == 0:
                # Clean exit before our 0.5s check — fast path with nothing to do.
                _last_run_state = "finished"
                _proc = None
                _start_mono = None
                return {
                    "ok": True,
                    "note": "completed immediately",
                    "log_tail": tail or ["(no output captured)"],
                }
            _proc = None
            _start_mono = None
            _last_run_state = "stopped"
            return {
                "ok": False,
                "error": f"Harvester exited immediately (code {rc})",
                "log_tail": tail or ["(no output captured)"],
                "token_consumed": True,
            }
        return {"ok": True, "pid": _proc.pid, "log": str(_log_path)}


@app.post("/api/stop")
async def stop_harvester():
    global _proc, _start_mono, _last_run_state

    async with _get_lock():
        if _proc is None or _proc.poll() is not None:
            # Process already exited — preserve any prior "finished" state
            # so the pill doesn't flip to "stopped" misleadingly.
            _proc = None
            _start_mono = None
            if _last_run_state is None:
                _last_run_state = "finished"
            return {"ok": True, "note": "was not running"}

        _terminate_proc(_proc, timeout=5)
        _proc = None
        _start_mono = None
        _last_run_state = "stopped"
        return {"ok": True}


@app.get("/api/status")
async def get_status():
    global _proc, _start_mono, _last_run_state

    async with _get_lock():
        running = _proc is not None and _proc.poll() is None
        # Process exited on its own: capture that distinctly from a user-stopped run.
        if not running and _proc is not None:
            if _last_run_state is None:
                _last_run_state = "finished"
            _proc = None
            _start_mono = None
        pid = _proc.pid if (running and _proc) else None
        uptime = int(time.monotonic() - _start_mono) if (running and _start_mono) else 0
        last_state = _last_run_state

    conn = _open_db()
    try:
        total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        hosts_scanned = conn.execute("SELECT COUNT(*) FROM probed_hosts").fetchone()[0]
    finally:
        conn.close()

    return {
        "running": running,
        "pid": pid,
        "uptime_seconds": uptime,
        "total_findings": total,
        "hosts_scanned": hosts_scanned,
        "last_run_state": last_state,
    }


@app.get("/api/findings")
async def get_findings(limit: int = Query(default=200, ge=1, le=1000)):
    conn = _open_db()
    try:
        rows = conn.execute(
            "SELECT id, source, url, resend_key, linked_domain, file_path, detected_at, vendor, verified, domain_alive "
            "FROM findings ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


async def _sse_events(after_id: int) -> AsyncIterator[str]:
    global _proc, _start_mono, _last_run_state
    last_id = after_id

    conn = _open_db()
    try:
        while True:
            rows = conn.execute(
                "SELECT id, source, url, resend_key, linked_domain, file_path, detected_at, vendor, verified, domain_alive "
                "FROM findings WHERE id > ? ORDER BY id ASC LIMIT 50",
                (last_id,),
            ).fetchall()
            # Single-roundtrip count (cuts SSE DB load by ~33%).
            counts = conn.execute(
                "SELECT (SELECT COUNT(*) FROM findings) AS f, "
                "(SELECT COUNT(*) FROM probed_hosts) AS h"
            ).fetchone()
            total = counts["f"]
            hosts_scanned = counts["h"]

            for row in rows:
                d = dict(row)
                last_id = d["id"]
                yield f"event: finding\ndata: {json.dumps(d)}\n\n"

            async with _get_lock():
                running = _proc is not None and _proc.poll() is None
                if not running and _proc is not None:
                    if _last_run_state is None:
                        _last_run_state = "finished"
                    _proc = None
                    _start_mono = None
                uptime = int(time.monotonic() - _start_mono) if (running and _start_mono) else 0
                last_state = _last_run_state

            yield (
                f"event: stats\n"
                f"data: {json.dumps({'running': running, 'uptime_seconds': uptime, 'total_findings': total, 'hosts_scanned': hosts_scanned, 'last_run_state': last_state})}\n\n"
            )

            # Back off when idle — UI doesn't need fast updates if nothing's
            # running. 2 s during a scan, 10 s otherwise.
            await asyncio.sleep(2 if running else 10)
    finally:
        conn.close()


async def _sse_log_events(after_seq: int) -> AsyncIterator[str]:
    """SSE stream of harvester log lines for the live console panel."""
    last = after_seq
    while True:
        latest, entries = _get_log_lines_after(last)
        for seq, line in entries:
            last = seq
            yield f"event: log\ndata: {json.dumps({'seq': seq, 'line': line})}\n\n"
        # heartbeat with current high-water mark so client knows we're alive
        yield f"event: ping\ndata: {json.dumps({'latest': latest})}\n\n"
        await asyncio.sleep(1)


@app.get("/api/log-stream")
async def log_stream(after: int = Query(default=0)):
    return StreamingResponse(
        _sse_log_events(after),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.get("/api/stream")
async def stream(after: int = Query(default=0)):
    return StreamingResponse(
        _sse_events(after),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.get("/api/cpanel-findings")
async def cpanel_findings(limit: int = Query(default=500)):
    conn = _open_db()
    try:
        rows = conn.execute(
            "SELECT id, source, url, service, host, port, username, password, "
            "verified, detected_at FROM cpanel_findings ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@app.get("/api/cpanel-export")
async def cpanel_export(fmt: str = Query(default="csv", alias="format")):
    conn = _open_db()
    try:
        rows = conn.execute(
            "SELECT url, service, host, port, username, password, verified, detected_at "
            "FROM cpanel_findings ORDER BY id ASC"
        ).fetchall()
    finally:
        conn.close()

    if fmt == "json":
        return [dict(r) for r in rows]

    lines = ["url,service,host,port,username,password,verified,detected_at"]
    for r in rows:
        verified = "live" if r["verified"] == 1 else ("dead" if r["verified"] == 0 else "untested")
        lines.append(",".join([
            str(r["url"] or ""), str(r["service"] or ""),
            str(r["host"] or ""), str(r["port"] or ""),
            str(r["username"] or ""), str(r["password"] or ""),
            verified, str(r["detected_at"] or ""),
        ]))
    from fastapi.responses import Response
    return Response(
        content="\n".join(lines),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=cpanel_findings.csv"},
    )


@app.get("/api/wp-findings")
async def wp_findings(limit: int = Query(default=500, ge=1, le=5000)):
    conn = _open_db()
    try:
        rows = conn.execute(
            "SELECT id, source, url, domain, component, version, cve, title, severity, "
            "fixed_in, verified, shell_url, detected_at FROM wp_findings ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []
    finally:
        conn.close()


@app.get("/api/wp-export")
async def wp_export(fmt: str = Query(default="csv", alias="format")):
    conn = _open_db()
    try:
        rows = conn.execute(
            "SELECT url, component, version, cve, title, severity, fixed_in, "
            "verified, shell_url, detected_at FROM wp_findings ORDER BY id ASC"
        ).fetchall()
    finally:
        conn.close()

    if fmt == "json":
        return [dict(r) for r in rows]

    def _esc(v: str) -> str:
        return '"' + (v or "").replace('"', '""') + '"'

    lines = ["url,component,version,cve,title,severity,fixed_in,verified,shell_url,detected_at"]
    for r in rows:
        lines.append(",".join(_esc(str(r[c] or "")) for c in (
            "url", "component", "version", "cve",
            "title", "severity", "fixed_in", "verified", "shell_url", "detected_at",
        )))
    from fastapi.responses import Response
    return Response(
        content="\n".join(lines),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=wp_findings.csv"},
    )


@app.get("/api/backlink-findings")
async def backlink_findings(limit: int = Query(default=1000, ge=1, le=10000)):
    conn = _open_db()
    try:
        rows = conn.execute(
            "SELECT id, host, cpanel_user, site_url, file_path, site_type, "
            "anchor_text, injected_at, status FROM backlink_findings "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []
    finally:
        conn.close()


@app.get("/api/backlink-export")
async def backlink_export(fmt: str = Query(default="csv", alias="format")):
    conn = _open_db()
    try:
        rows = conn.execute(
            "SELECT host, cpanel_user, site_url, file_path, site_type, "
            "anchor_text, injected_at, status FROM backlink_findings ORDER BY id ASC"
        ).fetchall()
    except Exception:
        rows = []
    finally:
        conn.close()

    if fmt == "json":
        return [dict(r) for r in rows]

    lines = ["host,cpanel_user,site_url,file_path,site_type,anchor_text,injected_at,status"]
    for r in rows:
        lines.append(",".join([
            str(r["host"] or ""), str(r["cpanel_user"] or ""),
            str(r["site_url"] or ""), str(r["file_path"] or ""),
            str(r["site_type"] or ""), f'"{r["anchor_text"] or ""}"',
            str(r["injected_at"] or ""), str(r["status"] or ""),
        ]))
    from fastapi.responses import Response
    return Response(
        content="\n".join(lines),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=backlink_findings.csv"},
    )


@app.post("/api/verify-domains")
async def verify_domains():
    """Check liveness of all linked_domains in findings and update domain_alive flag."""
    import asyncio, aiohttp

    conn = _open_db()
    try:
        rows = conn.execute(
            "SELECT resend_key, linked_domain FROM findings "
            "WHERE linked_domain IS NOT NULL AND linked_domain != '' AND domain_alive IS NULL"
        ).fetchall()
    except Exception:
        rows = []
    finally:
        conn.close()

    if not rows:
        return {"checked": 0, "alive": 0, "dead": 0}

    to = aiohttp.ClientTimeout(total=6, sock_connect=3)

    async def _probe(domain: str) -> bool:
        for scheme in ("https", "http"):
            try:
                async with aiohttp.ClientSession() as s:
                    async with s.get(
                        f"{scheme}://{domain}", timeout=to,
                        allow_redirects=True, ssl=False,
                        headers={"User-Agent": "Mozilla/5.0"},
                    ) as r:
                        return r.status < 400
            except Exception:
                continue
        return False

    sem = asyncio.Semaphore(30)

    async def _check_one(key: str, domain: str):
        async with sem:
            alive = await _probe(domain)
        c = _open_db()
        try:
            c.execute(
                "UPDATE findings SET domain_alive=? WHERE resend_key=?",
                (1 if alive else 0, key),
            )
            c.commit()
        finally:
            c.close()
        return alive

    results = await asyncio.gather(*[_check_one(r["resend_key"], r["linked_domain"]) for r in rows])
    alive_count = sum(1 for r in results if r)
    return {"checked": len(results), "alive": alive_count, "dead": len(results) - alive_count}


@app.post("/api/clear-history")
async def clear_history():
    """Delete all probed_hosts records so every host can be scanned again."""
    conn = _open_db()
    try:
        count = conn.execute("SELECT COUNT(*) FROM probed_hosts").fetchone()[0]
        conn.execute("DELETE FROM probed_hosts")
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "cleared": count}


class WpRescanRequest(BaseModel):
    host: str
    concurrency: int = 10


@app.post("/api/wp-rescan")
async def wp_rescan(req: WpRescanRequest):
    """Remove a single host from probed_hosts and immediately re-run the WP exploit against it."""
    global _proc, _log_path, _tee_thread, _last_run_state

    if _proc is not None and _proc.poll() is None:
        return {"ok": False, "error": "A scan is already running. Stop it first."}

    host = req.host.strip().rstrip("/")
    if not host:
        return {"ok": False, "error": "host is required"}

    # Remove from checkpoint so the pipeline doesn't skip it
    conn = _open_db()
    try:
        conn.execute("DELETE FROM probed_hosts WHERE host = ? OR host LIKE ?",
                     (host, f"%{host}%"))
        conn.commit()
    finally:
        conn.close()

    cmd = [
        sys.executable, str(HARVESTER),
        "--targets", host,
        "--scan-mode", "wordpress",
        "--concurrency", str(req.concurrency),
        "--no-tcp-prefilter",   # single known host — no need to TCP-prefilter
    ]

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    _log_path = LOG_DIR / f"harvester_{ts}.log"
    _tee_stop.set()
    if _tee_thread is not None and _tee_thread.is_alive():
        _tee_thread.join(timeout=2)

    proc_env = {**os.environ}
    _proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, env=proc_env,
    )
    _start_mono = time.monotonic()
    _last_run_state = None
    _tee_stop.clear()

    log_file = open(_log_path, "w", encoding="utf-8")
    def _tee():
        try:
            for line in _proc.stdout:
                log_file.write(line)
                log_file.flush()
        finally:
            log_file.close()
    _tee_thread = threading.Thread(target=_tee, daemon=True)
    _tee_thread.start()

    return {"ok": True, "host": host, "pid": _proc.pid}


class DbConnectRequest(BaseModel):
    host: str
    port: Optional[int] = None   # None = auto (3306 mysql / 5432 pgsql)
    user: str = "root"
    password: str
    database: str = ""
    driver: str = "mysql"  # "mysql" | "pgsql"


async def _try_mysql(host: str, port: int, user: str, password: str, database: str):
    conn = await asyncio.wait_for(
        _aiomysql.connect(
            host=host, port=port,
            user=user, password=password,
            db=database or "",
            connect_timeout=8,
            autocommit=True,
        ),
        timeout=10,
    )
    async with conn.cursor() as cur:
        await cur.execute("SHOW TABLES")
        rows = await cur.fetchmany(30)
    tables = [r[0] for r in rows]
    conn.close()
    return tables


@app.post("/api/db-connect")
async def db_connect(req: DbConnectRequest):
    """Attempt a live DB connection and return status + table list."""
    host = req.host.strip()
    if not host:
        return {"ok": False, "error": "Host is required", "tables": []}

    if req.driver == "pgsql":
        if _asyncpg is None:
            return {"ok": False, "error": "asyncpg not installed — restart the server", "tables": []}
        port = req.port or 5432
        try:
            conn = await asyncio.wait_for(
                _asyncpg.connect(
                    host=host, port=port,
                    user=req.user, password=req.password,
                    database=req.database or "postgres",
                    timeout=8,
                ),
                timeout=10,
            )
            rows = await conn.fetch(
                "SELECT tablename FROM pg_tables WHERE schemaname='public' LIMIT 30"
            )
            tables = [r["tablename"] for r in rows]
            await conn.close()
            return {"ok": True, "error": None, "tables": tables, "port": port}
        except Exception as exc:
            return {"ok": False, "error": str(exc), "tables": []}
    else:
        if _aiomysql is None:
            return {"ok": False, "error": "aiomysql not installed — restart the server", "tables": []}
        # Try supplied port first; if none given, try 3306 then 3307
        ports_to_try = [req.port] if req.port else [3306, 3307]
        last_err = ""
        for port in ports_to_try:
            try:
                tables = await _try_mysql(host, port, req.user, req.password, req.database)
                return {"ok": True, "error": None, "tables": tables, "port": port}
            except Exception as exc:
                last_err = str(exc)
        return {"ok": False, "error": last_err, "tables": []}


@app.get("/api/export")
async def export_findings(fmt: str = Query(default="txt", alias="format")):
    conn = _open_db()
    try:
        rows = conn.execute(
            "SELECT resend_key, linked_domain, vendor, verified, url, detected_at "
            "FROM findings ORDER BY id ASC"
        ).fetchall()
    finally:
        conn.close()

    print(f"[api] /api/export?format={fmt}  → {len(rows)} row(s) from {DB_PATH}", flush=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if not rows:
        msg = (
            f"# No findings to export.\n"
            f"# Database: {DB_PATH}\n"
            f"# If you have hits in the live log, the harvester may be writing\n"
            f"# to a different DB. Check that `python harvester.py` is invoked\n"
            f"# from this directory or with --db pointing here.\n"
        )
        return PlainTextResponse(
            msg,
            headers={"Content-Disposition": f'attachment; filename="envharvester_empty_{ts}.txt"'},
        )

    if fmt == "json":
        data = [dict(r) for r in rows]
        return PlainTextResponse(
            json.dumps(data, indent=2) + "\n",
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="envharvester_{ts}.json"'},
        )

    if fmt == "csv":
        def _esc(v: str) -> str:
            return '"' + (v or "").replace('"', '""') + '"'
        lines = ["key,domain,vendor,verified,url,detected_at"]
        for r in rows:
            verified = "yes" if r["verified"] == 1 else ("no" if r["verified"] == 0 else "")
            lines.append(",".join(_esc(v) for v in (
                str(r["resend_key"] or ""), str(r["linked_domain"] or ""),
                str(r["vendor"] or ""), verified,
                str(r["url"] or ""), str(r["detected_at"] or ""),
            )))
        return PlainTextResponse(
            "\n".join(lines) + "\n",
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="envharvester_{ts}.csv"'},
        )

    # default: plain-text block format — each field on its own line, blank line between findings
    blocks = []
    for r in rows:
        verified = "yes" if r["verified"] == 1 else ("no" if r["verified"] == 0 else "untested")
        block = (
            f"key:      {r['resend_key'] or ''}\n"
            f"domain:   {r['linked_domain'] or 'unknown'}\n"
            f"vendor:   {r['vendor'] or 'unknown'}\n"
            f"verified: {verified}\n"
            f"url:      {r['url'] or ''}"
        )
        blocks.append(block)
    return PlainTextResponse(
        "\n\n".join(blocks) + "\n",
        headers={"Content-Disposition": f'attachment; filename="envharvester_{ts}.txt"'},
    )


# static assets (mount after explicit routes)
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static_assets")


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    print(f"EnvHarvester UI → http://localhost:{port}")
    uvicorn.run("api:app", host="0.0.0.0", port=port, log_level="warning", reload=False)
