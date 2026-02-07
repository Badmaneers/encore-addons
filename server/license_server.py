"""
Encore Bypass Charging Addon — License Server (Web UI Edition)

Features:
  - Web dashboard at / with fluid animated UI
  - WebSocket live console streaming at /ws
  - REST API for license management
  - Original license verification protocol at /{file_hash}/{serial}

Protocol (unchanged):
  1. Client sends GET /{file_hash}/{serial}
     User-Agent: EncoreLicenseVerifier/1.3
  2. Server computes: SHA256(file_hash + serial + "Watashi...me")
  3. Server returns the hex digest if device is in the license database
     (or always, if running in permissive mode)

Usage:
  python3 license_server.py [--port 8443] [--permissive] [--db licenses.json]

  --permissive    Respond with valid hash for ANY device (for testing)
  --db FILE       JSON file mapping serial numbers to licensed status
  --port PORT     Listen port (default 8443)
  --tls-cert      Path to TLS certificate (optional, for HTTPS)
  --tls-key       Path to TLS private key (optional, for HTTPS)
"""

import hashlib
import hmac
import json
import argparse
import os
import secrets
import sys
import ssl
import base64
import logging
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("ERROR: cryptography is required. Install with: pip install cryptography")
    sys.exit(1)

try:
    from aiohttp import web
    import aiohttp
except ImportError:
    print("ERROR: aiohttp is required. Install with: pip install aiohttp")
    sys.exit(1)

# ─── Constants matching the binary ────────────────────────────────────
HMAC_SALT = b"Watashi...me"
EXPECTED_USER_AGENT_PREFIX = "EncoreLicenseVerifier/"
TEMPLATE_DIR = Path(__file__).parent / "templates"

# ─── Logging setup ────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("license-server")


def compute_expected_response(file_hash: str, serial: str) -> str:
    """
    Replicate the binary's request HMAC:
      SHA256(file_hash + serial + "Watashi...me")
    """
    data = file_hash.encode("utf-8") + serial.encode("utf-8") + HMAC_SALT
    return hashlib.sha256(data).hexdigest()


# ═══════════════════════════════════════════════════════════════════════
#  Rate Limiter
# ═══════════════════════════════════════════════════════════════════════
class RateLimiter:
    """Token-bucket rate limiter keyed by IP address."""

    def __init__(self, max_requests: int = 30, window_sec: float = 60.0):
        self.max_requests = max_requests
        self.window_sec = window_sec
        self._hits: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now = time.monotonic()
        hits = self._hits[key]
        # Prune old entries
        self._hits[key] = [t for t in hits if now - t < self.window_sec]
        if len(self._hits[key]) >= self.max_requests:
            return False
        self._hits[key].append(now)
        return True

    def remaining(self, key: str) -> int:
        now = time.monotonic()
        hits = [t for t in self._hits[key] if now - t < self.window_sec]
        return max(0, self.max_requests - len(hits))


# ═══════════════════════════════════════════════════════════════════════
#  Authentication Helpers
# ═══════════════════════════════════════════════════════════════════════
def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode(), b.encode())


def _generate_session_token() -> str:
    """Generate a cryptographically secure session token."""
    return secrets.token_urlsafe(48)


# ═══════════════════════════════════════════════════════════════════════
#  License Database
# ═══════════════════════════════════════════════════════════════════════
# ─── Encryption helpers ───────────────────────────────────────────────
# Fixed salt so the same passphrase always produces the same key.
# This is safe because PBKDF2 with 480 000 iterations is already slow
# enough to resist brute-force, and the salt only needs to be unique
# per application (not per user).
_DB_KDF_SALT = b"encore-license-db-v1"
_DB_KDF_ITERATIONS = 480_000


def _derive_fernet_key(passphrase: str) -> bytes:
    """Derive a Fernet key from a passphrase using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_DB_KDF_SALT,
        iterations=_DB_KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


class LicenseDatabase:
    """Manages the license database (encrypted JSON file on disk)."""

    def __init__(self, db_path: str, passphrase: str):
        self.db_path = db_path
        self.licenses: dict = {}
        self._fernet = Fernet(_derive_fernet_key(passphrase))
        self._load()

    def _load(self):
        if os.path.exists(self.db_path):
            try:
                raw = Path(self.db_path).read_bytes()
                # Try decrypting first (encrypted DB)
                try:
                    plaintext = self._fernet.decrypt(raw)
                    self.licenses = json.loads(plaintext.decode("utf-8"))
                    log.info(
                        "Loaded %d licenses from %s (encrypted)",
                        len(self.licenses),
                        self.db_path,
                    )
                except InvalidToken:
                    # Maybe it's a legacy plaintext JSON — try to migrate
                    try:
                        self.licenses = json.loads(raw.decode("utf-8"))
                        log.warning(
                            "Loaded %d licenses from UNENCRYPTED %s — migrating to encrypted",
                            len(self.licenses),
                            self.db_path,
                        )
                        self.save()  # Re-save encrypted
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        log.error(
                            "Failed to decrypt %s — wrong passphrase?", self.db_path
                        )
                        self.licenses = {}
            except IOError as e:
                log.error("Failed to load license DB: %s", e)
                self.licenses = {}
        else:
            log.info("No license DB found at %s, starting empty", self.db_path)
            self.licenses = {}

    def save(self):
        try:
            plaintext = json.dumps(self.licenses, indent=2).encode("utf-8")
            encrypted = self._fernet.encrypt(plaintext)
            Path(self.db_path).write_bytes(encrypted)
        except IOError as e:
            log.error("Failed to save license DB: %s", e)

    def is_licensed(self, serial: str) -> bool:
        return self.licenses.get(serial, {}).get("licensed", False)

    def add_license(self, serial: str, file_hash: str):
        self.licenses[serial] = {
            "licensed": True,
            "file_hash": file_hash,
            "added": datetime.now().isoformat(),
        }
        self.save()
        log.info("Added license for serial: %s", serial)

    def revoke_license(self, serial: str):
        if serial in self.licenses:
            self.licenses[serial]["licensed"] = False
            self.licenses[serial]["revoked"] = datetime.now().isoformat()
            self.save()
            log.info("Revoked license for serial: %s", serial)

    def delete_license(self, serial: str) -> bool:
        if serial in self.licenses:
            del self.licenses[serial]
            self.save()
            log.info("Deleted license for serial: %s", serial)
            return True
        return False

    def list_all(self) -> dict:
        return self.licenses


# ═══════════════════════════════════════════════════════════════════════
#  WebSocket Console Broadcaster
# ═══════════════════════════════════════════════════════════════════════
class ConsoleBroadcaster:
    """Manages WebSocket connections and broadcasts log/event messages."""

    def __init__(self):
        self.clients: set = set()

    async def register(self, ws: web.WebSocketResponse):
        self.clients.add(ws)
        log.info("WebSocket client connected (%d total)", len(self.clients))

    async def unregister(self, ws: web.WebSocketResponse):
        self.clients.discard(ws)
        log.info("WebSocket client disconnected (%d total)", len(self.clients))

    async def broadcast(self, msg: dict):
        dead = set()
        payload = json.dumps(msg)
        for ws in self.clients:
            try:
                await ws.send_str(payload)
            except (ConnectionError, RuntimeError):
                dead.add(ws)
        self.clients -= dead

    async def send_log(self, level: str, message: str, **extra):
        await self.broadcast(
            {"type": "log", "level": level, "message": message, **extra}
        )

    async def send_request(self, level: str, message: str, refresh: bool = False):
        await self.broadcast(
            {
                "type": "request",
                "level": level,
                "message": message,
                "refresh": refresh,
            }
        )


# ═══════════════════════════════════════════════════════════════════════
#  Application State
# ═══════════════════════════════════════════════════════════════════════
class AppState:
    def __init__(self, db: LicenseDatabase, permissive: bool, bind: str, port: int,
                 api_key: str):
        self.db = db
        self.permissive = permissive
        self.bind = bind
        self.port = port
        self.api_key = api_key
        self.broadcaster = ConsoleBroadcaster()
        self.request_count = 0
        self.start_time = datetime.now()
        self.rate_limiter = RateLimiter(max_requests=30, window_sec=60)
        # Session tokens: set of valid tokens issued after login
        self.sessions: set[str] = set()

    def verify_api_key(self, key: str) -> bool:
        return _constant_time_compare(self.api_key, key)

    def create_session(self) -> str:
        token = _generate_session_token()
        self.sessions.add(token)
        return token

    def verify_session(self, token: str) -> bool:
        if not token:
            return False
        return token in self.sessions


# ═══════════════════════════════════════════════════════════════════════
#  Route Handlers
# ═══════════════════════════════════════════════════════════════════════


# ─── Auth helpers for routes ──────────────────────────────────────────
def _get_session_token(request: web.Request) -> str:
    """Extract session token from cookie or Authorization header."""
    # Check cookie first
    token = request.cookies.get("session")
    if token:
        return token
    # Fallback to Authorization: Bearer <token>
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return ""


def _require_auth(handler):
    """Decorator: reject requests without a valid session."""
    async def wrapper(request: web.Request) -> web.Response:
        state: AppState = request.app["state"]
        token = _get_session_token(request)
        if not state.verify_session(token):
            return web.json_response({"error": "Unauthorized"}, status=401)
        return await handler(request)
    return wrapper


# ─── Login / Session ──────────────────────────────────────────────────
async def handle_login_page(request: web.Request) -> web.Response:
    """Serve the login page."""
    state: AppState = request.app["state"]
    # If already has a valid session, redirect to dashboard
    token = _get_session_token(request)
    if state.verify_session(token):
        raise web.HTTPFound("/")
    login_path = TEMPLATE_DIR / "login.html"
    if not login_path.exists():
        return web.Response(text="Login template not found", status=500)
    return web.FileResponse(login_path)


async def handle_login_api(request: web.Request) -> web.Response:
    """POST /api/login — authenticate with API key, get a session cookie."""
    state: AppState = request.app["state"]
    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        return web.json_response({"error": "Invalid JSON"}, status=400)

    api_key = data.get("api_key", "")
    if not state.verify_api_key(api_key):
        await state.broadcaster.send_log(
            "WARN", f"Failed login attempt from {request.remote}"
        )
        return web.json_response({"error": "Invalid API key"}, status=403)

    token = state.create_session()
    resp = web.json_response({"status": "ok"})
    resp.set_cookie(
        "session", token,
        httponly=True,
        samesite="Strict",
        max_age=86400,  # 24 hours
        secure=request.secure,
    )
    await state.broadcaster.send_log(
        "OK", f"Admin logged in from {request.remote}"
    )
    return resp


async def handle_logout(request: web.Request) -> web.Response:
    """POST /api/logout — invalidate the session."""
    state: AppState = request.app["state"]
    token = _get_session_token(request)
    state.sessions.discard(token)
    resp = web.json_response({"status": "ok"})
    resp.del_cookie("session")
    return resp


# ─── Web UI ───────────────────────────────────────────────────────────
async def handle_index(request: web.Request) -> web.Response:
    """Serve the dashboard — requires a valid session."""
    state: AppState = request.app["state"]
    token = _get_session_token(request)
    if not state.verify_session(token):
        raise web.HTTPFound("/login")
    html_path = TEMPLATE_DIR / "index.html"
    if not html_path.exists():
        return web.Response(text="Template not found", status=500)
    return web.FileResponse(html_path)


# ─── WebSocket ────────────────────────────────────────────────────────
async def handle_websocket(request: web.Request) -> web.WebSocketResponse:
    state: AppState = request.app["state"]
    ws = web.WebSocketResponse(heartbeat=30.0)
    await ws.prepare(request)

    # Authenticate: client must send {"type": "auth", "token": "..."} first
    # Also accept session cookie for browser-based connections
    cookie_token = request.cookies.get("session", "")
    authenticated = state.verify_session(cookie_token)

    if not authenticated:
        try:
            auth_msg = await ws.receive_json(timeout=10.0)
            if auth_msg.get("type") == "auth":
                authenticated = state.verify_session(auth_msg.get("token", ""))
        except Exception:
            pass

    if not authenticated:
        await ws.send_json({"type": "error", "message": "Unauthorized"})
        await ws.close(code=4001, message=b"Unauthorized")
        return ws

    await state.broadcaster.register(ws)

    # Send welcome + initial stats
    await ws.send_json(
        {
            "type": "log",
            "level": "OK",
            "message": f"Dashboard connected — {len(state.db.list_all())} licenses loaded",
        }
    )
    await ws.send_json({"type": "stats", "request_count": state.request_count})

    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                pass  # Client doesn't send commands (yet)
            elif msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSE):
                break
    finally:
        await state.broadcaster.unregister(ws)

    return ws


# ─── API: Server Status ──────────────────────────────────────────────
@_require_auth
async def api_status(request: web.Request) -> web.Response:
    state: AppState = request.app["state"]
    return web.json_response(
        {
            "status": "ok",
            "permissive": state.permissive,
            "address": f"{state.bind}:{state.port}",
            "request_count": state.request_count,
            "uptime_seconds": (datetime.now() - state.start_time).total_seconds(),
            "license_count": len(state.db.list_all()),
        }
    )


# ─── API: List Licenses ──────────────────────────────────────────────
@_require_auth
async def api_licenses(request: web.Request) -> web.Response:
    state: AppState = request.app["state"]
    return web.json_response(state.db.list_all())


# ─── API: Add License ────────────────────────────────────────────────
@_require_auth
async def api_license_add(request: web.Request) -> web.Response:
    state: AppState = request.app["state"]
    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        return web.json_response({"error": "Invalid JSON"}, status=400)

    serial = data.get("serial", "").strip()
    file_hash = data.get("file_hash", "unknown").strip() or "unknown"

    if not serial:
        return web.json_response({"error": "serial is required"}, status=400)

    state.db.add_license(serial, file_hash)
    await state.broadcaster.send_request(
        "OK", f"License GRANTED for serial={serial}", refresh=True
    )
    return web.json_response({"status": "added", "serial": serial})


# ─── API: Revoke License ─────────────────────────────────────────────
@_require_auth
async def api_license_revoke(request: web.Request) -> web.Response:
    state: AppState = request.app["state"]
    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        return web.json_response({"error": "Invalid JSON"}, status=400)

    serial = data.get("serial", "").strip()
    if not serial:
        return web.json_response({"error": "serial is required"}, status=400)

    state.db.revoke_license(serial)
    await state.broadcaster.send_request(
        "WARN", f"License REVOKED for serial={serial}", refresh=True
    )
    return web.json_response({"status": "revoked", "serial": serial})


# ─── API: Delete License ──────────────────────────────────────────────
@_require_auth
async def api_license_delete(request: web.Request) -> web.Response:
    state: AppState = request.app["state"]
    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        return web.json_response({"error": "Invalid JSON"}, status=400)

    serial = data.get("serial", "").strip()
    if not serial:
        return web.json_response({"error": "serial is required"}, status=400)

    if state.db.delete_license(serial):
        await state.broadcaster.send_request(
            "WARN", f"License DELETED for serial={serial}", refresh=True
        )
        return web.json_response({"status": "deleted", "serial": serial})
    else:
        return web.json_response({"error": "Serial not found"}, status=404)


# ─── API: Compute HMAC ───────────────────────────────────────────────
@_require_auth
async def api_compute(request: web.Request) -> web.Response:
    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        return web.json_response({"error": "Invalid JSON"}, status=400)

    file_hash = data.get("file_hash", "").strip()
    serial = data.get("serial", "").strip()

    if not file_hash or not serial:
        return web.json_response(
            {"error": "file_hash and serial are required"}, status=400
        )

    expected = compute_expected_response(file_hash, serial)
    return web.json_response(
        {
            "file_hash": file_hash,
            "serial": serial,
            "expected_response": expected,
            "formula": "SHA256(file_hash + serial + 'Watashi...me')",
        }
    )


# ─── License Verification (original protocol) ────────────────────────
async def handle_license_check(request: web.Request) -> web.Response:
    """
    GET /{file_hash}/{serial}

    The binary expects:
      - 200 OK with body = SHA256(file_hash + serial + "Watashi...me") hex
        if the device is licensed
      - Any other response (or mismatched hash) = unlicensed
    """
    state: AppState = request.app["state"]
    file_hash = request.match_info["file_hash"]
    serial = request.match_info["serial"]
    ua = request.headers.get("User-Agent", "unknown")
    client_ip = request.remote or "unknown"

    state.request_count += 1

    # Rate limiting
    if not state.rate_limiter.is_allowed(client_ip):
        await state.broadcaster.send_request(
            "WARN", f"Rate limited: {client_ip} (too many requests)"
        )
        return web.Response(
            text="Too Many Requests", status=429,
            headers={"Retry-After": "60"},
        )

    # Validate hex hash
    if len(file_hash) != 64 or not all(c in "0123456789abcdef" for c in file_hash):
        await state.broadcaster.send_request(
            "WARN",
            f"Bad hash format from {request.remote}: {file_hash[:20]}...",
        )
        return web.Response(text="Bad Request: invalid hash format", status=400)

    await state.broadcaster.send_request(
        "INFO",
        f"License check: serial={serial} hash={file_hash[:8]}...{file_hash[-8:]} UA={ua}",
    )

    expected = compute_expected_response(file_hash, serial)

    if state.permissive:
        await state.broadcaster.send_request(
            "OK", f"PERMISSIVE: license GRANTED to serial={serial}"
        )
        return web.Response(text=expected, content_type="text/plain")

    if state.db.is_licensed(serial):
        await state.broadcaster.send_request(
            "OK", f"LICENSED: serial={serial} — response sent"
        )
        return web.Response(text=expected, content_type="text/plain")
    else:
        await state.broadcaster.send_request(
            "WARN", f"UNLICENSED: serial={serial} — denied"
        )
        return web.Response(text="unlicensed", content_type="text/plain")


# ─── Health check ─────────────────────────────────────────────────────
async def handle_health(request: web.Request) -> web.Response:
    state: AppState = request.app["state"]
    return web.json_response({"status": "ok", "permissive": state.permissive})


# ═══════════════════════════════════════════════════════════════════════
#  App Factory
# ═══════════════════════════════════════════════════════════════════════
def create_app(state: AppState) -> web.Application:
    app = web.Application()
    app["state"] = state

    # ── Security headers middleware ──────────────────────────────────
    @web.middleware
    async def security_headers(request: web.Request, handler):
        resp = await handler(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-XSS-Protection"] = "1; mode=block"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # HSTS only if served over TLS
        if request.secure:
            resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        # CSP: allow self, inline styles/scripts (needed for single-file dashboard),
        # Google Fonts, and WebSocket connections
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self' ws: wss:; "
            "img-src 'self' data:; "
            "frame-ancestors 'none';"
        )
        return resp

    app.middlewares.append(security_headers)

    # Auth (no session required)
    app.router.add_get("/login", handle_login_page)
    app.router.add_post("/api/login", handle_login_api)
    app.router.add_post("/api/logout", handle_logout)

    # Web UI (session required — handle_index redirects to /login)
    app.router.add_get("/", handle_index)
    app.router.add_get("/ws", handle_websocket)

    # REST API (all require auth via @_require_auth)
    app.router.add_get("/api/status", api_status)
    app.router.add_get("/api/licenses", api_licenses)
    app.router.add_post("/api/license/add", api_license_add)
    app.router.add_post("/api/license/revoke", api_license_revoke)
    app.router.add_post("/api/license/delete", api_license_delete)
    app.router.add_post("/api/compute", api_compute)

    # Health (public — no auth)
    app.router.add_get("/health", handle_health)

    # License verification protocol (public — must be last)
    app.router.add_get("/{file_hash}/{serial}", handle_license_check)

    return app


# ═══════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="Encore Bypass Charging Addon — License Server"
    )
    parser.add_argument(
        "--port", type=int, default=8443, help="Listen port (default: 8443)"
    )
    parser.add_argument(
        "--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--permissive",
        action="store_true",
        help="Grant license to ALL devices (testing mode)",
    )
    parser.add_argument(
        "--db",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "licenses.db"),
        help="Path to encrypted license database (default: licenses.db)",
    )
    parser.add_argument(
        "--db-key",
        default=os.environ.get("LICENSE_DB_KEY", None),
        help="Passphrase for encrypting/decrypting the license DB "
             "(or set LICENSE_DB_KEY env var)",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("LICENSE_API_KEY", None),
        help="API key for admin authentication "
             "(or set LICENSE_API_KEY env var)",
    )
    parser.add_argument(
        "--tls-cert", default=None, help="Path to TLS certificate file (for HTTPS)"
    )
    parser.add_argument(
        "--tls-key", default=None, help="Path to TLS private key file (for HTTPS)"
    )
    args = parser.parse_args()

    if not args.db_key:
        log.error("Database passphrase required: use --db-key or set LICENSE_DB_KEY env var")
        sys.exit(1)

    if not args.api_key:
        log.error("API key required: use --api-key or set LICENSE_API_KEY env var")
        sys.exit(1)

    db = LicenseDatabase(args.db, args.db_key)
    state = AppState(db, args.permissive, args.bind, args.port, args.api_key)
    app = create_app(state)

    ssl_ctx = None
    if args.tls_cert and args.tls_key:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(args.tls_cert, args.tls_key)
        proto = "HTTPS"
    else:
        proto = "HTTP"

    mode = (
        "PERMISSIVE (all devices granted)"
        if args.permissive
        else "STRICT (database only)"
    )
    print()
    log.info("═══════════════════════════════════════════════════")
    log.info("  Encore License Server starting")
    log.info("  Mode:      %s", mode)
    log.info("  Listen:    %s://%s:%d", proto.lower(), args.bind, args.port)
    log.info("  Dashboard: %s://%s:%d/", proto.lower(), args.bind, args.port)
    log.info("  Database:  %s (%d entries)", args.db, len(db.list_all()))
    log.info("═══════════════════════════════════════════════════")
    print()
    log.info("  Protocol:")
    log.info("    GET /{file_hash}/{serial}")
    log.info("    → SHA256(file_hash + serial + 'Watashi...me')")
    print()
    log.info("  REST API:")
    log.info("    GET  /api/status")
    log.info("    GET  /api/licenses")
    log.info("    POST /api/license/add    {serial, file_hash}")
    log.info("    POST /api/license/revoke {serial}")
    log.info("    POST /api/compute        {file_hash, serial}")
    print()
    log.info("  WebSocket: ws://%s:%d/ws", args.bind, args.port)
    print()

    web.run_app(
        app,
        host=args.bind,
        port=args.port,
        ssl_context=ssl_ctx,
        print=None,  # We already printed our banner
    )


if __name__ == "__main__":
    main()
