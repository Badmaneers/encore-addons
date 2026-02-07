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
import json
import argparse
import os
import sys
import ssl
import logging
from datetime import datetime
from pathlib import Path

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
#  License Database
# ═══════════════════════════════════════════════════════════════════════
class LicenseDatabase:
    """Manages the license database (JSON file on disk)."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.licenses: dict = {}
        self._load()

    def _load(self):
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r") as f:
                    self.licenses = json.load(f)
                log.info(
                    "Loaded %d licenses from %s", len(self.licenses), self.db_path
                )
            except (json.JSONDecodeError, IOError) as e:
                log.error("Failed to load license DB: %s", e)
                self.licenses = {}
        else:
            log.info("No license DB found at %s, starting empty", self.db_path)
            self.licenses = {}

    def save(self):
        try:
            with open(self.db_path, "w") as f:
                json.dump(self.licenses, f, indent=2)
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
    def __init__(self, db: LicenseDatabase, permissive: bool, bind: str, port: int):
        self.db = db
        self.permissive = permissive
        self.bind = bind
        self.port = port
        self.broadcaster = ConsoleBroadcaster()
        self.request_count = 0
        self.start_time = datetime.now()


# ═══════════════════════════════════════════════════════════════════════
#  Route Handlers
# ═══════════════════════════════════════════════════════════════════════


# ─── Web UI ───────────────────────────────────────────────────────────
async def handle_index(request: web.Request) -> web.Response:
    html_path = TEMPLATE_DIR / "index.html"
    if not html_path.exists():
        return web.Response(text="Template not found", status=500)
    return web.FileResponse(html_path)


# ─── WebSocket ────────────────────────────────────────────────────────
async def handle_websocket(request: web.Request) -> web.WebSocketResponse:
    state: AppState = request.app["state"]
    ws = web.WebSocketResponse(heartbeat=30.0)
    await ws.prepare(request)
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
async def api_licenses(request: web.Request) -> web.Response:
    state: AppState = request.app["state"]
    return web.json_response(state.db.list_all())


# ─── API: Add License ────────────────────────────────────────────────
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

    state.request_count += 1

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

    # Web UI
    app.router.add_get("/", handle_index)
    app.router.add_get("/ws", handle_websocket)

    # REST API
    app.router.add_get("/api/status", api_status)
    app.router.add_get("/api/licenses", api_licenses)
    app.router.add_post("/api/license/add", api_license_add)
    app.router.add_post("/api/license/revoke", api_license_revoke)
    app.router.add_post("/api/license/delete", api_license_delete)
    app.router.add_post("/api/compute", api_compute)

    # Health
    app.router.add_get("/health", handle_health)

    # License verification protocol (must be last — catches /{hash}/{serial})
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
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "licenses.json"),
        help="Path to license database JSON (default: licenses.json)",
    )
    parser.add_argument(
        "--tls-cert", default=None, help="Path to TLS certificate file (for HTTPS)"
    )
    parser.add_argument(
        "--tls-key", default=None, help="Path to TLS private key file (for HTTPS)"
    )
    args = parser.parse_args()

    db = LicenseDatabase(args.db)
    state = AppState(db, args.permissive, args.bind, args.port)
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
