# Encore License Server

Web-based license management server for the Encore Bypass Charging Addon. Provides a dashboard UI, REST API, WebSocket live console, and the license verification endpoint used by the binary.

## Features

- **Web Dashboard** — Fluid animated UI at `/` for managing licenses
- **WebSocket Console** — Live log streaming at `/ws`
- **REST API** — JSON endpoints for license CRUD operations
- **Challenge-Response Protocol** — Nonce-based license verification with anti-replay
- **Encrypted Database** — AES-256 encrypted JSON storage (Fernet + PBKDF2)
- **Authentication** — API key + session-based login for admin access
- **Rate Limiting** — 30 requests/minute per IP
- **Security Headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- **Suspicious Pattern Detection** — Flags serials with >3 IPs, >2 hashes, or >10 requests in 5 minutes

## Requirements

```bash
pip install aiohttp cryptography
```

- Python 3.10+
- `aiohttp` — async HTTP server + WebSocket
- `cryptography` — Fernet AES encryption for license database

## Quick Start

```bash
# Basic (permissive mode — accepts all devices, for testing)
python3 license_server.py --permissive

# Strict mode with authentication and encryption
python3 license_server.py \
    --port 8443 \
    --api-key "your-secret-key" \
    --db-key "your-encryption-passphrase"

# With TLS
python3 license_server.py \
    --port 8443 \
    --api-key "your-secret-key" \
    --db-key "your-encryption-passphrase" \
    --tls-cert /path/to/cert.pem \
    --tls-key /path/to/key.pem
```

## Command-Line Options

| Flag | Default | Description |
|---|---|---|
| `--port PORT` | `8443` | Listen port |
| `--permissive` | Off | Respond with valid hash for ANY device (testing mode) |
| `--db FILE` | `licenses.json` | Path to license database file |
| `--db-key KEY` | None | Passphrase for AES-256 database encryption (PBKDF2-derived) |
| `--api-key KEY` | None | API key required for admin endpoints and WebSocket |
| `--tls-cert FILE` | None | TLS certificate for HTTPS |
| `--tls-key FILE` | None | TLS private key for HTTPS |

## Operating Modes

### Permissive Mode (`--permissive`)
Returns a valid license response for **any** device. Used for development and testing. The device is auto-registered in the database on first contact.

### Strict Mode (default)
Only responds with a valid hash if the device serial is registered in the license database. Unregistered devices get a 403 response.

## API Endpoints

### Public

| Method | Path | Description |
|---|---|---|
| `GET` | `/nonce` | Request a single-use timestamped nonce (for license checks) |
| `GET` | `/{file_hash}/{serial}` | License verification (binary calls this) |
| `GET` | `/{file_hash}/{serial}?nonce={nonce}` | Nonce-enhanced license verification |

### Admin (requires API key)

All admin endpoints require the `X-API-Key` header or an active session cookie.

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Web dashboard (redirects to `/login` if not authenticated) |
| `GET` | `/login` | Login page |
| `POST` | `/api/login` | Authenticate with API key, returns session cookie |
| `POST` | `/api/logout` | Destroy session |
| `GET` | `/api/licenses` | List all licenses (JSON) |
| `POST` | `/api/licenses` | Add a new license `{"serial": "..."}` |
| `DELETE` | `/api/licenses` | Delete a license `{"serial": "..."}` |
| `GET` | `/api/stats` | Server statistics (uptime, request counts, etc.) |
| `WS` | `/ws` | WebSocket live console (log streaming) |

## License Database

The database is a JSON file (`licenses.json` by default) mapping device serials to their license status:

```json
{
  "ABC123": {"licensed": true, "added": "2026-02-07T12:00:00"},
  "DEF456": {"licensed": true, "added": "2026-02-07T13:00:00"}
}
```

### Encryption

When `--db-key` is provided, the database is encrypted at rest using Fernet (AES-128-CBC + HMAC-SHA256). The key is derived from the passphrase using PBKDF2-HMAC-SHA256 with 480,000 iterations.

If an existing plaintext database is found, it is automatically migrated to encrypted format on first startup.

## Verification Protocol

```
Client                              Server
  │                                    │
  │  GET /nonce                        │
  │ ──────────────────────────────────>│
  │                                    │
  │  "<timestamp_hex>:<random_hex>"    │
  │ <──────────────────────────────────│
  │                                    │
  │  GET /{hash}/{serial}?nonce=...    │
  │  User-Agent: EncoreLicenseVerifier │
  │ ──────────────────────────────────>│
  │                                    │  lookup serial in DB
  │                                    │  compute SHA256(hash+serial+salt+nonce)
  │  "<hex_digest>"                    │
  │ <──────────────────────────────────│
  │                                    │
  │  compare with local computation   │
  │  (constant-time comparison)        │
```

The nonce is single-use and expires after 120 seconds. The server tracks nonces to prevent replay attacks.

## Security Notes

- **API key** is compared using constant-time comparison to prevent timing attacks
- **Sessions** use cryptographically random 32-byte tokens
- **Rate limiting** at 30 requests/minute per source IP (configurable)
- **Security headers** applied to all responses (CSP, HSTS, X-Frame-Options, etc.)
- **Anomaly tracking** flags serials exhibiting suspicious patterns (multiple IPs, rapid requests)
- The HMAC salt (`Watashi...me`) is hardcoded to match the binary's obfuscated salt

## File Structure

```
server/
├── license_server.py    # Main server application (~950 lines)
├── licenses.json        # License database (gitignored, auto-created)
└── templates/
    ├── index.html       # Admin dashboard (WebSocket console, license management)
    └── login.html       # Login page
```
