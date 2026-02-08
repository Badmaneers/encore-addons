# Encore License Server

Web-based license management server for the Encore Bypass Charging Addon. Provides a dashboard UI, REST API, WebSocket live console, and the license verification endpoint used by the binary.

Built with **Node.js** — zero-framework, using only `http`, `crypto` (built-in) + `ws` and `cookie` (npm).

## Features

- **Web Dashboard** — Fluid animated UI at `/` for managing licenses
- **WebSocket Console** — Live log streaming at `/ws`
- **REST API** — JSON endpoints for license CRUD operations
- **Challenge-Response Protocol** — Nonce-based license verification with anti-replay
- **Encrypted Database** — AES-256-GCM encrypted JSON storage (PBKDF2-derived key)
- **Authentication** — API key + session-based login for admin access
- **Rate Limiting** — 30 requests/minute per IP
- **Security Headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- **Suspicious Pattern Detection** — Flags serials with >3 IPs, >2 hashes, or >10 requests in 5 minutes

## Requirements

- **Node.js 18+**

```bash
npm install
```

Dependencies: `ws` (WebSocket), `cookie` (cookie parsing/serializing).

## Quick Start

```bash
# Install dependencies
cd server
npm install

# Basic (permissive mode — accepts all devices, for testing)
node license_server.js --permissive --api-key "test" --db-key "test"

# Strict mode with authentication and encryption
node license_server.js \
    --port 8443 \
    --api-key "your-secret-key" \
    --db-key "your-encryption-passphrase"

# With TLS
node license_server.js \
    --port 8443 \
    --api-key "your-secret-key" \
    --db-key "your-encryption-passphrase" \
    --tls-cert /path/to/cert.pem \
    --tls-key /path/to/key.pem

# Or use npm scripts
npm start                # requires env vars LICENSE_API_KEY + LICENSE_DB_KEY
npm run dev              # permissive mode with default keys (testing only)
```

### Environment Variables

Instead of CLI flags, you can use environment variables:

```bash
export LICENSE_API_KEY="your-secret-key"
export LICENSE_DB_KEY="your-encryption-passphrase"
node license_server.js
```

## Command-Line Options

| Flag | Default | Description |
|---|---|---|
| `--port PORT` | `8443` | Listen port |
| `--bind ADDR` | `0.0.0.0` | Bind address |
| `--permissive` | Off | Respond with valid hash for ANY device (testing mode) |
| `--db FILE` | `licenses.db` | Path to encrypted license database file |
| `--db-key KEY` | None | Passphrase for AES-256-GCM database encryption (PBKDF2-derived) |
| `--api-key KEY` | None | API key required for admin endpoints and WebSocket |
| `--tls-cert FILE` | None | TLS certificate for HTTPS |
| `--tls-key FILE` | None | TLS private key for HTTPS |

## Operating Modes

### Permissive Mode (`--permissive`)
Returns a valid license response for **any** device. Used for development and testing.

### Strict Mode (default)
Only responds with a valid hash if the device serial is registered and licensed in the database. Unregistered devices receive `"unlicensed"`.

## API Endpoints

### Public

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check (returns `{"status": "ok"}`) |
| `GET` | `/nonce` | Request a single-use timestamped nonce (for license checks) |
| `GET` | `/{file_hash}/{serial}` | License verification (binary calls this) |
| `GET` | `/{file_hash}/{serial}?nonce={nonce}` | Nonce-enhanced license verification |

### Admin (requires session)

All admin endpoints require a valid session cookie (obtained via `/api/login`).

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Web dashboard (redirects to `/login` if not authenticated) |
| `GET` | `/login` | Login page |
| `POST` | `/api/login` | Authenticate with API key `{"api_key": "..."}`, sets session cookie |
| `POST` | `/api/logout` | Destroy session |
| `GET` | `/api/status` | Server statistics (uptime, request counts, mode, license count) |
| `GET` | `/api/licenses` | List all licenses (JSON) |
| `POST` | `/api/license/add` | Add a license `{"serial": "...", "file_hash": "..."}` |
| `POST` | `/api/license/revoke` | Revoke a license `{"serial": "..."}` |
| `POST` | `/api/license/delete` | Permanently delete a license `{"serial": "..."}` |
| `POST` | `/api/compute` | Compute HMAC `{"file_hash": "...", "serial": "..."}` |
| `WS` | `/ws` | WebSocket live console (log streaming, authenticated via cookie) |

## License Database

The database is stored as an AES-256-GCM encrypted file (`licenses.db` by default). When decrypted, it contains JSON mapping device serials to their license status:

```json
{
  "ABC123": {"licensed": true, "file_hash": "unknown", "added": "2026-02-07T12:00:00.000Z"},
  "DEF456": {"licensed": true, "file_hash": "unknown", "added": "2026-02-07T13:00:00.000Z"}
}
```

### Encryption

The database is encrypted at rest using **AES-256-GCM** with a key derived via **PBKDF2-HMAC-SHA256** (480,000 iterations). The encryption is automatic — just provide `--db-key`.

If an existing plaintext JSON database is found, it is automatically migrated to encrypted format on first startup.

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

- **API key** is compared using `crypto.timingSafeEqual` to prevent timing attacks
- **Sessions** use cryptographically random 48-byte tokens (`crypto.randomBytes`)
- **Rate limiting** at 30 requests/minute per source IP
- **Security headers** applied to all responses (CSP, HSTS, X-Frame-Options, etc.)
- **Anomaly tracking** flags serials exhibiting suspicious patterns (multiple IPs, rapid requests)
- **Cookies** are `HttpOnly`, `SameSite=Strict`, and `Secure` (when TLS is enabled)
- The HMAC salt (`Watashi...me`) is hardcoded to match the binary's obfuscated salt

## File Structure

```
server/
├── license_server.js    # Main server application (Node.js)
├── package.json         # Dependencies and npm scripts
├── licenses.db          # Encrypted license database (gitignored, auto-created)
├── templates/
│   ├── index.html       # Admin dashboard (WebSocket console, license management)
│   └── login.html       # Login page
└── legacy/
    ├── license_server.py    # Original Python server (deprecated)
    └── requirements.txt     # Python dependencies (for legacy server)
```
