#!/usr/bin/env node
/**
 * Encore Bypass Charging Addon — License Server (Node.js Edition)
 *
 * Features:
 *   - Web dashboard at / with fluid animated UI
 *   - WebSocket live console streaming at /ws
 *   - REST API for license management
 *   - Original license verification protocol at /{file_hash}/{serial}
 *
 * Protocol:
 *   1. Client sends GET /{file_hash}/{serial}
 *      User-Agent: EncoreLicenseVerifier/1.3
 *   2. Server computes: SHA256(file_hash + serial + "Watashi...me")
 *   3. Server returns the hex digest if device is in the license database
 *      (or always, if running in permissive mode)
 *
 * Usage:
 *   node license_server.js [--port 8443] [--permissive] [--db-key KEY] [--api-key KEY]
 *
 *   --permissive    Respond with valid hash for ANY device (for testing)
 *   --db FILE       JSON file mapping serial numbers to licensed status
 *   --port PORT     Listen port (default 8443)
 *   --tls-cert      Path to TLS certificate (optional, for HTTPS)
 *   --tls-key       Path to TLS private key (optional, for HTTPS)
 */

"use strict";

const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { URL } = require("url");
const { WebSocketServer } = require("ws");
const cookie = require("cookie");

// ─── Constants matching the binary ──────────────────────────────────
const HMAC_SALT = "Watashi...me";
const TEMPLATE_DIR = path.join(__dirname, "templates");

// ─── Nonce settings ─────────────────────────────────────────────────
const NONCE_LIFETIME_SEC = 120;
const NONCE_RANDOM_BYTES = 16;

// ─── Encryption settings ────────────────────────────────────────────
const DB_KDF_SALT = "encore-license-db-v1";
const DB_KDF_ITERATIONS = 480000;

// ─── Logging ────────────────────────────────────────────────────────
function logInfo(msg) {
  const ts = new Date().toISOString().replace("T", " ").replace(/\.\d+Z$/, "");
  console.log(`${ts} INFO: ${msg}`);
}
function logWarn(msg) {
  const ts = new Date().toISOString().replace("T", " ").replace(/\.\d+Z$/, "");
  console.warn(`${ts} WARN: ${msg}`);
}
function logError(msg) {
  const ts = new Date().toISOString().replace("T", " ").replace(/\.\d+Z$/, "");
  console.error(`${ts} ERROR: ${msg}`);
}

// ─── Crypto Helpers ─────────────────────────────────────────────────
function computeExpectedResponse(fileHash, serial) {
  const data = fileHash + serial + HMAC_SALT;
  return crypto.createHash("sha256").update(data, "utf8").digest("hex");
}

function computeNonceResponse(fileHash, serial, nonce) {
  const data = fileHash + serial + HMAC_SALT + nonce;
  return crypto.createHash("sha256").update(data, "utf8").digest("hex");
}

function generateNonce() {
  const ts = Math.floor(Date.now() / 1000);
  const rand = crypto.randomBytes(NONCE_RANDOM_BYTES).toString("hex");
  return `${ts.toString(16).padStart(8, "0")}:${rand}`;
}

function verifyNonceAge(nonce) {
  try {
    const tsHex = nonce.split(":")[0];
    const nonceTime = parseInt(tsHex, 16);
    const now = Math.floor(Date.now() / 1000);
    return Math.abs(now - nonceTime) <= NONCE_LIFETIME_SEC;
  } catch {
    return false;
  }
}

function constantTimeCompare(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Compare anyway to keep constant time
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function generateSessionToken() {
  return crypto.randomBytes(48).toString("base64url");
}

// ─── Encryption (AES-256-GCM, compatible concept with Fernet) ──────
function deriveCipherKey(passphrase) {
  return crypto.pbkdf2Sync(
    passphrase,
    DB_KDF_SALT,
    DB_KDF_ITERATIONS,
    32,
    "sha256"
  );
}

function encryptData(plaintext, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  // Format: iv(12) + tag(16) + ciphertext
  return Buffer.concat([iv, tag, encrypted]);
}

function decryptData(data, key) {
  if (data.length < 28) throw new Error("Data too short");
  const iv = data.subarray(0, 12);
  const tag = data.subarray(12, 28);
  const ciphertext = data.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]).toString("utf8");
}

// ═══════════════════════════════════════════════════════════════════════
//  Rate Limiter
// ═══════════════════════════════════════════════════════════════════════
class RateLimiter {
  constructor(maxRequests = 30, windowSec = 60) {
    this.maxRequests = maxRequests;
    this.windowMs = windowSec * 1000;
    this._hits = new Map();
  }

  isAllowed(key) {
    const now = Date.now();
    let hits = this._hits.get(key) || [];
    hits = hits.filter((t) => now - t < this.windowMs);
    if (hits.length >= this.maxRequests) {
      this._hits.set(key, hits);
      return false;
    }
    hits.push(now);
    this._hits.set(key, hits);
    return true;
  }

  remaining(key) {
    const now = Date.now();
    const hits = (this._hits.get(key) || []).filter(
      (t) => now - t < this.windowMs
    );
    return Math.max(0, this.maxRequests - hits.length);
  }
}

// ═══════════════════════════════════════════════════════════════════════
//  License Database (AES-256-GCM encrypted JSON on disk)
// ═══════════════════════════════════════════════════════════════════════
class LicenseDatabase {
  constructor(dbPath, passphrase) {
    this.dbPath = dbPath;
    this.licenses = {};
    this._key = deriveCipherKey(passphrase);
    this._load();
  }

  _load() {
    if (!fs.existsSync(this.dbPath)) {
      logInfo(`No license DB found at ${this.dbPath}, starting empty`);
      return;
    }
    try {
      const raw = fs.readFileSync(this.dbPath);
      // Try decrypting (encrypted DB)
      try {
        const plaintext = decryptData(raw, this._key);
        this.licenses = JSON.parse(plaintext);
        logInfo(
          `Loaded ${Object.keys(this.licenses).length} licenses from ${this.dbPath} (encrypted)`
        );
      } catch {
        // Maybe legacy plaintext JSON — try to migrate
        try {
          this.licenses = JSON.parse(raw.toString("utf8"));
          logWarn(
            `Loaded ${Object.keys(this.licenses).length} licenses from UNENCRYPTED ${this.dbPath} — migrating to encrypted`
          );
          this.save();
        } catch {
          logError(
            `Failed to decrypt ${this.dbPath} — wrong passphrase?`
          );
          this.licenses = {};
        }
      }
    } catch (e) {
      logError(`Failed to load license DB: ${e.message}`);
      this.licenses = {};
    }
  }

  save() {
    try {
      const plaintext = JSON.stringify(this.licenses, null, 2);
      const encrypted = encryptData(plaintext, this._key);
      fs.writeFileSync(this.dbPath, encrypted);
    } catch (e) {
      logError(`Failed to save license DB: ${e.message}`);
    }
  }

  isLicensed(serial) {
    const entry = this.licenses[serial];
    return entry ? entry.licensed !== false : false;
  }

  addLicense(serial, fileHash) {
    this.licenses[serial] = {
      licensed: true,
      file_hash: fileHash,
      added: new Date().toISOString(),
    };
    this.save();
    logInfo(`Added license for serial: ${serial}`);
  }

  revokeLicense(serial) {
    if (this.licenses[serial]) {
      this.licenses[serial].licensed = false;
      this.licenses[serial].revoked = new Date().toISOString();
      this.save();
      logInfo(`Revoked license for serial: ${serial}`);
    }
  }

  deleteLicense(serial) {
    if (this.licenses[serial]) {
      delete this.licenses[serial];
      this.save();
      logInfo(`Deleted license for serial: ${serial}`);
      return true;
    }
    return false;
  }

  listAll() {
    return this.licenses;
  }
}

// ═══════════════════════════════════════════════════════════════════════
//  WebSocket Console Broadcaster
// ═══════════════════════════════════════════════════════════════════════
class ConsoleBroadcaster {
  constructor() {
    this.clients = new Set();
  }

  register(ws) {
    this.clients.add(ws);
    logInfo(`WebSocket client connected (${this.clients.size} total)`);
  }

  unregister(ws) {
    this.clients.delete(ws);
    logInfo(`WebSocket client disconnected (${this.clients.size} total)`);
  }

  broadcast(msg) {
    const payload = JSON.stringify(msg);
    const dead = [];
    for (const ws of this.clients) {
      try {
        if (ws.readyState === 1 /* OPEN */) {
          ws.send(payload);
        } else {
          dead.push(ws);
        }
      } catch {
        dead.push(ws);
      }
    }
    for (const ws of dead) this.clients.delete(ws);
  }

  sendLog(level, message, extra = {}) {
    this.broadcast({ type: "log", level, message, ...extra });
  }

  sendRequest(level, message, refresh = false) {
    this.broadcast({ type: "request", level, message, refresh });
  }
}

// ═══════════════════════════════════════════════════════════════════════
//  Application State
// ═══════════════════════════════════════════════════════════════════════
class AppState {
  constructor(db, permissive, bind, port, apiKey) {
    this.db = db;
    this.permissive = permissive;
    this.bind = bind;
    this.port = port;
    this.apiKey = apiKey;
    this.broadcaster = new ConsoleBroadcaster();
    this.requestCount = 0;
    this.startTime = new Date();
    this.rateLimiter = new RateLimiter(30, 60);
    this.sessions = new Set();
    this._nonces = new Map(); // nonce → expiryTimestamp
    this._suspicious = new Map(); // serial → [{ts, ip, hash}]
  }

  verifyApiKey(key) {
    return constantTimeCompare(this.apiKey, key);
  }

  createSession() {
    const token = generateSessionToken();
    this.sessions.add(token);
    return token;
  }

  verifySession(token) {
    if (!token) return false;
    return this.sessions.has(token);
  }

  issueNonce() {
    this._pruneNonces();
    const nonce = generateNonce();
    this._nonces.set(nonce, Date.now() + NONCE_LIFETIME_SEC * 1000);
    return nonce;
  }

  consumeNonce(nonce) {
    this._pruneNonces();
    if (this._nonces.has(nonce)) {
      this._nonces.delete(nonce);
      return verifyNonceAge(nonce);
    }
    return false;
  }

  _pruneNonces() {
    const now = Date.now();
    for (const [n, exp] of this._nonces) {
      if (exp <= now) this._nonces.delete(n);
    }
  }

  trackRequest(serial, clientIp, fileHash) {
    const now = Date.now();
    let history = this._suspicious.get(serial) || [];
    history = history.filter((h) => now - h.ts < 3600000);
    history.push({ ts: now, ip: clientIp, hash: fileHash });
    this._suspicious.set(serial, history);
  }

  isSuspicious(serial) {
    const history = this._suspicious.get(serial) || [];
    if (history.length < 3) return { suspicious: false, reason: "" };

    const uniqueIps = new Set(history.map((h) => h.ip));
    if (uniqueIps.size > 3) {
      return {
        suspicious: true,
        reason: `same serial from ${uniqueIps.size} different IPs`,
      };
    }

    const uniqueHashes = new Set(history.map((h) => h.hash));
    if (uniqueHashes.size > 2) {
      return {
        suspicious: true,
        reason: `same serial with ${uniqueHashes.size} different hashes`,
      };
    }

    const now = Date.now();
    const recent = history.filter((h) => now - h.ts < 300000);
    if (recent.length > 10) {
      return {
        suspicious: true,
        reason: `${recent.length} requests in 5 minutes`,
      };
    }

    return { suspicious: false, reason: "" };
  }
}

// ═══════════════════════════════════════════════════════════════════════
//  HTTP Helpers
// ═══════════════════════════════════════════════════════════════════════
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1e6) {
        req.destroy();
        reject(new Error("Body too large"));
      }
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });
    req.on("error", reject);
  });
}

function jsonResponse(res, data, status = 200) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

function textResponse(res, text, status = 200, headers = {}) {
  res.writeHead(status, {
    "Content-Type": "text/plain; charset=utf-8",
    "Content-Length": Buffer.byteLength(text),
    ...headers,
  });
  res.end(text);
}

function htmlResponse(res, html, status = 200) {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": Buffer.byteLength(html),
  });
  res.end(html);
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

function getSessionToken(req) {
  // Check cookie first
  const cookies = cookie.parse(req.headers.cookie || "");
  if (cookies.session) return cookies.session;
  // Fallback to Authorization: Bearer <token>
  const auth = req.headers.authorization || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  return "";
}

function getClientIp(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket.remoteAddress ||
    "unknown"
  );
}

function setSecurityHeaders(res, isSecure) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()"
  );
  if (isSecure) {
    res.setHeader(
      "Strict-Transport-Security",
      "max-age=63072000; includeSubDomains"
    );
  }
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline'; " +
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
      "font-src 'self' https://fonts.gstatic.com; " +
      "connect-src 'self' ws: wss:; " +
      "img-src 'self' data:; " +
      "frame-ancestors 'none';"
  );
}

// ═══════════════════════════════════════════════════════════════════════
//  Route Handler
// ═══════════════════════════════════════════════════════════════════════
function createRequestHandler(state, isSecure) {
  // Pre-load templates
  let indexHtml = "";
  let loginHtml = "";
  try {
    indexHtml = fs.readFileSync(path.join(TEMPLATE_DIR, "index.html"), "utf8");
  } catch {
    logWarn("index.html template not found");
  }
  try {
    loginHtml = fs.readFileSync(path.join(TEMPLATE_DIR, "login.html"), "utf8");
  } catch {
    logWarn("login.html template not found");
  }

  return async function handler(req, res) {
    setSecurityHeaders(res, isSecure);

    const url = new URL(req.url, `http://${req.headers.host}`);
    const pathname = url.pathname;
    const method = req.method;

    try {
      // ─── Auth pages ──────────────────────────────────────────
      if (method === "GET" && pathname === "/login") {
        const token = getSessionToken(req);
        if (state.verifySession(token)) return redirect(res, "/");
        if (!loginHtml) return textResponse(res, "Login template not found", 500);
        return htmlResponse(res, loginHtml);
      }

      if (method === "POST" && pathname === "/api/login") {
        let data;
        try {
          data = await parseBody(req);
        } catch {
          return jsonResponse(res, { error: "Invalid JSON" }, 400);
        }
        const apiKey = data.api_key || "";
        if (!state.verifyApiKey(apiKey)) {
          state.broadcaster.sendLog(
            "WARN",
            `Failed login attempt from ${getClientIp(req)}`
          );
          return jsonResponse(res, { error: "Invalid API key" }, 403);
        }
        const token = state.createSession();
        const cookieStr = cookie.serialize("session", token, {
          httpOnly: true,
          sameSite: "strict",
          maxAge: 86400,
          secure: isSecure,
          path: "/",
        });
        res.setHeader("Set-Cookie", cookieStr);
        state.broadcaster.sendLog(
          "OK",
          `Admin logged in from ${getClientIp(req)}`
        );
        return jsonResponse(res, { status: "ok" });
      }

      if (method === "POST" && pathname === "/api/logout") {
        const token = getSessionToken(req);
        state.sessions.delete(token);
        const cookieStr = cookie.serialize("session", "", {
          httpOnly: true,
          sameSite: "strict",
          maxAge: 0,
          path: "/",
        });
        res.setHeader("Set-Cookie", cookieStr);
        return jsonResponse(res, { status: "ok" });
      }

      // ─── Dashboard ───────────────────────────────────────────
      if (method === "GET" && pathname === "/") {
        const token = getSessionToken(req);
        if (!state.verifySession(token)) return redirect(res, "/login");
        if (!indexHtml) return textResponse(res, "Template not found", 500);
        return htmlResponse(res, indexHtml);
      }

      // ─── Health check (public) ───────────────────────────────
      if (method === "GET" && pathname === "/health") {
        return jsonResponse(res, {
          status: "ok",
          permissive: state.permissive,
        });
      }

      // ─── Nonce endpoint (public) ─────────────────────────────
      if (method === "GET" && pathname === "/nonce") {
        const clientIp = getClientIp(req);
        if (!state.rateLimiter.isAllowed(clientIp)) {
          return textResponse(res, "Too Many Requests", 429, {
            "Retry-After": "60",
          });
        }
        const nonce = state.issueNonce();
        state.broadcaster.sendRequest(
          "INFO",
          `Nonce issued to ${clientIp}: ${nonce.slice(0, 16)}...`
        );
        return textResponse(res, nonce);
      }

      // ─── API: Status (auth required) ─────────────────────────
      if (method === "GET" && pathname === "/api/status") {
        const token = getSessionToken(req);
        if (!state.verifySession(token)) {
          return jsonResponse(res, { error: "Unauthorized" }, 401);
        }
        return jsonResponse(res, {
          status: "ok",
          permissive: state.permissive,
          address: `${state.bind}:${state.port}`,
          request_count: state.requestCount,
          uptime_seconds: (Date.now() - state.startTime.getTime()) / 1000,
          license_count: Object.keys(state.db.listAll()).length,
        });
      }

      // ─── API: List Licenses (auth required) ──────────────────
      if (method === "GET" && pathname === "/api/licenses") {
        const token = getSessionToken(req);
        if (!state.verifySession(token)) {
          return jsonResponse(res, { error: "Unauthorized" }, 401);
        }
        return jsonResponse(res, state.db.listAll());
      }

      // ─── API: Add License (auth required) ────────────────────
      if (method === "POST" && pathname === "/api/license/add") {
        const token = getSessionToken(req);
        if (!state.verifySession(token)) {
          return jsonResponse(res, { error: "Unauthorized" }, 401);
        }
        let data;
        try {
          data = await parseBody(req);
        } catch {
          return jsonResponse(res, { error: "Invalid JSON" }, 400);
        }
        const serial = (data.serial || "").trim();
        const fileHash = (data.file_hash || "unknown").trim() || "unknown";
        if (!serial) {
          return jsonResponse(res, { error: "serial is required" }, 400);
        }
        state.db.addLicense(serial, fileHash);
        state.broadcaster.sendRequest(
          "OK",
          `License GRANTED for serial=${serial}`,
          true
        );
        return jsonResponse(res, { status: "added", serial });
      }

      // ─── API: Revoke License (auth required) ─────────────────
      if (method === "POST" && pathname === "/api/license/revoke") {
        const token = getSessionToken(req);
        if (!state.verifySession(token)) {
          return jsonResponse(res, { error: "Unauthorized" }, 401);
        }
        let data;
        try {
          data = await parseBody(req);
        } catch {
          return jsonResponse(res, { error: "Invalid JSON" }, 400);
        }
        const serial = (data.serial || "").trim();
        if (!serial) {
          return jsonResponse(res, { error: "serial is required" }, 400);
        }
        state.db.revokeLicense(serial);
        state.broadcaster.sendRequest(
          "WARN",
          `License REVOKED for serial=${serial}`,
          true
        );
        return jsonResponse(res, { status: "revoked", serial });
      }

      // ─── API: Delete License (auth required) ─────────────────
      if (method === "POST" && pathname === "/api/license/delete") {
        const token = getSessionToken(req);
        if (!state.verifySession(token)) {
          return jsonResponse(res, { error: "Unauthorized" }, 401);
        }
        let data;
        try {
          data = await parseBody(req);
        } catch {
          return jsonResponse(res, { error: "Invalid JSON" }, 400);
        }
        const serial = (data.serial || "").trim();
        if (!serial) {
          return jsonResponse(res, { error: "serial is required" }, 400);
        }
        if (state.db.deleteLicense(serial)) {
          state.broadcaster.sendRequest(
            "WARN",
            `License DELETED for serial=${serial}`,
            true
          );
          return jsonResponse(res, { status: "deleted", serial });
        } else {
          return jsonResponse(res, { error: "Serial not found" }, 404);
        }
      }

      // ─── API: Compute HMAC (auth required) ───────────────────
      if (method === "POST" && pathname === "/api/compute") {
        const token = getSessionToken(req);
        if (!state.verifySession(token)) {
          return jsonResponse(res, { error: "Unauthorized" }, 401);
        }
        let data;
        try {
          data = await parseBody(req);
        } catch {
          return jsonResponse(res, { error: "Invalid JSON" }, 400);
        }
        const fileHash = (data.file_hash || "").trim();
        const serial = (data.serial || "").trim();
        if (!fileHash || !serial) {
          return jsonResponse(
            res,
            { error: "file_hash and serial are required" },
            400
          );
        }
        const expected = computeExpectedResponse(fileHash, serial);
        return jsonResponse(res, {
          file_hash: fileHash,
          serial,
          expected_response: expected,
          formula: "SHA256(file_hash + serial + 'Watashi...me')",
        });
      }

      // ─── License Verification (public — /{file_hash}/{serial}) ──
      const licenseMatch = pathname.match(
        /^\/([0-9a-f]{64})\/([^/]+)$/
      );
      if (method === "GET" && licenseMatch) {
        const fileHash = licenseMatch[1];
        const serial = decodeURIComponent(licenseMatch[2]);
        const ua = req.headers["user-agent"] || "unknown";
        const clientIp = getClientIp(req);
        const nonce = url.searchParams.get("nonce");

        state.requestCount++;

        // Rate limiting
        if (!state.rateLimiter.isAllowed(clientIp)) {
          state.broadcaster.sendRequest(
            "WARN",
            `Rate limited: ${clientIp} (too many requests)`
          );
          return textResponse(res, "Too Many Requests", 429, {
            "Retry-After": "60",
          });
        }

        // Track request for anomaly detection
        state.trackRequest(serial, clientIp, fileHash);
        const { suspicious, reason } = state.isSuspicious(serial);
        if (suspicious) {
          state.broadcaster.sendRequest(
            "WARN",
            `⚠️ SUSPICIOUS: serial=${serial} — ${reason} (IP=${clientIp})`
          );
        }

        // Validate nonce if provided
        let nonceValid = false;
        if (nonce) {
          nonceValid = state.consumeNonce(nonce);
          if (!nonceValid) {
            state.broadcaster.sendRequest(
              "WARN",
              `Invalid/expired nonce from ${clientIp} serial=${serial}`
            );
          }
        }

        const proto = nonceValid ? "nonce" : "legacy";
        state.broadcaster.sendRequest(
          "INFO",
          `License check (${proto}): serial=${serial} hash=${fileHash.slice(0, 8)}...${fileHash.slice(-8)} UA=${ua}`
        );

        // Compute the appropriate response
        const expected = nonceValid
          ? computeNonceResponse(fileHash, serial, nonce)
          : computeExpectedResponse(fileHash, serial);

        if (state.permissive) {
          state.broadcaster.sendRequest(
            "OK",
            `PERMISSIVE: license GRANTED to serial=${serial}`
          );
          return textResponse(res, expected);
        }

        if (state.db.isLicensed(serial)) {
          state.broadcaster.sendRequest(
            "OK",
            `LICENSED: serial=${serial} — response sent (${proto})`
          );
          return textResponse(res, expected);
        } else {
          state.broadcaster.sendRequest(
            "WARN",
            `UNLICENSED: serial=${serial} — denied`
          );
          return textResponse(res, "unlicensed");
        }
      }

      // ─── 404 ─────────────────────────────────────────────────
      return jsonResponse(res, { error: "Not found" }, 404);
    } catch (err) {
      logError(`Request error: ${err.message}`);
      return jsonResponse(res, { error: "Internal server error" }, 500);
    }
  };
}

// ═══════════════════════════════════════════════════════════════════════
//  WebSocket Setup
// ═══════════════════════════════════════════════════════════════════════
function setupWebSocket(server, state) {
  const wss = new WebSocketServer({ noServer: true });

  server.on("upgrade", (req, socket, head) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (url.pathname !== "/ws") {
      socket.destroy();
      return;
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit("connection", ws, req);
    });
  });

  wss.on("connection", (ws, req) => {
    // Authenticate via cookie
    const cookies = cookie.parse(req.headers.cookie || "");
    let authenticated = state.verifySession(cookies.session || "");

    if (authenticated) {
      finishAuth(ws, state);
    } else {
      // Wait for auth message
      const authTimeout = setTimeout(() => {
        if (!authenticated) {
          ws.send(
            JSON.stringify({ type: "error", message: "Unauthorized" })
          );
          ws.close(4001, "Unauthorized");
        }
      }, 10000);

      ws.once("message", (data) => {
        clearTimeout(authTimeout);
        try {
          const msg = JSON.parse(data.toString());
          if (
            msg.type === "auth" &&
            state.verifySession(msg.token || "")
          ) {
            authenticated = true;
            finishAuth(ws, state);
          } else {
            ws.send(
              JSON.stringify({ type: "error", message: "Unauthorized" })
            );
            ws.close(4001, "Unauthorized");
          }
        } catch {
          ws.send(
            JSON.stringify({ type: "error", message: "Unauthorized" })
          );
          ws.close(4001, "Unauthorized");
        }
      });
    }
  });
}

function finishAuth(ws, state) {
  state.broadcaster.register(ws);

  // Send welcome + initial stats
  ws.send(
    JSON.stringify({
      type: "log",
      level: "OK",
      message: `Dashboard connected — ${Object.keys(state.db.listAll()).length} licenses loaded`,
    })
  );
  ws.send(
    JSON.stringify({
      type: "stats",
      request_count: state.requestCount,
    })
  );

  ws.on("close", () => {
    state.broadcaster.unregister(ws);
  });

  ws.on("error", () => {
    state.broadcaster.unregister(ws);
  });
}

// ═══════════════════════════════════════════════════════════════════════
//  CLI Argument Parser
// ═══════════════════════════════════════════════════════════════════════
function parseArgs() {
  const args = {
    port: 8443,
    bind: "0.0.0.0",
    permissive: false,
    db: path.join(__dirname, "licenses.db"),
    dbKey: process.env.LICENSE_DB_KEY || null,
    apiKey: process.env.LICENSE_API_KEY || null,
    tlsCert: null,
    tlsKey: null,
  };

  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case "--port":
        args.port = parseInt(argv[++i], 10);
        break;
      case "--bind":
        args.bind = argv[++i];
        break;
      case "--permissive":
        args.permissive = true;
        break;
      case "--db":
        args.db = argv[++i];
        break;
      case "--db-key":
        args.dbKey = argv[++i];
        break;
      case "--api-key":
        args.apiKey = argv[++i];
        break;
      case "--tls-cert":
        args.tlsCert = argv[++i];
        break;
      case "--tls-key":
        args.tlsKey = argv[++i];
        break;
      case "--help":
      case "-h":
        console.log(`
Encore License Server (Node.js)

Usage: node license_server.js [options]

Options:
  --port PORT       Listen port (default: 8443)
  --bind ADDR       Bind address (default: 0.0.0.0)
  --permissive      Grant license to ALL devices (testing)
  --db FILE         Path to encrypted license DB (default: licenses.db)
  --db-key KEY      Passphrase for DB encryption (or LICENSE_DB_KEY env)
  --api-key KEY     API key for admin auth (or LICENSE_API_KEY env)
  --tls-cert FILE   Path to TLS certificate (for HTTPS)
  --tls-key FILE    Path to TLS private key (for HTTPS)
  -h, --help        Show this help
`);
        process.exit(0);
    }
  }

  return args;
}

// ═══════════════════════════════════════════════════════════════════════
//  Main
// ═══════════════════════════════════════════════════════════════════════
function main() {
  const args = parseArgs();

  if (!args.dbKey) {
    logError(
      "Database passphrase required: use --db-key or set LICENSE_DB_KEY env var"
    );
    process.exit(1);
  }

  if (!args.apiKey) {
    logError(
      "API key required: use --api-key or set LICENSE_API_KEY env var"
    );
    process.exit(1);
  }

  const db = new LicenseDatabase(args.db, args.dbKey);
  const state = new AppState(
    db,
    args.permissive,
    args.bind,
    args.port,
    args.apiKey
  );

  let server;
  let proto;
  const isSecure = !!(args.tlsCert && args.tlsKey);

  if (isSecure) {
    const sslOptions = {
      cert: fs.readFileSync(args.tlsCert),
      key: fs.readFileSync(args.tlsKey),
    };
    server = https.createServer(sslOptions, createRequestHandler(state, true));
    proto = "HTTPS";
  } else {
    server = http.createServer(createRequestHandler(state, false));
    proto = "HTTP";
  }

  setupWebSocket(server, state);

  const mode = args.permissive
    ? "PERMISSIVE (all devices granted)"
    : "STRICT (database only)";

  server.listen(args.port, args.bind, () => {
    console.log();
    logInfo("═══════════════════════════════════════════════════");
    logInfo("  Encore License Server starting (Node.js)");
    logInfo(`  Mode:      ${mode}`);
    logInfo(
      `  Listen:    ${proto.toLowerCase()}://${args.bind}:${args.port}`
    );
    logInfo(
      `  Dashboard: ${proto.toLowerCase()}://${args.bind}:${args.port}/`
    );
    logInfo(
      `  Database:  ${args.db} (${Object.keys(db.listAll()).length} entries)`
    );
    logInfo("═══════════════════════════════════════════════════");
    console.log();
    logInfo("  Protocol:");
    logInfo("    GET /nonce → fresh challenge nonce");
    logInfo("    GET /{file_hash}/{serial}[?nonce=<nonce>]");
    logInfo("    → SHA256(file_hash + serial + salt [+ nonce])");
    logInfo(`    Nonce lifetime: ${NONCE_LIFETIME_SEC}s`);
    console.log();
    logInfo("  REST API:");
    logInfo("    GET  /api/status");
    logInfo("    GET  /api/licenses");
    logInfo("    POST /api/license/add    {serial, file_hash}");
    logInfo("    POST /api/license/revoke {serial}");
    logInfo("    POST /api/license/delete {serial}");
    logInfo("    POST /api/compute        {file_hash, serial}");
    console.log();
    logInfo(
      `  WebSocket: ws://${args.bind}:${args.port}/ws`
    );
    console.log();
  });

  // Graceful shutdown
  process.on("SIGINT", () => {
    logInfo("Shutting down...");
    server.close(() => process.exit(0));
  });
  process.on("SIGTERM", () => {
    logInfo("Shutting down...");
    server.close(() => process.exit(0));
  });
}

main();
