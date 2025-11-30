import { Router } from 'itty-router'

// Import our modular routes
import authRoutes from './src/routes/authRoutes'
import passwordRoutes from './src/routes/passwordRoutes'

const router = Router()

// ============ Lazy DB Migration for 2FA Columns ============
let migrationChecked = false
async function ensureMigration(env) {
  if (migrationChecked) return
  try {
    const info = await env.DB.prepare('PRAGMA table_info(users)').all()
    const cols = info.results.map(c => c.name)
    const needEnabled = !cols.includes('two_factor_enabled')
    const needSecret = !cols.includes('two_factor_secret')
    if (needEnabled) {
      await env.DB.prepare('ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER DEFAULT 0').run()
    }
    if (needSecret) {
      await env.DB.prepare('ALTER TABLE users ADD COLUMN two_factor_secret TEXT').run()
    }
    // Add username column to passwords if missing
    const pinfo = await env.DB.prepare('PRAGMA table_info(passwords)').all()
    const pcols = pinfo.results.map(c => c.name)
    if (!pcols.includes('username')) {
      try {
        await env.DB.prepare('ALTER TABLE passwords ADD COLUMN username TEXT DEFAULT ""').run()
      } catch (e) {
        // ignore
      }
    }
    if (!pcols.includes('tags')) {
      try {
        await env.DB.prepare('ALTER TABLE passwords ADD COLUMN tags TEXT DEFAULT ""').run()
      } catch (e) {
        // ignore
      }
    }
    // Recovery codes table
    const rcExists = await tableExists(env, 'recovery_codes')
    if (!rcExists) {
      try {
        await env.DB.prepare('CREATE TABLE recovery_codes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, code_hash TEXT, used INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)').run()
        await env.DB.prepare('CREATE INDEX idx_recovery_user ON recovery_codes(user_id)').run()
      } catch (e) {
        // ignore
      }
    }
  } catch (e) {
    // swallow errors to avoid breaking requests
  } finally {
    migrationChecked = true
  }
}

// ============ Helper Functions ============

// 通用：检测表是否存在（常量表名，避免拼写错误）
async function tableExists(env, tableName) {
  try {
    const q = "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
    const r = await env.DB.prepare(q).bind(tableName).all()
    return r.results && r.results.length > 0
  } catch { return false }
}

// Base64 helpers
function base64ToBytes(str) {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0))
}
function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes))
}

// Legacy hash (backwards compatibility for existing accounts)
async function legacyHashPassword(password) {
  const enc = new TextEncoder()
  const data = enc.encode(password + 'salt_demo')
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return bytesToBase64(new Uint8Array(hashBuffer))
}

// Create PBKDF2 hash with random salt: returns "salt:hash" (both base64)
async function createPasswordHash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const enc = new TextEncoder()
  const passKey = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits'])
  const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, passKey, 256)
  const derived = new Uint8Array(derivedBits)
  const saltB64 = bytesToBase64(salt)
  const hashB64 = bytesToBase64(derived)
  return `${saltB64}:${hashB64}`
}

// Verify hash supporting both new format (salt:hash) and legacy
async function verifyPassword(password, stored) {
  if (!stored.includes(':')) {
    // Legacy path
    const legacy = await legacyHashPassword(password)
    return legacy === stored
  }
  const [saltB64, hashB64] = stored.split(':')
  const salt = base64ToBytes(saltB64)
  const enc = new TextEncoder()
  const passKey = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits'])
  const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, passKey, 256)
  const derived = bytesToBase64(new Uint8Array(derivedBits))
  // Constant time compare
  if (derived.length !== hashB64.length) return false
  let diff = 0
  for (let i = 0; i < derived.length; i++) diff |= derived.charCodeAt(i) ^ hashB64.charCodeAt(i)
  return diff === 0
}

// Generate JWT token
async function hmacSHA256(message, secret) {
  const enc = new TextEncoder()
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message))
  return bytesToBase64(new Uint8Array(sig))
}

async function generateToken(userId, env) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payload = btoa(JSON.stringify({
    userId,
    exp: Math.floor(Date.now() / 1000) + 86400 * 7 // 7 days
  }))
  const secret = env?.JWT_SECRET || ''
  if (!secret) throw new Error('Missing JWT_SECRET')
  const signature = await hmacSHA256(`${header}.${payload}`, secret)
  return `${header}.${payload}.${signature}`
}

// Temporary JWT for pending 2FA (short lifetime 5m)
async function generateTemp2FAToken(userId, env) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payload = btoa(JSON.stringify({ userId, twofa: 'pending', exp: Math.floor(Date.now() / 1000) + 300 }))
  const secret = env?.JWT_SECRET || ''
  if (!secret) throw new Error('Missing JWT_SECRET')
  const signature = await hmacSHA256(`${header}.${payload}`, secret)
  return `${header}.${payload}.${signature}`
}

// Verify JWT token
function verifyToken(token, env) {
  try {
    const [header, payload, signature] = token.split('.')
    const decoded = JSON.parse(atob(payload))
    if (decoded.exp < Math.floor(Date.now() / 1000)) {
      return null
    }
    const secret = env?.JWT_SECRET || ''
    if (!secret) return null
    // verify signature
    return crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'])
      .then(key => crypto.subtle.verify('HMAC', key, base64ToBytes(signature), new TextEncoder().encode(`${header}.${payload}`)))
      .then(ok => ok ? decoded.userId : null)
      .catch(() => null)
  } catch {
    return null
  }
}

function decodeToken(token, env) {
  try {
    const [header, payload, signature] = token.split('.')
    const decoded = JSON.parse(atob(payload))
    if (decoded.exp < Math.floor(Date.now() / 1000)) return null
    const secret = env?.JWT_SECRET || ''
    if (!secret) return null
    return crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'])
      .then(key => crypto.subtle.verify('HMAC', key, base64ToBytes(signature), new TextEncoder().encode(`${header}.${payload}`)))
      .then(ok => ok ? decoded : null)
      .catch(() => null)
  } catch { return null }
}

// Extract user from request
async function getUserFromRequest(request, env) {
  const auth = request.headers.get('Authorization')
  if (!auth || !auth.startsWith('Bearer ')) return null
  const token = auth.slice(7)
  return await verifyToken(token, env)
}

// Encryption (updated to use AES-GCM for production)
async function encryptPassword(password, keyMaterial) {
  // Create a key from the key material
  const keyBytes = new TextEncoder().encode(keyMaterial);
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  // Derive an AES-GCM key
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: new TextEncoder().encode('salt_for_passfortress'),
      iterations: 100000,
      hash: 'SHA-256'
    },
    key,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  // Generate a random IV
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt the password
  const plaintextBytes = new TextEncoder().encode(password);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    plaintextBytes
  );

  // Combine IV and ciphertext
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);

  // Return as base64
  const bytes = new Uint8Array(combined.buffer);
  let binaryString = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binaryString += String.fromCharCode(bytes[i]);
  }
  return btoa(binaryString);
}

async function decryptPassword(encryptedPassword, keyMaterial) {
  // Create a key from the key material
  const keyBytes = new TextEncoder().encode(keyMaterial);
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  // Derive the AES-GCM key
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: new TextEncoder().encode('salt_for_passfortress'),
      iterations: 100000,
      hash: 'SHA-256'
    },
    key,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  // Decode from base64
  const binaryString = atob(encryptedPassword);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  const combined = bytes.buffer;

  const combinedBytes = new Uint8Array(combined);

  // Extract IV and ciphertext
  const iv = combinedBytes.slice(0, 12);
  const ciphertext = combinedBytes.slice(12);

  // Decrypt
  const plaintextBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    ciphertext
  );

  // Convert to string
  return new TextDecoder().decode(plaintextBuffer);
}

// ============ TOTP 2FA Helpers ============
// Base32 decode (RFC 4648, no padding required)
function base32Decode(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  let out = []
  const clean = str.replace(/=+$/,'').toUpperCase()
  for (const c of clean) {
    const val = alphabet.indexOf(c)
    if (val < 0) continue
    bits += val.toString(2).padStart(5,'0')
    while (bits.length >= 8) {
      out.push(parseInt(bits.slice(0,8),2))
      bits = bits.slice(8)
    }
  }
  return new Uint8Array(out)
}

// Generate random base32 secret
function generateBase32Secret(length = 32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bytes = crypto.getRandomValues(new Uint8Array(length))
  let out = ''
  for (const b of bytes) out += alphabet[b % alphabet.length]
  return out
}

async function generateTOTP(secret, timeStep = 30, digits = 6) {
  const keyBytes = base32Decode(secret)
  const counter = Math.floor(Date.now() / 1000 / timeStep)
  const buf = new ArrayBuffer(8)
  const view = new DataView(buf)
  view.setUint32(4, counter) // low 32 bits
  // Import HMAC key
  const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign'])
  const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, buf))
  const offset = hmac[hmac.length - 1] & 0x0f
  const binary = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff)
  const otp = (binary % (10 ** digits)).toString().padStart(digits, '0')
  return otp
}

async function verifyTOTP(secret, code) {
  if (!/^[0-9]{6}$/.test(code)) return false
  // Allow small drift ±1 window
  for (let drift = -1; drift <= 1; drift++) {
    const keyBytes = base32Decode(secret)
    const counter = Math.floor(Date.now() / 1000 / 30) + drift
    const buf = new ArrayBuffer(8)
    const view = new DataView(buf)
    view.setUint32(4, counter)
    const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign'])
    const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, buf))
    const offset = hmac[hmac.length - 1] & 0x0f
    const binary = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff)
    const otp = (binary % (10 ** 6)).toString().padStart(6, '0')
    if (otp === code) return true
  }
  return false
}

// ============ CORS Middleware ============
// 从环境变量或请求自动检测允许的�?
function getAllowedOrigins(env, request) {
  const origins = []
  // 添加环境变量配置的域�?
  if (env.CUSTOM_DOMAIN) {
    origins.push(`https://${env.CUSTOM_DOMAIN}`)
  }
  // 添加当前请求的域名（workers.dev或自定义域名�?
  const requestUrl = new URL(request.url)
  const currentOrigin = `${requestUrl.protocol}//${requestUrl.hostname}`
  if (!origins.includes(currentOrigin)) {
    origins.push(currentOrigin)
  }
  return origins
}

// OPTIONS 预检
router.options('*', (request, env) => {
  const allowedOrigins = getAllowedOrigins(env, request)
  const origin = request.headers.get('Origin')
  const allowOrigin = origin && allowedOrigins.includes(origin) ? origin : allowedOrigins[0]
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': allowOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, PUT, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400'
    }
  })
})

// 公共配置端点：暴露非敏感运行时配置供前端使用
router.get('/api/config', async (request, env) => {
  const allowed = getAllowedOrigins(env, request)
  const sitekey = env.TURNSTILE_SITE_KEY || ''
  const domain = env.CUSTOM_DOMAIN || ''
  return new Response(JSON.stringify({ sitekey, domain }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' }
  })
})

// 安全响应�?+ CORS + RateLimit �?
function applySecurityHeaders(response, request, rateInfo, env) {
  const allowedOrigins = env ? getAllowedOrigins(env, request) : []
  const origin = request.headers.get('Origin')
  const allowOrigin = origin && allowedOrigins.includes(origin) ? origin : (allowedOrigins[0] || request.headers.get('host'))
  const h = response.headers
  h.set('Access-Control-Allow-Origin', allowOrigin)
  h.set('Vary', 'Origin')
  h.set('X-Content-Type-Options', 'nosniff')
  h.set('X-Frame-Options', 'SAMEORIGIN')
  h.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  h.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
  h.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
  // 收紧CSP：将 connect-src 限定为允许来源（自定义域与当前 worker 子域），阻止 cloudflareinsights 脚本
  // 使用上方 allowedOrigins 计算 connect-src
  const connectSrc = allowedOrigins.length ? allowedOrigins.join(' ') : "'self'"
  h.set('Content-Security-Policy', `default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src ${connectSrc}; frame-src https://challenges.cloudflare.com; object-src 'none'; base-uri 'self'`)
  if (rateInfo) {
    h.set('X-RateLimit-Limit', rateInfo.limit.toString())
    h.set('X-RateLimit-Remaining', Math.max(rateInfo.limit - rateInfo.count, 0).toString())
    h.set('X-RateLimit-Reset', rateInfo.reset.toString())
  }
  return response
}

// 允许来源计算（生产收紧到自定义域与 worker 子域）
function getAllowedOrigin(request, env) {
  const origin = request.headers.get('Origin') || ''
  const allowed = new Set()
  if (env?.CUSTOM_DOMAIN) {
    const https = `https://${env.CUSTOM_DOMAIN}`
    const http = `http://${env.CUSTOM_DOMAIN}`
    allowed.add(https); allowed.add(http)
  }
  // 允许本地开发与 worker 子域
  const host = request.headers.get('Host') || ''
  if (host) {
    allowed.add(`https://${host}`)
    allowed.add(`http://${host}`)
  }
  if (origin && allowed.has(origin)) return origin
  // 默认仅回退到 self 以阻止滥用跨域
  return null
}

// 包装响应
function addCors(response, request, rateInfo, env) {
  const res = applySecurityHeaders(response, request, rateInfo, env)
  const origin = getAllowedOrigin(request, env)
  if (origin) {
    res.headers.set('Access-Control-Allow-Origin', origin)
    res.headers.set('Vary', 'Origin')
  } else {
    // 不设置通配，阻止任意站点跨域读
  }
  return res
}

// ============ Rate Limiting ============
const RATE_LIMIT = 30
const WINDOW_MS = 60_000
const AUTH_RATE_LIMIT = 10
const AUTH_WINDOW_MS = 60_000
const rateBuckets = new Map() // key -> {count, reset}

function checkRateLimit(request, { auth = false } = {}) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown'
  const now = Date.now()
  const key = `${auth ? 'auth' : 'gen'}:${ip}`
  let bucket = rateBuckets.get(key)
  if (!bucket || bucket.reset < now) {
    bucket = { count: 0, reset: now + (auth ? AUTH_WINDOW_MS : WINDOW_MS) }
  }
  bucket.count += 1
  rateBuckets.set(key, bucket)
  const limit = auth ? AUTH_RATE_LIMIT : RATE_LIMIT
  return { allowed: bucket.count <= limit, count: bucket.count, limit, reset: Math.floor(bucket.reset / 1000) }
}

// Turnstile 验证
async function verifyTurnstile(token, request, env) {
  try {
    if (!env?.TURNSTILE_SECRET) return true // 未配置则跳过
    if (!token) return false
    const ip = request.headers.get('CF-Connecting-IP') || ''
    const form = new URLSearchParams()
    form.append('secret', env.TURNSTILE_SECRET)
    form.append('response', token)
    if (ip) form.append('remoteip', ip)
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: form,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    })
    const data = await r.json()
    // 将错误代码附加到全局以便调用方记录
    request.__turnstile_last = data
    return !!data.success
  } catch (e) {
    return false
  }
}

// 登录失败计数（内存锁）
const loginFailures = new Map() // key=email|ip -> {count, until}
function isLocked(key) {
  const info = loginFailures.get(key)
  return info && info.until && info.until > Date.now()
}
function recordFailure(key) {
  const info = loginFailures.get(key) || { count: 0, until: 0 }
  info.count += 1
  if (info.count >= 5) {
    info.until = Date.now() + 15 * 60_000 // 锁 15 分钟
    info.count = 0
  }
  loginFailures.set(key, info)
}
function clearFailures(key) { loginFailures.delete(key) }

// ============ Auth Routes ============

// Register
router.post('/api/auth/register', async (request, env) => {
  try {
    const rl = checkRateLimit(request, { auth: true })
    if (!rl.allowed) {
      return addCors(new Response(JSON.stringify({ error: 'Too many requests' }), { status: 429, headers: { 'Content-Type': 'application/json' } }), request, rl, env)
    }
    const { email, password } = await request.json()
    if (!email || !password) {
      return addCors(new Response(JSON.stringify({ error: 'email and password required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }
    // Turnstile 验证（前端需提交 cf_turnstile_token）
    const cfToken = request.headers.get('X-CF-Turnstile') || null
    const okCaptcha = await verifyTurnstile(cfToken, request, env)
    const dbg = request.__turnstile_last || {}
    if (!okCaptcha && String(env?.TURNSTILE_ENFORCE || 'true').toLowerCase() === 'true') {
      return addCors(new Response(JSON.stringify({ error: 'Captcha verification failed', details: dbg['error-codes'] || [] }), { status: 403, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }

    // Basic server-side validation (avoid user enumeration / weak password acceptance)
    const emailRegex = /^[^@\s]+@[^@\s]+\.[^@\s]+$/
    if (!emailRegex.test(email)) {
      return addCors(new Response(JSON.stringify({ error: 'Invalid registration data' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }
    // Password policy: >=8 chars, include 3 of (lower, upper, number, symbol)
    const categories = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].reduce((acc, r) => acc + (r.test(password) ? 1 : 0), 0)
    if (password.length < 8 || categories < 3) {
      return addCors(new Response(JSON.stringify({ error: 'Invalid registration data' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }

    // Check if user exists
    const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first()
    if (existing) {
      return addCors(new Response(JSON.stringify({ error: 'Registration failed' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }

    // Hash password (PBKDF2)
    const passwordHash = await createPasswordHash(password)

    // Create user
    const stmt = env.DB.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)')
    await stmt.bind(email, passwordHash).run()
    const result = await env.DB.prepare('SELECT id, email FROM users WHERE email = ?').bind(email).first()

    const token = await generateToken(result.id, env)

    const payload = { user: result, token }
    if (!okCaptcha) {
      payload.warning = 'Captcha not verified'
      payload.details = dbg['error-codes'] || []
      payload.soft = true
    }
    return addCors(new Response(JSON.stringify(payload), { status: 201, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  }
})

// Login
router.post('/api/auth/login', async (request, env) => {
  try {
    await ensureMigration(env)
    const rl = checkRateLimit(request, { auth: true })
    if (!rl.allowed) {
      return addCors(new Response(JSON.stringify({ error: 'Too many requests' }), { status: 429, headers: { 'Content-Type': 'application/json' } }), request, rl, env)
    }
    const { email, password } = await request.json()
    if (!email || !password) {
      return addCors(new Response(JSON.stringify({ error: 'email and password required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }
    const lockKey = `email:${email.trim().toLowerCase()}`
    const ipKey = `ip:${request.headers.get('CF-Connecting-IP') || 'unknown'}`
    if (isLocked(lockKey) || isLocked(ipKey)) {
      return addCors(new Response(JSON.stringify({ error: 'Temporarily locked. Try later.' }), { status: 423, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }
    const cfToken = request.headers.get('X-CF-Turnstile') || null
    const okCaptcha = await verifyTurnstile(cfToken, request, env)
    if (!okCaptcha) {
      recordFailure(lockKey); recordFailure(ipKey)
      const dbg = request.__turnstile_last || {}
      if (String(env?.TURNSTILE_ENFORCE || 'true').toLowerCase() === 'false') {
        // 软通过：继续执行登录流程
        // 不再返回错误，后续逻辑将继续
      } else {
        return addCors(new Response(JSON.stringify({ error: 'Captcha verification failed', details: dbg['error-codes'] || [] }), { status: 403, headers: { 'Content-Type': 'application/json' } }), request, null, env)
      }
    }

    // Normalize email (defensive)
    const normalizedEmail = email.trim().toLowerCase()
    const emailRegex = /^[^@\s]+@[^@\s]+\.[^@\s]+$/
    if (!emailRegex.test(normalizedEmail)) {
      return addCors(new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }
    const user = await env.DB.prepare('SELECT id, password_hash, two_factor_enabled FROM users WHERE email = ?').bind(normalizedEmail).first()
    if (!user) {
      recordFailure(lockKey); recordFailure(ipKey)
      return addCors(new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }

    const isValid = await verifyPassword(password, user.password_hash)
    if (!isValid) {
      recordFailure(lockKey); recordFailure(ipKey)
      return addCors(new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }

    if (user.two_factor_enabled) {
      // Return temp token requiring 2FA
      const temp = await generateTemp2FAToken(user.id, env)
      clearFailures(lockKey); clearFailures(ipKey)
      return addCors(new Response(JSON.stringify({ require2FA: true, tempToken: temp }), { status: 200, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }
    const token = await generateToken(user.id, env)
    clearFailures(lockKey); clearFailures(ipKey)
    return addCors(new Response(JSON.stringify({ user: { id: user.id, email: normalizedEmail }, token }), { status: 200, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  }
})

// init 2FA: generate secret (not enabled until activation)
router.post('/api/auth/2fa/init', async (request, env) => {
  try {
    await ensureMigration(env)
    const userId = await getUserFromRequest(request, env)
    if (!userId) return addCors(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    const user = await env.DB.prepare('SELECT two_factor_enabled, two_factor_secret, email FROM users WHERE id = ?').bind(userId).first()
    if (user.two_factor_enabled) return addCors(new Response(JSON.stringify({ error: 'Already enabled' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    const secret = generateBase32Secret(32)
    await env.DB.prepare('UPDATE users SET two_factor_secret = ? WHERE id = ?').bind(secret, userId).run()
    const otpauth = `otpauth://totp/PassFortress:${encodeURIComponent(user.email)}?secret=${secret}&issuer=PassFortress`
    return addCors(new Response(JSON.stringify({ secret, otpauth }), { status: 200, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  }
})

// activate 2FA (verify code then enable)
router.post('/api/auth/2fa/activate', async (request, env) => {
  try {
    await ensureMigration(env)
    const userId = await getUserFromRequest(request, env)
    if (!userId) return addCors(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    const { code } = await request.json()
    if (!code) return addCors(new Response(JSON.stringify({ error: 'code required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    const user = await env.DB.prepare('SELECT two_factor_secret, two_factor_enabled FROM users WHERE id = ?').bind(userId).first()
    if (!user.two_factor_secret) return addCors(new Response(JSON.stringify({ error: 'init required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    if (user.two_factor_enabled) return addCors(new Response(JSON.stringify({ error: 'Already enabled' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    const ok = await verifyTOTP(user.two_factor_secret, code)
    if (!ok) return addCors(new Response(JSON.stringify({ error: 'Invalid code' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    await env.DB.prepare('UPDATE users SET two_factor_enabled = 1 WHERE id = ?').bind(userId).run()
    return addCors(new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  }
})

// verify 2FA after login (exchange tempToken + code for full token)
router.post('/api/auth/2fa/verify', async (request, env) => {
  try {
    await ensureMigration(env)
    const { tempToken, code } = await request.json()
    if (!tempToken || !code) return addCors(new Response(JSON.stringify({ error: 'tempToken and code required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    const decoded = await decodeToken(tempToken, env)
    if (!decoded || decoded.twofa !== 'pending') return addCors(new Response(JSON.stringify({ error: 'Invalid token' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    const user = await env.DB.prepare('SELECT id, email, two_factor_secret, two_factor_enabled FROM users WHERE id = ?').bind(decoded.userId).first()
    if (!user || !user.two_factor_enabled || !user.two_factor_secret) return addCors(new Response(JSON.stringify({ error: '2FA not enabled' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    const ok = await verifyTOTP(user.two_factor_secret, code)
    if (!ok) return addCors(new Response(JSON.stringify({ error: 'Invalid code' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    const fullToken = await generateToken(user.id, env)
    return addCors(new Response(JSON.stringify({ user: { id: user.id, email: user.email }, token: fullToken }), { status: 200, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  }
})

// disable 2FA (requires current code)
router.post('/api/auth/2fa/disable', async (request, env) => {
  try {
    await ensureMigration(env)
    const userId = await getUserFromRequest(request, env)
    if (!userId) return addCors(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    const { code } = await request.json()
    if (!code) return addCors(new Response(JSON.stringify({ error: 'code required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    const user = await env.DB.prepare('SELECT two_factor_secret, two_factor_enabled FROM users WHERE id = ?').bind(userId).first()
    if (!user.two_factor_enabled || !user.two_factor_secret) return addCors(new Response(JSON.stringify({ error: 'Not enabled' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    const ok = await verifyTOTP(user.two_factor_secret, code)
    if (!ok) return addCors(new Response(JSON.stringify({ error: 'Invalid code' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    await env.DB.prepare('UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL WHERE id = ?').bind(userId).run()
    return addCors(new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  }
})

// ============ Password Routes (Protected) ============

// Get all passwords for user
router.get('/api/passwords', async (request, env) => {
  try {
    const userId = await getUserFromRequest(request, env)
    if (!userId) {
      return addCors(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }

    const stmt = env.DB.prepare('SELECT id, website, username, tags, password, created_at FROM passwords WHERE user_id = ? ORDER BY created_at DESC')
    const results = await stmt.bind(userId).all()

    // Decrypt passwords (in frontend)
    const decrypted = results.results.map(p => ({
      ...p,
      password: decryptPassword(p.password, `user_${userId}`)
    }))

    return addCors(new Response(JSON.stringify(decrypted), { headers: { 'Content-Type': 'application/json' } }), request, null, env)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  }
})

// Create password
router.post('/api/passwords', async (request, env) => {
  try {
    const userId = await getUserFromRequest(request, env)
    if (!userId) {
      return addCors(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }

    const { website, username = '', tags = [], password } = await request.json()
    if (!website || !password) {
      return addCors(new Response(JSON.stringify({ error: 'website and password required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }
    // Sanitize inputs (防止XSS和注入，保留正常字符)
    const sanitizedWebsite = String(website).trim().slice(0, 500)
    const sanitizedUsername = String(username).trim().slice(0, 200)

    // Encrypt password
    const encryptedPassword = encryptPassword(password, `user_${userId}`)

    const tagsStr = Array.isArray(tags) ? tags.join(',') : ''
    const stmt = env.DB.prepare('INSERT INTO passwords (user_id, website, username, tags, password) VALUES (?, ?, ?, ?, ?)')
    const insertResult = await stmt.bind(userId, sanitizedWebsite, sanitizedUsername, tagsStr, encryptedPassword).run()
    const result = await env.DB.prepare('SELECT id, website, username, tags, created_at FROM passwords WHERE id = ?').bind(insertResult.meta.last_row_id).first()

    return addCors(new Response(JSON.stringify({ ...result, password }), { status: 201, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  }
})

// Delete password
router.delete('/api/passwords/:id', async (request, env) => {
  try {
    const userId = await getUserFromRequest(request, env)
    if (!userId) {
      return addCors(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }

    const { id } = request.params
    if (!id) {
      return addCors(new Response(JSON.stringify({ error: 'id required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }

    // Verify ownership
    const exists = await env.DB.prepare('SELECT id FROM passwords WHERE id = ? AND user_id = ?').bind(id, userId).first()
    if (!exists) {
      return addCors(new Response(JSON.stringify({ error: 'Password not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }

    const stmt = env.DB.prepare('DELETE FROM passwords WHERE id = ? AND user_id = ?')
    await stmt.bind(id, userId).run()

    return addCors(new Response(JSON.stringify({ success: true, id }), { headers: { 'Content-Type': 'application/json' } }), request, null, env)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  }
})

// Update password
router.put('/api/passwords/:id', async (request, env) => {
  try {
    const userId = await getUserFromRequest(request, env)
    if (!userId) {
      return addCors(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }

    const { id } = request.params
    const { website, username = '', tags = [], password } = await request.json()
    
    if (!id || !website || !password) {
      return addCors(new Response(JSON.stringify({ error: 'id, website and password required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }
    // Sanitize inputs
    const sanitizedWebsite = String(website).trim().slice(0, 500)
    const sanitizedUsername = String(username).trim().slice(0, 200)

    // Verify ownership
    const exists = await env.DB.prepare('SELECT id FROM passwords WHERE id = ? AND user_id = ?').bind(id, userId).first()
    if (!exists) {
      return addCors(new Response(JSON.stringify({ error: 'Password not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    }

    // Encrypt password
    const encryptedPassword = encryptPassword(password, `user_${userId}`)

    const tagsStr = Array.isArray(tags) ? tags.join(',') : ''
    const stmt = env.DB.prepare('UPDATE passwords SET website = ?, username = ?, tags = ?, password = ? WHERE id = ? AND user_id = ?')
    await stmt.bind(sanitizedWebsite, sanitizedUsername, tagsStr, encryptedPassword, id, userId).run()

    return addCors(new Response(JSON.stringify({ success: true, id, website: sanitizedWebsite, username: sanitizedUsername, tags }), { headers: { 'Content-Type': 'application/json' } }), request, null, env)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  }
})

// Generate recovery codes (requires 2FA enabled)
router.post('/api/auth/2fa/recovery/generate', async (request, env) => {
  try {
    await ensureMigration(env)
    const userId = await getUserFromRequest(request, env)
    if (!userId) return addCors(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    const user = await env.DB.prepare('SELECT two_factor_enabled FROM users WHERE id = ?').bind(userId).first()
    if (!user || !user.two_factor_enabled) return addCors(new Response(JSON.stringify({ error: '2FA not enabled' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    // Invalidate old unused codes
    await env.DB.prepare('DELETE FROM recovery_codes WHERE user_id = ? AND used = 0').bind(userId).run()
    const codes = []
    for (let i = 0; i < 10; i++) {
      const raw = [...crypto.getRandomValues(new Uint8Array(6))].map(b => (b % 36).toString(36)).join('').toUpperCase()
      const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw))
      const hash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2,'0')).join('')
      await env.DB.prepare('INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)').bind(userId, hash).run()
      codes.push(raw)
    }
    return addCors(new Response(JSON.stringify({ codes }), { status: 201, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  }
})

// Verify recovery code (tempToken + recoveryCode)
router.post('/api/auth/2fa/recovery/verify', async (request, env) => {
  try {
    await ensureMigration(env)
    const { tempToken, recoveryCode } = await request.json()
    if (!tempToken || !recoveryCode) return addCors(new Response(JSON.stringify({ error: 'tempToken and recoveryCode required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    const decoded = decodeToken(tempToken)
    if (!decoded || decoded.twofa !== 'pending') return addCors(new Response(JSON.stringify({ error: 'Invalid token' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    const user = await env.DB.prepare('SELECT id, email, two_factor_enabled FROM users WHERE id = ?').bind(decoded.userId).first()
    if (!user || !user.two_factor_enabled) return addCors(new Response(JSON.stringify({ error: '2FA not enabled' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(recoveryCode.toUpperCase()))
    const hash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2,'0')).join('')
    const rec = await env.DB.prepare('SELECT id, used FROM recovery_codes WHERE user_id = ? AND code_hash = ?').bind(user.id, hash).first()
    if (!rec || rec.used) return addCors(new Response(JSON.stringify({ error: 'Invalid code' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request, null, env)
    await env.DB.prepare('UPDATE recovery_codes SET used = 1 WHERE id = ?').bind(rec.id).run()
    const fullToken = await generateToken(user.id, env)
    return addCors(new Response(JSON.stringify({ user: { id: user.id, email: user.email }, token: fullToken }), { status: 200, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request, null, env)
  }
})

// Mount our modular routes
router.mount('/api/auth', authRoutes)
router.mount('/api/passwords', passwordRoutes)

// Fallback
router.all('*', (request, env) => addCors(new Response('Not Found', { status: 404 }), request, null, env))

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    // Force HTTPS for custom domain
    if (url.protocol === 'http:' && env?.CUSTOM_DOMAIN && url.hostname === env.CUSTOM_DOMAIN) {
      const httpsUrl = new URL(request.url)
      httpsUrl.protocol = 'https:'
      return new Response(null, { status: 301, headers: { Location: httpsUrl.toString() } })
    }
    
    // Rate limit & API 优先
    let rateInfo = null
    // Use our modular router for API requests
    if (url.pathname.startsWith('/api/')) {
      rateInfo = checkRateLimit(request)
      if (!rateInfo.allowed) {
        return applySecurityHeaders(new Response(JSON.stringify({ error: 'Rate limit exceeded' }), { status: 429, headers: { 'Content-Type': 'application/json' } }), request, rateInfo, env)
      }
      await ensureMigration(env)
      const apiResp = await router.handle(request, env, ctx)
      return applySecurityHeaders(apiResp, request, rateInfo, env)
    }
    
    // For root path, serve HTML directly from ASSETS
    if (url.pathname === '/' || url.pathname === '/index.html') {
      if (env.ASSETS) {
        try {
          const assetReq = new Request(new URL('/index.html', url.origin), request);
          const assetResp = await env.ASSETS.fetch(assetReq);
          if (assetResp.status === 200) {
            // 读取HTML文本并移除 Cloudflare Insights 注入的脚本标签
            const html = await assetResp.text();
            const sanitized = html.replace(/<script[^>]*src="https:\/\/static\.cloudflareinsights\.com\/beacon\.min\.js[^"]*"[\s\S]*?<\/script>/gi, "");

            const headers = new Headers();
            headers.set('Content-Type', 'text/html; charset=utf-8');
            headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0, s-maxage=0');
            headers.set('Pragma', 'no-cache');
            headers.set('Expires', '0');
            headers.set('Clear-Site-Data', '"cache", "storage"');
            // 使用时间戳作为ETag强制浏览器重新验证
            headers.set('ETag', `"v5-${Date.now()}"`);
            headers.set('Last-Modified', new Date().toUTCString());
            return applySecurityHeaders(new Response(sanitized, { status: 200, headers }), request, null, env);
          }
        } catch (e) {
          console.error('ASSETS error:', e);
        }
      }
      return applySecurityHeaders(new Response('Service temporarily unavailable', { status: 503 }), request, null, env);
    }
    
    // Handle favicon.ico - return empty 204 to avoid 500 error
    if (url.pathname === '/favicon.ico') {
      return new Response(null, { status: 204 });
    }
    
    // Try to serve other static assets
    if (env.ASSETS) {
      try {
        const assetResponse = await env.ASSETS.fetch(request);
        if (assetResponse.status !== 404) {
          const headers = new Headers(assetResponse.headers);
          headers.set('Cache-Control', 'no-cache, no-store, must-revalidate');
          const resp = new Response(assetResponse.body, { status: assetResponse.status, statusText: assetResponse.statusText, headers })
          return applySecurityHeaders(resp, request, null, env)
        }
      } catch (e) {
        // Asset not found, continue
      }
    }
    
    // Fallback to router for other requests
    const r = await router.handle(request, env, ctx)
    return applySecurityHeaders(r, request, null, env)
  }
}
