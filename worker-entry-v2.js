import { Router } from 'itty-router'

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
  } catch (e) {
    // swallow errors to avoid breaking requests
  } finally {
    migrationChecked = true
  }
}

// ============ Helper Functions ============

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
async function generateToken(userId) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payload = btoa(JSON.stringify({
    userId,
    exp: Math.floor(Date.now() / 1000) + 86400 * 7 // 7 days
  }))
  const signature = btoa('demo-secret-key') // In production, use proper HMAC
  return `${header}.${payload}.${signature}`
}

// Temporary JWT for pending 2FA (short lifetime 5m)
async function generateTemp2FAToken(userId) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payload = btoa(JSON.stringify({ userId, twofa: 'pending', exp: Math.floor(Date.now() / 1000) + 300 }))
  const signature = btoa('demo-secret-key')
  return `${header}.${payload}.${signature}`
}

// Verify JWT token
function verifyToken(token) {
  try {
    const [header, payload, signature] = token.split('.')
    const decoded = JSON.parse(atob(payload))
    if (decoded.exp < Math.floor(Date.now() / 1000)) {
      return null
    }
    return decoded.userId
  } catch {
    return null
  }
}

function decodeToken(token) {
  try {
    const [header, payload, signature] = token.split('.')
    const decoded = JSON.parse(atob(payload))
    if (decoded.exp < Math.floor(Date.now() / 1000)) return null
    return decoded
  } catch { return null }
}

// Extract user from request
function getUserFromRequest(request) {
  const auth = request.headers.get('Authorization')
  if (!auth || !auth.startsWith('Bearer ')) return null
  const token = auth.slice(7)
  return verifyToken(token)
}

// Encryption (simple XOR for demo - use AES in production)
function encryptPassword(password, key) {
  const encoder = new TextEncoder()
  const data = encoder.encode(password)
  const keyData = encoder.encode(key.slice(0, 32))
  const encrypted = new Uint8Array(data.length)
  for (let i = 0; i < data.length; i++) {
    encrypted[i] = data[i] ^ keyData[i % keyData.length]
  }
  return bytesToBase64(encrypted)
}

function decryptPassword(encrypted, key) {
  const encrypted_bytes = base64ToBytes(encrypted)
  const keyData = new TextEncoder().encode(key.slice(0, 32))
  const decrypted = new Uint8Array(encrypted_bytes.length)
  for (let i = 0; i < encrypted_bytes.length; i++) {
    decrypted[i] = encrypted_bytes[i] ^ keyData[i % keyData.length]
  }
  return new TextDecoder().decode(decrypted)
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
// Allowed origins (可根据需要扩展)
const ALLOWED_ORIGINS = [
  'https://password.genghao880.workers.dev'
]

// OPTIONS 预检
router.options('*', (request) => {
  const origin = request.headers.get('Origin')
  const allowOrigin = origin && ALLOWED_ORIGINS.includes(origin) ? origin : 'https://password.genghao880.workers.dev'
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

// 安全响应头 + CORS + RateLimit 头
function applySecurityHeaders(response, request, rateInfo) {
  const origin = request.headers.get('Origin')
  const allowOrigin = origin && ALLOWED_ORIGINS.includes(origin) ? origin : 'https://password.genghao880.workers.dev'
  const h = response.headers
  h.set('Access-Control-Allow-Origin', allowOrigin)
  h.set('Vary', 'Origin')
  h.set('X-Content-Type-Options', 'nosniff')
  h.set('X-Frame-Options', 'DENY')
  h.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  h.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
  h.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
  h.set('Content-Security-Policy', "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; upgrade-insecure-requests")
  if (rateInfo) {
    h.set('X-RateLimit-Limit', rateInfo.limit.toString())
    h.set('X-RateLimit-Remaining', Math.max(rateInfo.limit - rateInfo.count, 0).toString())
    h.set('X-RateLimit-Reset', rateInfo.reset.toString())
  }
  return response
}

// 包装响应
function addCors(response, request, rateInfo) {
  return applySecurityHeaders(response, request, rateInfo)
}

// ============ Rate Limiting ============
const RATE_LIMIT = 30
const WINDOW_MS = 60_000
const rateBuckets = new Map() // key -> {count, reset}

function checkRateLimit(request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown'
  const now = Date.now()
  let bucket = rateBuckets.get(ip)
  if (!bucket || bucket.reset < now) {
    bucket = { count: 0, reset: now + WINDOW_MS }
  }
  bucket.count += 1
  rateBuckets.set(ip, bucket)
  return { allowed: bucket.count <= RATE_LIMIT, count: bucket.count, limit: RATE_LIMIT, reset: Math.floor(bucket.reset / 1000) }
}

// ============ Auth Routes ============

// Register
router.post('/api/auth/register', async (request, env) => {
  try {
    const { email, password } = await request.json()
    if (!email || !password) {
      return addCors(new Response(JSON.stringify({ error: 'email and password required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request)
    }

    // Basic server-side validation (avoid user enumeration / weak password acceptance)
    const emailRegex = /^[^@\s]+@[^@\s]+\.[^@\s]+$/
    if (!emailRegex.test(email)) {
      return addCors(new Response(JSON.stringify({ error: 'Invalid registration data' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request)
    }
    // Password policy: >=8 chars, include 3 of (lower, upper, number, symbol)
    const categories = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].reduce((acc, r) => acc + (r.test(password) ? 1 : 0), 0)
    if (password.length < 8 || categories < 3) {
      return addCors(new Response(JSON.stringify({ error: 'Invalid registration data' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request)
    }

    // Check if user exists
    const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first()
    if (existing) {
      return addCors(new Response(JSON.stringify({ error: 'Registration failed' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request)
    }

    // Hash password (PBKDF2)
    const passwordHash = await createPasswordHash(password)

    // Create user
    const stmt = env.DB.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?) RETURNING id, email')
    const result = await stmt.bind(email, passwordHash).first()

    const token = await generateToken(result.id)

    return addCors(new Response(JSON.stringify({ user: result, token }), { status: 201, headers: { 'Content-Type': 'application/json' } }), request)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request)
  }
})

// Login
router.post('/api/auth/login', async (request, env) => {
  try {
    await ensureMigration(env)
    const { email, password } = await request.json()
    if (!email || !password) {
      return addCors(new Response(JSON.stringify({ error: 'email and password required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request)
    }

    // Normalize email (defensive)
    const normalizedEmail = email.trim().toLowerCase()
    const emailRegex = /^[^@\s]+@[^@\s]+\.[^@\s]+$/
    if (!emailRegex.test(normalizedEmail)) {
      return addCors(new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request)
    }
    const user = await env.DB.prepare('SELECT id, password_hash, two_factor_enabled FROM users WHERE email = ?').bind(normalizedEmail).first()
    if (!user) {
      return addCors(new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request)
    }

    const isValid = await verifyPassword(password, user.password_hash)
    if (!isValid) {
      return addCors(new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request)
    }

    if (user.two_factor_enabled) {
      // Return temp token requiring 2FA
      const temp = await generateTemp2FAToken(user.id)
      return addCors(new Response(JSON.stringify({ require2FA: true, tempToken: temp }), { status: 200, headers: { 'Content-Type': 'application/json' } }), request)
    }
    const token = await generateToken(user.id)
    return addCors(new Response(JSON.stringify({ user: { id: user.id, email: normalizedEmail }, token }), { status: 200, headers: { 'Content-Type': 'application/json' } }), request)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request)
  }
})

// init 2FA: generate secret (not enabled until activation)
router.post('/api/auth/2fa/init', async (request, env) => {
  try {
    await ensureMigration(env)
    const userId = getUserFromRequest(request)
    if (!userId) return addCors(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request)
    const user = await env.DB.prepare('SELECT two_factor_enabled, two_factor_secret, email FROM users WHERE id = ?').bind(userId).first()
    if (user.two_factor_enabled) return addCors(new Response(JSON.stringify({ error: 'Already enabled' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request)
    const secret = generateBase32Secret(32)
    await env.DB.prepare('UPDATE users SET two_factor_secret = ? WHERE id = ?').bind(secret, userId).run()
    const otpauth = `otpauth://totp/PassFortress:${encodeURIComponent(user.email)}?secret=${secret}&issuer=PassFortress`
    return addCors(new Response(JSON.stringify({ secret, otpauth }), { status: 200, headers: { 'Content-Type': 'application/json' } }), request)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request)
  }
})

// activate 2FA (verify code then enable)
router.post('/api/auth/2fa/activate', async (request, env) => {
  try {
    await ensureMigration(env)
    const userId = getUserFromRequest(request)
    if (!userId) return addCors(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request)
    const { code } = await request.json()
    if (!code) return addCors(new Response(JSON.stringify({ error: 'code required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request)
    const user = await env.DB.prepare('SELECT two_factor_secret, two_factor_enabled FROM users WHERE id = ?').bind(userId).first()
    if (!user.two_factor_secret) return addCors(new Response(JSON.stringify({ error: 'init required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request)
    if (user.two_factor_enabled) return addCors(new Response(JSON.stringify({ error: 'Already enabled' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request)
    const ok = await verifyTOTP(user.two_factor_secret, code)
    if (!ok) return addCors(new Response(JSON.stringify({ error: 'Invalid code' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request)
    await env.DB.prepare('UPDATE users SET two_factor_enabled = 1 WHERE id = ?').bind(userId).run()
    return addCors(new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json' } }), request)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request)
  }
})

// verify 2FA after login (exchange tempToken + code for full token)
router.post('/api/auth/2fa/verify', async (request, env) => {
  try {
    await ensureMigration(env)
    const { tempToken, code } = await request.json()
    if (!tempToken || !code) return addCors(new Response(JSON.stringify({ error: 'tempToken and code required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request)
    const decoded = decodeToken(tempToken)
    if (!decoded || decoded.twofa !== 'pending') return addCors(new Response(JSON.stringify({ error: 'Invalid token' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request)
    const user = await env.DB.prepare('SELECT id, email, two_factor_secret, two_factor_enabled FROM users WHERE id = ?').bind(decoded.userId).first()
    if (!user || !user.two_factor_enabled || !user.two_factor_secret) return addCors(new Response(JSON.stringify({ error: '2FA not enabled' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request)
    const ok = await verifyTOTP(user.two_factor_secret, code)
    if (!ok) return addCors(new Response(JSON.stringify({ error: 'Invalid code' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request)
    const fullToken = await generateToken(user.id)
    return addCors(new Response(JSON.stringify({ user: { id: user.id, email: user.email }, token: fullToken }), { status: 200, headers: { 'Content-Type': 'application/json' } }), request)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request)
  }
})

// disable 2FA (requires current code)
router.post('/api/auth/2fa/disable', async (request, env) => {
  try {
    await ensureMigration(env)
    const userId = getUserFromRequest(request)
    if (!userId) return addCors(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request)
    const { code } = await request.json()
    if (!code) return addCors(new Response(JSON.stringify({ error: 'code required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request)
    const user = await env.DB.prepare('SELECT two_factor_secret, two_factor_enabled FROM users WHERE id = ?').bind(userId).first()
    if (!user.two_factor_enabled || !user.two_factor_secret) return addCors(new Response(JSON.stringify({ error: 'Not enabled' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request)
    const ok = await verifyTOTP(user.two_factor_secret, code)
    if (!ok) return addCors(new Response(JSON.stringify({ error: 'Invalid code' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request)
    await env.DB.prepare('UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL WHERE id = ?').bind(userId).run()
    return addCors(new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json' } }), request)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request)
  }
})

// ============ Password Routes (Protected) ============

// Get all passwords for user
router.get('/api/passwords', async (request, env) => {
  try {
    const userId = getUserFromRequest(request)
    if (!userId) {
      return addCors(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request)
    }

    const stmt = env.DB.prepare('SELECT id, website, password, created_at FROM passwords WHERE user_id = ? ORDER BY created_at DESC')
    const results = await stmt.bind(userId).all()

    // Decrypt passwords (in frontend)
    const decrypted = results.results.map(p => ({
      ...p,
      password: decryptPassword(p.password, `user_${userId}`)
    }))

    return addCors(new Response(JSON.stringify(decrypted), { headers: { 'Content-Type': 'application/json' } }), request)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request)
  }
})

// Create password
router.post('/api/passwords', async (request, env) => {
  try {
    const userId = getUserFromRequest(request)
    if (!userId) {
      return addCors(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request)
    }

    const { website, password } = await request.json()
    if (!website || !password) {
      return addCors(new Response(JSON.stringify({ error: 'website and password required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request)
    }

    // Encrypt password
    const encryptedPassword = encryptPassword(password, `user_${userId}`)

    const stmt = env.DB.prepare('INSERT INTO passwords (user_id, website, password) VALUES (?, ?, ?) RETURNING id, website, created_at')
    const result = await stmt.bind(userId, website, encryptedPassword).first()

    return addCors(new Response(JSON.stringify({ ...result, password }), { status: 201, headers: { 'Content-Type': 'application/json' } }), request)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request)
  }
})

// Delete password
router.delete('/api/passwords/:id', async (request, env) => {
  try {
    const userId = getUserFromRequest(request)
    if (!userId) {
      return addCors(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request)
    }

    const { id } = request.params
    if (!id) {
      return addCors(new Response(JSON.stringify({ error: 'id required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request)
    }

    // Verify ownership
    const exists = await env.DB.prepare('SELECT id FROM passwords WHERE id = ? AND user_id = ?').bind(id, userId).first()
    if (!exists) {
      return addCors(new Response(JSON.stringify({ error: 'Password not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } }), request)
    }

    const stmt = env.DB.prepare('DELETE FROM passwords WHERE id = ? AND user_id = ?')
    await stmt.bind(id, userId).run()

    return addCors(new Response(JSON.stringify({ success: true, id }), { headers: { 'Content-Type': 'application/json' } }), request)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request)
  }
})

// Update password
router.put('/api/passwords/:id', async (request, env) => {
  try {
    const userId = getUserFromRequest(request)
    if (!userId) {
      return addCors(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } }), request)
    }

    const { id } = request.params
    const { website, password } = await request.json()
    
    if (!id || !website || !password) {
      return addCors(new Response(JSON.stringify({ error: 'id, website and password required' }), { status: 400, headers: { 'Content-Type': 'application/json' } }), request)
    }

    // Verify ownership
    const exists = await env.DB.prepare('SELECT id FROM passwords WHERE id = ? AND user_id = ?').bind(id, userId).first()
    if (!exists) {
      return addCors(new Response(JSON.stringify({ error: 'Password not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } }), request)
    }

    // Encrypt password
    const encryptedPassword = encryptPassword(password, `user_${userId}`)

    const stmt = env.DB.prepare('UPDATE passwords SET website = ?, password = ? WHERE id = ? AND user_id = ?')
    await stmt.bind(website, encryptedPassword, id, userId).run()

    return addCors(new Response(JSON.stringify({ success: true, id, website }), { headers: { 'Content-Type': 'application/json' } }), request)
  } catch (e) {
    return addCors(new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } }), request)
  }
})

// Fallback
router.all('*', (request) => addCors(new Response('Not Found', { status: 404 }), request))

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // Rate limit & API 优先
    let rateInfo = null
    if (url.pathname.startsWith('/api/')) {
      rateInfo = checkRateLimit(request)
      if (!rateInfo.allowed) {
        return applySecurityHeaders(new Response(JSON.stringify({ error: 'Rate limit exceeded' }), { status: 429, headers: { 'Content-Type': 'application/json' } }), request, rateInfo)
      }
      const apiResp = await router.handle(request, env, ctx)
      return applySecurityHeaders(apiResp, request, rateInfo)
    }
    
    // Try to serve static assets
    if (env.ASSETS) {
      try {
        const assetResponse = await env.ASSETS.fetch(request);
        if (assetResponse.status !== 404) {
          // Add cache control headers to prevent caching
          const headers = new Headers(assetResponse.headers);
          headers.set('Cache-Control', 'no-cache, no-store, must-revalidate');
          headers.set('Pragma', 'no-cache');
          headers.set('Expires', '0');
          const resp = new Response(assetResponse.body, { status: assetResponse.status, statusText: assetResponse.statusText, headers })
          return applySecurityHeaders(resp, request)
        }
      } catch (e) {
        // Asset not found, continue
      }
    }
    
    // Fallback to router for other requests
    const r = await router.handle(request, env, ctx)
    return applySecurityHeaders(r, request)
  }
}
