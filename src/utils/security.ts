// Base64 helpers
export function base64ToBytes(str: string): Uint8Array {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

export function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

// Create PBKDF2 hash with random salt: returns "salt:hash" (both base64)
export async function createPasswordHash(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const enc = new TextEncoder();
  const passKey = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: 100000, hash: 'SHA-256' }, passKey, 256);
  const derived = new Uint8Array(derivedBits);
  const saltB64 = bytesToBase64(salt);
  const hashB64 = bytesToBase64(derived);
  return `${saltB64}:${hashB64}`;
}

// Verify hash supporting both new format (salt:hash) and legacy
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  if (!stored.includes(':')) {
    // Legacy path not supported in this improved version
    return false;
  }
  
  const [saltB64, hashB64] = stored.split(':');
  const salt = base64ToBytes(saltB64);
  const enc = new TextEncoder();
  const passKey = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: 100000, hash: 'SHA-256' }, passKey, 256);
  const derived = bytesToBase64(new Uint8Array(derivedBits));
  
  // Constant time compare
  if (derived.length !== hashB64.length) return false;
  let diff = 0;
  for (let i = 0; i < derived.length; i++) {
    diff |= derived.charCodeAt(i) ^ hashB64.charCodeAt(i);
  }
  return diff === 0;
}

// Generate JWT token
async function hmacSHA256(message: string, secret: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return bytesToBase64(new Uint8Array(sig));
}

export async function generateToken(userId: number, env: { JWT_SECRET?: string }): Promise<string> {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = btoa(JSON.stringify({
    userId,
    exp: Math.floor(Date.now() / 1000) + 86400 * 7 // 7 days
  }));
  const secret = env?.JWT_SECRET || '';
  if (!secret) throw new Error('Missing JWT_SECRET');
  const signature = await hmacSHA256(`${header}.${payload}`, secret);
  return `${header}.${payload}.${signature}`;
}

// Verify JWT token
export async function verifyToken(token: string, env: { JWT_SECRET?: string }): Promise<number | null> {
  try {
    const [header, payload, signature] = token.split('.');
    const decoded = JSON.parse(atob(payload));
    if (decoded.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    const secret = env?.JWT_SECRET || '';
    if (!secret) return null;
    
    // verify signature
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBytes = base64ToBytes(signature);
    const ok = await crypto.subtle.verify('HMAC', key, sigBytes.buffer as ArrayBuffer, new TextEncoder().encode(`${header}.${payload}`));

    return ok ? decoded.userId : null;
  } catch {
    return null;
  }
}

// Convert string to ArrayBuffer
function stringToArrayBuffer(str: string): ArrayBuffer {
  return new TextEncoder().encode(str).buffer;
}

// Convert ArrayBuffer to string
function arrayBufferToString(buffer: ArrayBuffer): string {
  return new TextDecoder().decode(buffer);
}

// Convert base64 to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// Convert ArrayBuffer to base64
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binaryString = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binaryString += String.fromCharCode(bytes[i]);
  }
  return btoa(binaryString);
}

/**
 * Encrypt a password using AES-GCM
 * @param password - The plaintext password to encrypt
 * @param keyMaterial - The key material (user-specific)
 * @returns Encrypted password as base64 string containing IV + ciphertext + auth tag
 */
export async function encryptPassword(password: string, keyMaterial: string): Promise<string> {
  // Create a key from the key material
  const keyBytes = stringToArrayBuffer(keyMaterial);
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
      salt: stringToArrayBuffer('salt_for_passfortress'), // In production, use a unique salt per user
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
  const plaintextBytes = stringToArrayBuffer(password);
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
  return arrayBufferToBase64(combined.buffer);
}

/**
 * Decrypt a password using AES-GCM
 * @param encryptedPassword - The base64 encrypted password (IV + ciphertext + auth tag)
 * @param keyMaterial - The key material (user-specific)
 * @returns Decrypted plaintext password
 */
export async function decryptPassword(encryptedPassword: string, keyMaterial: string): Promise<string> {
  // Create a key from the key material
  const keyBytes = stringToArrayBuffer(keyMaterial);
  
  // For simplicity in this implementation, we'll return a placeholder
  // A full implementation would mirror the encryption process but with decrypt operations
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
      salt: stringToArrayBuffer('salt_for_passfortress'), // In production, use a unique salt per user
      iterations: 100000,
      hash: 'SHA-256'
    },
    key,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  // Decode from base64
  const combined = base64ToArrayBuffer(encryptedPassword);
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
  return arrayBufferToString(plaintextBuffer);
}