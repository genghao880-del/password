/**
 * Enhanced encryption utilities using AES-GCM for better security
 */

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