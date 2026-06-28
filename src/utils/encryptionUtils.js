const crypto = require('crypto');

// SECURITY: AES-256-GCM - NIST-approved authenticated encryption
// GCM mode provides both confidentiality AND integrity (prevents tampering)
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;      
const TAG_LENGTH = 16;      

function getEncryptionKey() {
  const key = process.env.ENCRYPTION_KEY;
  if (!key) throw new Error('ENCRYPTION_KEY environment variable not set');

  const keyBuffer = Buffer.from(key, 'utf8');
  if (keyBuffer.length < 32) {
    throw new Error('ENCRYPTION_KEY must be at least 32 bytes');
  }
  // SECURITY: Use exactly 32 bytes (256 bits)
  return keyBuffer.slice(0, 32);
}

//Encrypt data using AES-256-GCM
function encrypt(plaintext) {
  try {
    const key = getEncryptionKey();
    // Cryptographically random IV, unique per encryption
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // GCM auth tag verifies ciphertext integrity on decryption
    const authTag = cipher.getAuthTag();

    return `${iv.toString('hex')}:${encrypted}:${authTag.toString('hex')}`;
  } catch (err) {
    throw new Error('Encryption failed');
  }
}

/**
 * Decrypt AES-256-GCM encrypted data
 */
function decrypt(encryptedData) {
  try {
    const key = getEncryptionKey();
    const parts = encryptedData.split(':');
    if (parts.length !== 3) throw new Error('Invalid encrypted data format');

    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const authTag = Buffer.from(parts[2], 'hex');

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    // Set auth tag for integrity verification before decryption
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } catch (err) {
    throw new Error('Decryption failed - data may be tampered');
  }
}

/**
 * Generate HMAC-SHA256 signature for data integrity
 */
function generateHMACSignature(data) {
  const secret = process.env.HMAC_SECRET;
  if (!secret) throw new Error('HMAC_SECRET environment variable not set');

  const dataString = typeof data === 'object' ? JSON.stringify(data) : String(data);
  return crypto.createHmac('sha256', secret).update(dataString).digest('hex');
}

/**
 * Verify HMAC-SHA256 signature
 */
function verifyHMACSignature(data, signature) {
  try {
    const expectedSignature = generateHMACSignature(data);
    const expectedBuffer = Buffer.from(expectedSignature, 'hex');
    const actualBuffer = Buffer.from(signature, 'hex');

    if (expectedBuffer.length !== actualBuffer.length) return false;

    // Timing-safe comparison prevents timing oracle attacks
    return crypto.timingSafeEqual(expectedBuffer, actualBuffer);
  } catch {
    return false;
  }
}

module.exports = {
  encrypt,
  decrypt,
  generateHMACSignature,
  verifyHMACSignature,
};