const crypto = require('crypto');
const fs = require('fs');

// Whitelist of allowed MIME types - only PDF and images
const ALLOWED_MIME_TYPES = ['application/pdf', 'image/png', 'image/jpeg'];
const ALLOWED_EXTENSIONS = ['.pdf', '.png', '.jpg', '.jpeg'];

// Maximum file size 10MB (prevents storage exhaustion DoS)
const MAX_FILE_SIZE = 10 * 1024 * 1024;

function generateFileHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);

    stream.on('data', (data) => hash.update(data));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', (err) => reject(new Error(`File hashing failed: ${err.message}`)));
  });
}

function validateFileType(mimetype, originalname) {
  if (!ALLOWED_MIME_TYPES.includes(mimetype)) {
    return {
      valid: false,
      error: `File type not allowed. Only PDF, PNG, and JPEG files are accepted. Got: ${mimetype}`,
    };
  }

  const ext = originalname.toLowerCase().match(/\.[^.]+$/)?.[0];
  if (!ext || !ALLOWED_EXTENSIONS.includes(ext)) {
    return {
      valid: false,
      error: `File extension not allowed. Only .pdf, .png, .jpg, .jpeg files are accepted`,
    };
  }

  return { valid: true };
}

/**
 * Validate file size
 * 10MB limit prevents storage exhaustion and DoS attacks
 */
function validateFileSize(size) {
  if (size > MAX_FILE_SIZE) {
    return {
      valid: false,
      error: `File size ${(size / 1024 / 1024).toFixed(2)}MB exceeds maximum allowed size of 10MB`,
    };
  }
  return { valid: true };
}


async function verifyFileIntegrity(filePath, expectedHash) {
  try {
    const actualHash = await generateFileHash(filePath);
    // SECURITY: Timing-safe comparison
    const expectedBuffer = Buffer.from(expectedHash, 'hex');
    const actualBuffer = Buffer.from(actualHash, 'hex');
    if (expectedBuffer.length !== actualBuffer.length) return false;
    return crypto.timingSafeEqual(expectedBuffer, actualBuffer);
  } catch {
    return false;
  }
}

/**
 * Safely delete a file from disk
 */
function deleteFile(filePath) {
  return new Promise((resolve) => {
    fs.unlink(filePath, (err) => {
      if (err) {
        console.error(`Failed to delete file ${filePath}:`, err.message);
      }
      resolve();
    });
  });
}

module.exports = {
  generateFileHash,
  validateFileType,
  validateFileSize,
  verifyFileIntegrity,
  deleteFile,
  ALLOWED_MIME_TYPES,
  MAX_FILE_SIZE,
};