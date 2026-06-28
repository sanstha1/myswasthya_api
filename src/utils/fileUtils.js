const crypto = require('crypto');

function generateFileHash(buffer) {
  return crypto
    .createHash('sha256')
    .update(buffer)
    .digest('hex');
}

function validateFileType(mimeType) {
  const allowedTypes = ['application/pdf', 'image/png', 'image/jpeg'];
  return allowedTypes.includes(mimeType);
}

function validateFileSize(size, maxSize = 10 * 1024 * 1024) {
  return size <= maxSize;
}

module.exports = { generateFileHash, validateFileType, validateFileSize };