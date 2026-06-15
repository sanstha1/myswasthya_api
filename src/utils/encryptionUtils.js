const crypto = require('crypto');

function encrypt(text) {
  const key = process.env.ENCRYPTION_KEY;
  const cipher = crypto.createCipher('aes-256-gcm', key);
  const encrypted = cipher.update(text, 'utf8', 'base64');
  const authTag = cipher.getAuthTag();
  return encrypted + ':' + authTag.toString('base64');
}

function decrypt(encryptedText) {
  const [encrypted, authTag] = encryptedText.split(':');
  const key = process.env.ENCRYPTION_KEY;
  const decipher = crypto.createDecipher('aes-256-gcm', key);
  decipher.setAuthTag(Buffer.from(authTag, 'base64'));
  return decipher.update(encrypted, 'base64', 'utf8') + decipher.final('utf8');
}

function generateHMACSignature(data) {
  const secret = process.env.JWT_SECRET;
  return crypto
    .createHmac('sha256', secret)
    .update(data)
    .digest('hex');
}

function verifyHMACSignature(data, signature) {
  const expectedSignature = generateHMACSignature(data);
  return signature === expectedSignature;
}

module.exports = { encrypt, decrypt, generateHMACSignature, verifyHMACSignature };