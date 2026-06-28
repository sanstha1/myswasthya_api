const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const crypto = require('crypto');

/**
 * Generate a new TOTP secret for MFA setup
 */
function generateTOTPSecret(userEmail) {
  const secret = speakeasy.generateSecret({
    name: `MySwasthya:${userEmail}`,
    issuer: 'MySwasthya',
    length: 32,
  });

  return {
    base32: secret.base32,
    otpauthUrl: secret.otpauth_url,
  };
}

/**
 * Generate QR code image URL from TOTP otpauth URL
 * SECURITY: QR code generated server-side, contains only otpauth URL
 */
async function generateTOTPQRCode(otpauthUrl) {
  try {
    const qrCodeDataURL = await QRCode.toDataURL(otpauthUrl, {
      errorCorrectionLevel: 'M',
      type: 'image/png',
      width: 200,
      margin: 2,
    });
    return qrCodeDataURL;
  } catch (err) {
    throw new Error('QR code generation failed');
  }
}


function verifyTOTPCode(secret, token) {
  if (!secret || !token) return false;

  // SECURITY: Sanitize token - must be exactly 6 digits
  const sanitizedToken = String(token).replace(/\D/g, '');
  if (sanitizedToken.length !== 6) return false;

  return speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: sanitizedToken,
    window: 1,
  });
}

/**
 * Generate 10 single-use backup codes for MFA recovery
 * SECURITY: Cryptographically random, formatted as XXXX-XXXX for readability
 */
function generateBackupCodes() {
  const codes = [];
  for (let i = 0; i < 10; i++) {
    const rawCode = crypto.randomBytes(4).toString('hex').toUpperCase();
    codes.push(`${rawCode.slice(0, 4)}-${rawCode.slice(4, 8)}`);
  }
  return codes;
}

function verifyBackupCode(inputCode, storedCodes) {
  const normalized = inputCode.toUpperCase().replace(/[^A-F0-9-]/g, '');
  const index = storedCodes.indexOf(normalized);
  if (index !== -1) {
    const remaining = [...storedCodes];
    remaining.splice(index, 1);
    return { valid: true, remaining };
  }
  return { valid: false, remaining: storedCodes };
}

module.exports = {
  generateTOTPSecret,
  generateTOTPQRCode,
  verifyTOTPCode,
  generateBackupCodes,
  verifyBackupCode,
};