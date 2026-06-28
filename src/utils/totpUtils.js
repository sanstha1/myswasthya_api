const speakeasy = require('speakeasy');

function generateTOTPSecret() {
  return speakeasy.generateSecret({
    name: 'MySwasthya',
    issuer: 'MySwasthya'
  });
}

function verifyTOTPCode(secret, code) {
  return speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    window: 1
  });
}

function generateTOTPQRURL(secret, email) {
  return speakeasy.otpauthURL({
    secret: secret,
    label: email,
    issuer: 'MySwasthya'
  });
}

module.exports = { generateTOTPSecret, verifyTOTPCode, generateTOTPQRURL };