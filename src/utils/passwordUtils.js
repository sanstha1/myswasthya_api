const argon2 = require('argon2');
const zxcvbn = require('zxcvbn-ts');

async function hashPassword(password) {
  return await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4
  });
}

async function verifyPassword(password, hash) {
  return await argon2.verify(hash, password);
}

function checkPasswordStrength(password) {
  const issues = [];
  
  if (password.length < 12) {
    issues.push('Password must be at least 12 characters');
  }
  if (password.length > 128) {
    issues.push('Password must be at most 128 characters');
  }
  if (!/[A-Z]/.test(password)) {
    issues.push('Password must contain uppercase letter');
  }
  if (!/[a-z]/.test(password)) {
    issues.push('Password must contain lowercase letter');
  }
  if (!/[0-9]/.test(password)) {
    issues.push('Password must contain number');
  }
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    issues.push('Password must contain special character');
  }
  
  const zxcvbnResult = zxcvbn.Execute(password);
  
  return {
    valid: issues.length === 0,
    issues,
    score: zxcvbnResult.score
  };
}

module.exports = { hashPassword, verifyPassword, checkPasswordStrength };