const argon2 = require('argon2');
const zxcvbn = require('zxcvbn');

// Argon2id parameters - OWASP 2024 recommended (memory-hard, GPU-resistant)
const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 65536,  
  timeCost: 3,        
  parallelism: 4,     
};

// Minimum 12 chars, maximum 128 chars per OWASP guidelines
const PASSWORD_MIN_LENGTH = 12;
const PASSWORD_MAX_LENGTH = 128;

// Regex enforces complexity: uppercase + lowercase + digit + special char
const PASSWORD_COMPLEXITY_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~])/;


async function hashPassword(plainPassword) {
  try {
    const hash = await argon2.hash(plainPassword, ARGON2_OPTIONS);
    return hash;
  } catch (err) {
    throw new Error('Password hashing failed');
  }
}

async function verifyPassword(hash, plainPassword) {
  try {
    const isValid = await argon2.verify(hash, plainPassword);
    return isValid;
  } catch (err) {
    return false;
  }
}

function validatePasswordComplexity(password) {
  const errors = [];

  if (!password || typeof password !== 'string') {
    return { valid: false, errors: ['Password is required'] };
  }

  if (password.length < PASSWORD_MIN_LENGTH) {
    errors.push(`Password must be at least ${PASSWORD_MIN_LENGTH} characters`);
  }

  if (password.length > PASSWORD_MAX_LENGTH) {
    errors.push(`Password must not exceed ${PASSWORD_MAX_LENGTH} characters`);
  }

  if (!PASSWORD_COMPLEXITY_REGEX.test(password)) {
    if (!/[a-z]/.test(password)) errors.push('Password must contain at least one lowercase letter');
    if (!/[A-Z]/.test(password)) errors.push('Password must contain at least one uppercase letter');
    if (!/\d/.test(password)) errors.push('Password must contain at least one number');
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Check password strength using zxcvbn
 * SECURITY: zxcvbn detects common patterns, dictionary words, and weak passwords
 * Score: 0 (very weak) to 4 (very strong)
 */
function checkPasswordStrength(password) {
  if (!password) {
    return { score: 0, feedback: { warning: 'Password is required', suggestions: [] } };
  }

  const result = zxcvbn(password);
  return {
    score: result.score,
    crackTime: result.crack_times_display.offline_slow_hashing_1e4_per_second,
    feedback: {
      warning: result.feedback.warning || '',
      suggestions: result.feedback.suggestions || [],
    },
  };
}

async function isPasswordInHistory(newPassword, passwordHistory) {
  if (!passwordHistory || passwordHistory.length === 0) {
    return false;
  }

  for (const oldHash of passwordHistory) {
    try {
      const matches = await argon2.verify(oldHash, newPassword);
      if (matches) return true;
    } catch {
      continue;
    }
  }
  return false;
}

module.exports = {
  hashPassword,
  verifyPassword,
  validatePasswordComplexity,
  checkPasswordStrength,
  isPasswordInHistory,
  PASSWORD_MIN_LENGTH,
  PASSWORD_MAX_LENGTH,
};