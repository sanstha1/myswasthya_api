const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

// JWT expiry set to 30days - balances security with usability
const JWT_EXPIRY = '30d';

/**
 * Generate JWT token with session tracking
 */
function generateJWTToken(userId, email) {
  const sessionId = uuidv4();

  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET environment variable not set');
  }

  const token = jwt.sign(
    {
      userId: userId.toString(),
      email,
      sessionId,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: JWT_EXPIRY,
      issuer: 'myswasthya',
      audience: 'myswasthya-users',
    }
  );

  return { token, sessionId };
}


function getSessionCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 30 * 24 * 60 * 60 * 1000,
    path: '/',
  };
}

/**
 * Cookie options for clearing the session cookie on logout
 */
function getClearCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
  };
}

module.exports = {
  generateJWTToken,
  getSessionCookieOptions,
  getClearCookieOptions,
};