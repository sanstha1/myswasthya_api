const jwt = require('jsonwebtoken');
const crypto = require('crypto');

function generateJWTToken(user) {
  return jwt.sign(
    { 
      userId: user.id, 
      email: user.email,
      sessionId: crypto.randomBytes(16).toString('hex')
    },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
}

function verifyJWTToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    return null;
  }
}

const sessionCookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 24 * 60 * 60 * 1000,
  path: '/'
};

module.exports = { generateJWTToken, verifyJWTToken, sessionCookieOptions };