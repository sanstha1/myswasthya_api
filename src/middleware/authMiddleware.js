const jwt = require('jsonwebtoken');
const User = require('../models/User');

/**
 * JWT Authentication Middleware
 * SECURITY: Verifies JWT token from httpOnly cookie on every protected request
 * httpOnly cookie prevents XSS attacks from stealing the token via JavaScript
 */
async function authenticate(req, res, next) {
  try {
    // Read JWT from httpOnly cookie (not localStorage - XSS resistant)
    const token = req.cookies?.authToken;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
    }

    let decoded;
    try {
      // Verify JWT signature using secret from environment variable
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (jwtError) {
      if (jwtError.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          message: 'Session expired, please login again',
        });
      }
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token',
      });
    }

    // Fetch user from database to validate account is still active
    const user = await User.findById(decoded.userId).select('+activeSessions');
    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Account not found or disabled',
      });
    }

    // Verify sessionId exists in user's active sessions (prevents token reuse after logout)
    const sessionExists = user.activeSessions.some(
      (s) => s.sessionId === decoded.sessionId
    );
    if (!sessionExists) {
      return res.status(401).json({
        success: false,
        message: 'Session invalidated, please login again',
      });
    }

    // Verify user agent matches session (basic session binding)
    const session = user.activeSessions.find((s) => s.sessionId === decoded.sessionId);
    if (session && session.userAgent !== req.headers['user-agent']) {
      return res.status(401).json({
        success: false,
        message: 'Session fingerprint mismatch',
      });
    }

    // Attach user info to request for downstream middleware and controllers
    req.user = {
      userId: decoded.userId,
      email: decoded.email,
      sessionId: decoded.sessionId,
    };

    next();
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Authentication error',
    });
  }
}

module.exports = { authenticate };