const { generateJWTToken, getSessionCookieOptions } = require('../middleware/sessionMiddleware');
const { logAction } = require('../middleware/loggingMiddleware');
const User = require('../models/User');

/**
 * GET /api/auth/google/callback
 * SECURITY: Handles Google OAuth callback, issues JWT in httpOnly cookie
 * Same session security as password login - httpOnly, sameSite strict
 */
async function googleCallback(req, res) {
  try {
    const user = req.user;

    if (!user) {
      return res.redirect(
        `${process.env.FRONTEND_URL}/login?error=oauth_failed`
      );
    }

    // SECURITY: Generate JWT with session tracking - same as password login
    const { token, sessionId } = generateJWTToken(user._id, user.email);

    // SECURITY: Add session to active sessions list
    await User.findByIdAndUpdate(user._id, {
      lastLogin: new Date(),
      $push: {
        activeSessions: {
          sessionId,
          userAgent: req.headers['user-agent']?.slice(0, 500) || 'unknown',
          ipAddress: req.ip,
          createdAt: new Date(),
          lastActive: new Date(),
        },
      },
    });

    await logAction(user._id, 'login', req, {
      method: 'google_oauth',
      sessionId,
    });

    // SECURITY: JWT in httpOnly cookie - same security as password login
    res.cookie('authToken', token, getSessionCookieOptions());

   
    return res.redirect(`${process.env.FRONTEND_URL}/dashboard`);

  } catch (err) {
    console.error('[OAUTH] Google callback error:', err.message);
    return res.redirect(
      `${process.env.FRONTEND_URL}/login?error=oauth_error`
    );
  }
}

/**
 * GET /api/auth/google/failure
 * Called when Google OAuth fails
 */
function googleFailure(req, res) {
  return res.redirect(
    `${process.env.FRONTEND_URL}/login?error=oauth_cancelled`
  );
}

module.exports = { googleCallback, googleFailure };