const express = require('express');
const rateLimit = require('express-rate-limit');
const passport = require('passport');
const router = express.Router();

const {
  register,
  login,
  logout,
  changePassword,
  enableMFA,
  verifyMFASetup,
  disableMFA,
  getSessions,
  logoutOtherSessions,
} = require('../controllers/authController');
const { googleCallback, googleFailure } = require('../controllers/oauthController');
const { authenticate } = require('../middleware/authMiddleware');

// SECURITY: Strict rate limiting on authentication endpoints
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many login attempts. Please try again after 15 minutes.',
  },
  statusCode: 429,
});

const registerRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: {
    success: false,
    message: 'Too many registration attempts. Please try again after 1 hour.',
  },
  statusCode: 429,
});

// Public routes
router.post('/register', registerRateLimit, register);
router.post('/login', authRateLimit, login);

// SECURITY: Google OAuth 2.0 routes
// Initiates OAuth flow - redirects to Google consent screen
router.get(
  '/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    session: false,
  })
);

// SECURITY: Google OAuth callback - receives authorization code from Google
router.get(
  '/google/callback',
  passport.authenticate('google', {
    session: false,
    failureRedirect: '/api/auth/google/failure',
  }),
  googleCallback
);

router.get('/google/failure', googleFailure);

// Protected routes
router.post('/logout', authenticate, logout);
router.post('/change-password', authenticate, changePassword);
router.post('/enable-mfa', authenticate, enableMFA);
router.post('/verify-mfa-setup', authenticate, verifyMFASetup);
router.post('/disable-mfa', authenticate, disableMFA);
router.get('/sessions', authenticate, getSessions);
router.delete('/sessions/others', authenticate, logoutOtherSessions);

module.exports = router;