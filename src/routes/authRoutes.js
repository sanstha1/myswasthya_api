const express = require('express');
const rateLimit = require('express-rate-limit');
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
const { authenticate } = require('../middleware/authMiddleware');

// Strict rate limiting on authentication endpoints
// 5 requests per 15 minutes per IP prevents brute-force attacks
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  message: {
    success: false,
    message: 'Too many login attempts. Please try again after 15 minutes.',
  },
  statusCode: 429,
});

//Slightly more lenient limit for registration (still rate-limited)
const registerRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: {
    success: false,
    message: 'Too many registration attempts. Please try again after 1 hour.',
  },
  statusCode: 429,
});

// Public routes (no authentication required)
router.post('/register', registerRateLimit, register);
router.post('/login', authRateLimit, login);  // Rate limited

// Protected routes (require valid JWT)
router.post('/logout', authenticate, logout);
router.post('/change-password', authenticate, changePassword);
router.post('/enable-mfa', authenticate, enableMFA);
router.post('/verify-mfa-setup', authenticate, verifyMFASetup);
router.post('/disable-mfa', authenticate, disableMFA);
router.get('/sessions', authenticate, getSessions);
router.delete('/sessions/others', authenticate, logoutOtherSessions);

module.exports = router;