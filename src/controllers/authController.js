const User = require('../models/User');
const Profile = require('../models/Profile');
const { hashPassword, verifyPassword, validatePasswordComplexity, checkPasswordStrength, isPasswordInHistory } = require('../utils/passwordUtils');
const { generateTOTPSecret, generateTOTPQRCode, verifyTOTPCode, generateBackupCodes } = require('../utils/totpUtils');
const { generateJWTToken, getSessionCookieOptions, getClearCookieOptions } = require('../middleware/sessionMiddleware');
const { logAction } = require('../middleware/loggingMiddleware');
const { z } = require('zod');
const escapeHtml = require('escape-html');

// Zod schema for registration input validation
const registerSchema = z.object({
  email: z.string().email('Invalid email format').max(254).toLowerCase().trim(),
  password: z.string().min(12, 'Password must be at least 12 characters').max(128, 'Password too long'),
  fullName: z.string().min(2, 'Full name must be at least 2 characters').max(100).trim(),
});

// Zod schema for login input validation
const loginSchema = z.object({
  email: z.string().email('Invalid email format').toLowerCase().trim(),
  password: z.string().min(1, 'Password is required').max(128),
  totpCode: z.string().optional(),
});

async function register(req, res) {
  try {
    //Validate input with Zod schema
    const parseResult = registerSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: parseResult.error.errors.map((e) => e.message),
      });
    }

    const { email, password, fullName } = parseResult.data;

    // Validate password complexity server-side (not just client-side)
    const complexityCheck = validatePasswordComplexity(password);
    if (!complexityCheck.valid) {
      return res.status(400).json({
        success: false,
        message: 'Password does not meet requirements',
        errors: complexityCheck.errors,
      });
    }

    //Check password strength with zxcvbn (score must be >= 2)
    const strengthCheck = checkPasswordStrength(password);
    if (strengthCheck.score < 2) {
      return res.status(400).json({
        success: false,
        message: 'Password is too weak',
        feedback: strengthCheck.feedback,
      });
    }

   
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'Email already registered',
      });
    }

    //Hash password with Argon2id (memory-hard, GPU-resistant)
    const passwordHash = await hashPassword(password);

    //Generate TOTP secret for MFA enrollment (RFC 6238)
    const totpData = generateTOTPSecret(email);

    //Set password expiry to 90 days from now
    const passwordExpiry = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);

    const user = await User.create({
      email,
      passwordHash,
      passwordHistory: [passwordHash],
      lastPasswordChange: new Date(),
      passwordExpiry,
      totpSecret: totpData.base32,
      isMFAEnabled: false,
    });

    // Input sanitized before storing profile data
    await Profile.create({
      userId: user._id,
      fullName: escapeHtml(fullName.trim()),
    });

    // Generate QR code for authenticator app enrollment
    const qrCodeDataURL = await generateTOTPQRCode(totpData.otpauthUrl);

    await logAction(user._id, 'register', req, { email });

    return res.status(201).json({
      success: true,
      message: 'Registration successful. Please scan the QR code with your authenticator app.',
      data: {
        userId: user._id,
        email: user.email,
        qrCode: qrCodeDataURL,
        totpSecret: totpData.base32,
      },
    });

  } catch (err) {
    console.error('[AUTH] Register error:', err.message);
    return res.status(500).json({ success: false, message: 'Registration failed' });
  }
}


async function login(req, res) {
  try {
    const parseResult = loginSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        message: 'Invalid input',
        errors: parseResult.error.errors.map((e) => e.message),
      });
    }

    const { email, password, totpCode } = parseResult.data;

    // Find user - use .select() to explicitly include sensitive fields needed
    const user = await User.findOne({ email }).select(
      '+passwordHash +totpSecret +isMFAEnabled +failedLoginAttempts +lockedUntil +activeSessions +passwordExpiry'
    );

    // Generic error message - do not reveal whether email exists
    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password',
      });
    }

    // Check account lockout (brute-force protection)
    if (user.isLocked()) {
      const remainingTime = Math.ceil((user.lockedUntil - Date.now()) / 60000);
      await logAction(user._id, 'login_failed', req, { reason: 'account_locked' });
      return res.status(423).json({
        success: false,
        message: `Account locked due to too many failed attempts. Try again in ${remainingTime} minutes.`,
      });
    }

    // Verify password with Argon2id (timing-safe)
    const isPasswordValid = await verifyPassword(user.passwordHash, password);

    if (!isPasswordValid) {
      // Increment failed attempts counter
      user.failedLoginAttempts += 1;

      // Lock account after 5 failed attempts for 15 minutes
      if (user.failedLoginAttempts >= 5) {
        user.lockedUntil = new Date(Date.now() + 15 * 60 * 1000);
        user.failedLoginAttempts = 0;
        await user.save();
        await logAction(user._id, 'account_locked', req, { email });
        return res.status(423).json({
          success: false,
          message: 'Account locked after 5 failed attempts. Please try again in 15 minutes.',
          showCaptcha: true,
        });
      }

      await user.save();
      await logAction(user._id, 'login_failed', req, {
        failedAttempts: user.failedLoginAttempts,
        requiresCaptcha: user.failedLoginAttempts >= 3,
      });

      return res.status(401).json({
        success: false,
        message: 'Invalid email or password',
        failedAttempts: user.failedLoginAttempts,
        showCaptcha: user.failedLoginAttempts >= 3,
      });
    }

    // Verify TOTP if MFA is enabled (RFC 6238)
    if (user.isMFAEnabled) {
      if (!totpCode) {
        return res.status(400).json({
          success: false,
          message: 'MFA code is required',
          requiresMFA: true,
        });
      }

      const isTOTPValid = verifyTOTPCode(user.totpSecret, totpCode);
      if (!isTOTPValid) {
        await logAction(user._id, 'login_failed', req, { reason: 'invalid_mfa' });
        return res.status(401).json({
          success: false,
          message: 'Invalid MFA code',
        });
      }
    }

    // Reset failed attempts after successful authentication
    user.failedLoginAttempts = 0;
    user.lockedUntil = null;
    user.lastLogin = new Date();

    // Generate JWT with session tracking
    const { token, sessionId } = generateJWTToken(user._id, user.email);

    // Add session to active sessions list (for multi-device management)
    user.activeSessions.push({
      sessionId,
      userAgent: req.headers['user-agent']?.slice(0, 500) || 'unknown',
      ipAddress: req.ip,
      createdAt: new Date(),
      lastActive: new Date(),
    });

    // Keep only the last 10 sessions
    if (user.activeSessions.length > 10) {
      user.activeSessions = user.activeSessions.slice(-10);
    }

    await user.save();

    // Check if password is about to expire (warn 7 days before)
    const daysUntilExpiry = user.passwordExpiry
      ? Math.ceil((user.passwordExpiry - Date.now()) / (24 * 60 * 60 * 1000))
      : null;

    await logAction(user._id, 'login', req, { sessionId });

    // JWT stored in httpOnly cookie, not exposed to JavaScript
    res.cookie('authToken', token, getSessionCookieOptions());

    return res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        userId: user._id,
        email: user.email,
        isMFAEnabled: user.isMFAEnabled,
        passwordExpiresInDays: daysUntilExpiry,
        passwordExpired: user.isPasswordExpired(),
      },
    });

  } catch (err) {
    console.error('[AUTH] Login error:', err.message);
    return res.status(500).json({ success: false, message: 'Login failed' });
  }
}


async function logout(req, res) {
  try {
    const { userId, sessionId } = req.user;

    // Remove session from database (token reuse after logout prevented)
    await User.findByIdAndUpdate(userId, {
      $pull: { activeSessions: { sessionId } },
    });

    await logAction(userId, 'logout', req, { sessionId });

    // Clear the httpOnly cookie
    res.clearCookie('authToken', getClearCookieOptions());

    return res.status(200).json({
      success: true,
      message: 'Logged out successfully',
    });

  } catch (err) {
    console.error('[AUTH] Logout error:', err.message);
    return res.status(500).json({ success: false, message: 'Logout failed' });
  }
}


async function changePassword(req, res) {
  try {
    const { userId } = req.user;

    const schema = z.object({
      currentPassword: z.string().min(1),
      newPassword: z.string().min(12).max(128),
    });

    const parseResult = schema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: parseResult.error.errors.map((e) => e.message),
      });
    }

    const { currentPassword, newPassword } = parseResult.data;

    const user = await User.findById(userId).select(
      '+passwordHash +passwordHistory'
    );
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Verify current password before allowing change
    const isCurrentValid = await verifyPassword(user.passwordHash, currentPassword);
    if (!isCurrentValid) {
      return res.status(401).json({
        success: false,
        message: 'Current password is incorrect',
      });
    }

    // Validate new password complexity
    const complexityCheck = validatePasswordComplexity(newPassword);
    if (!complexityCheck.valid) {
      return res.status(400).json({
        success: false,
        message: 'New password does not meet requirements',
        errors: complexityCheck.errors,
      });
    }

    // Check password history - prevent reuse of last 5 passwords
    const inHistory = await isPasswordInHistory(newPassword, user.passwordHistory || []);
    if (inHistory) {
      return res.status(400).json({
        success: false,
        message: 'New password cannot be the same as your last 5 passwords',
      });
    }

    const newHash = await hashPassword(newPassword);

    
    const updatedHistory = [newHash, ...(user.passwordHistory || [])].slice(0, 5);

    
    const newExpiry = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);

    
    await User.findByIdAndUpdate(userId, {
      passwordHash: newHash,
      passwordHistory: updatedHistory,
      lastPasswordChange: new Date(),
      passwordExpiry: newExpiry,
      activeSessions: [],   // Clear all sessions
    });

    await logAction(userId, 'change_password', req);

    // Clear current session cookie (user must re-login)
    res.clearCookie('authToken', getClearCookieOptions());

    return res.status(200).json({
      success: true,
      message: 'Password changed successfully. Please login again with your new password.',
    });

  } catch (err) {
    console.error('[AUTH] Change password error:', err.message);
    return res.status(500).json({ success: false, message: 'Password change failed' });
  }
}


async function enableMFA(req, res) {
  try {
    const { userId, email } = req.user;

    const totpData = generateTOTPSecret(email);
    const qrCodeDataURL = await generateTOTPQRCode(totpData.otpauthUrl);

    // Generate backup codes for MFA recovery (10 single-use codes)
    const backupCodes = generateBackupCodes();

    // Store TOTP secret but don't enable MFA yet (requires verification)
    await User.findByIdAndUpdate(userId, {
      totpSecret: totpData.base32,
      backupCodes,
      isMFAEnabled: false,
    });

    return res.status(200).json({
      success: true,
      message: 'Scan the QR code with your authenticator app, then verify to complete MFA setup',
      data: {
        qrCode: qrCodeDataURL,
        totpSecret: totpData.base32,
        backupCodes,
      },
    });

  } catch (err) {
    console.error('[AUTH] Enable MFA error:', err.message);
    return res.status(500).json({ success: false, message: 'MFA setup failed' });
  }
}


async function verifyMFASetup(req, res) {
  try {
    const { userId } = req.user;
    const { totpCode } = req.body;

    if (!totpCode) {
      return res.status(400).json({ success: false, message: 'TOTP code is required' });
    }

    const user = await User.findById(userId).select('+totpSecret');
    if (!user || !user.totpSecret) {
      return res.status(400).json({ success: false, message: 'MFA setup not initiated' });
    }

    // Verify TOTP code before enabling MFA
    const isValid = verifyTOTPCode(user.totpSecret, totpCode);
    if (!isValid) {
      return res.status(400).json({ success: false, message: 'Invalid TOTP code - please check your authenticator app' });
    }

    await User.findByIdAndUpdate(userId, { isMFAEnabled: true });
    await logAction(userId, 'enable_mfa', req);

    return res.status(200).json({
      success: true,
      message: 'MFA enabled successfully',
    });

  } catch (err) {
    console.error('[AUTH] Verify MFA setup error:', err.message);
    return res.status(500).json({ success: false, message: 'MFA verification failed' });
  }
}

/**
 * POST /api/auth/disable-mfa
 * Requires password verification before disabling MFA
 * Prevents attacker from disabling MFA if they only have the session token
 */
async function disableMFA(req, res) {
  try {
    const { userId } = req.user;
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ success: false, message: 'Password is required to disable MFA' });
    }

    const user = await User.findById(userId).select('+passwordHash');
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Re-authenticate with password before disabling MFA
    const isPasswordValid = await verifyPassword(user.passwordHash, password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Incorrect password' });
    }

    await User.findByIdAndUpdate(userId, {
      isMFAEnabled: false,
      totpSecret: null,
      backupCodes: [],
    });

    await logAction(userId, 'disable_mfa', req);

    return res.status(200).json({
      success: true,
      message: 'MFA disabled successfully',
    });

  } catch (err) {
    console.error('[AUTH] Disable MFA error:', err.message);
    return res.status(500).json({ success: false, message: 'MFA disable failed' });
  }
}


async function getSessions(req, res) {
  try {
    const { userId, sessionId } = req.user;
    const user = await User.findById(userId).select('+activeSessions');

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const sessions = user.activeSessions.map((s) => ({
      sessionId: s.sessionId,
      userAgent: s.userAgent,
      ipAddress: s.ipAddress,
      createdAt: s.createdAt,
      lastActive: s.lastActive,
      isCurrent: s.sessionId === sessionId,
    }));

    return res.status(200).json({ success: true, data: sessions });

  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to retrieve sessions' });
  }
}


async function logoutOtherSessions(req, res) {
  try {
    const { userId, sessionId } = req.user;

    const user = await User.findById(userId).select('+activeSessions');
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Keep only the current session, remove all others
    const currentSession = user.activeSessions.find((s) => s.sessionId === sessionId);
    await User.findByIdAndUpdate(userId, {
      activeSessions: currentSession ? [currentSession] : [],
    });

    await logAction(userId, 'session_invalidated', req, { reason: 'logout_other_sessions' });

    return res.status(200).json({
      success: true,
      message: 'All other sessions have been logged out',
    });

  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to logout other sessions' });
  }
}

module.exports = {
  register,
  login,
  logout,
  changePassword,
  enableMFA,
  verifyMFASetup,
  disableMFA,
  getSessions,
  logoutOtherSessions,
};