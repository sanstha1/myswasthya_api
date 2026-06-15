const User = require('../models/User');
const Profile = require('../models/Profile');
const AuditLog = require('../models/AuditLog');
const { hashPassword, verifyPassword, checkPasswordStrength } = require('../utils/passwordUtils');
const { generateTOTPSecret, generateTOTPQRURL, verifyTOTPCode } = require('../utils/totpUtils');
const { generateJWTToken } = require('../middleware/sessionMiddleware');

const register = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email and password are required' });

    const strength = checkPasswordStrength(password);
    if (!strength.valid) return res.status(400).json({ success: false, error: 'Weak password', issues: strength.issues });

    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ success: false, error: 'Email already exists' });

    const passwordHash = await hashPassword(password);
    const secret = generateTOTPSecret(email);
    const passwordExpiry = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);

    const user = await User.create({
      email,
      passwordHash,
      totpSecret: secret.base32,
      passwordExpiry,
      lastPasswordChange: new Date(),
      passwordHistory: [passwordHash]
    });

    await Profile.create({ userId: user._id });

    const qrUrl = generateTOTPQRURL(secret, email);

    await AuditLog.create({
      userId: user._id,
      action: 'register',
      resource: 'auth',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] || ''
    });

    res.status(201).json({
      success: true,
      message: 'Registered successfully',
      qrUrl,
      secret: secret.base32
    });
  } catch (error) {
    next(error);
  }
};

const login = async (req, res, next) => {
  try {
    const { email, password, totpCode } = req.body;
    const user = await User.findOne({ email, isActive: true });
    if (!user) return res.status(401).json({ success: false, error: 'Invalid credentials' });

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      return res.status(429).json({ success: false, error: 'Account locked' });
    }

    const passwordValid = await verifyPassword(password, user.passwordHash);
    if (!passwordValid) {
      user.failedLoginAttempts += 1;
      if (user.failedLoginAttempts >= 5) {
        user.lockedUntil = new Date(Date.now() + 15 * 60 * 1000);
      }
      await user.save();
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const totpValid = verifyTOTPCode(user.totpSecret, totpCode);
    if (!totpValid) return res.status(401).json({ success: false, error: 'Invalid MFA code' });

    user.failedLoginAttempts = 0;
    user.lockedUntil = null;
    user.lastLogin = new Date();
    await user.save();

    const token = generateJWTToken({ id: user._id, email: user.email });

    await AuditLog.create({
      userId: user._id,
      action: 'login',
      resource: 'auth',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] || ''
    });

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        email: user.email
      }
    });
  } catch (error) {
    next(error);
  }
};

const changePassword = async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    const currentValid = await verifyPassword(currentPassword, user.passwordHash);
    if (!currentValid) return res.status(401).json({ success: false, error: 'Invalid current password' });

    const strength = checkPasswordStrength(newPassword);
    if (!strength.valid) return res.status(400).json({ success: false, error: 'Weak password', issues: strength.issues });

    const newHash = await hashPassword(newPassword);
    if (user.passwordHistory.includes(newHash)) {
      return res.status(400).json({ success: false, error: 'Password was previously used' });
    }

    user.passwordHistory.unshift(newHash);
    user.passwordHistory = user.passwordHistory.slice(0, 5);
    user.passwordHash = newHash;
    user.lastPasswordChange = new Date();
    user.passwordExpiry = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);
    await user.save();

    await AuditLog.create({
      userId: user._id,
      action: 'change_password',
      resource: 'auth',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] || ''
    });

    res.json({ success: true, message: 'Password changed successfully' });
  } catch (error) {
    next(error);
  }
};

const enableMFA = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    const secret = generateTOTPSecret(user.email);
    user.totpSecret = secret.base32;
    await user.save();

    const qrUrl = generateTOTPQRURL(secret, user.email);

    await AuditLog.create({
      userId: user._id,
      action: 'enable_mfa',
      resource: 'auth',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] || ''
    });

    res.json({ success: true, qrUrl, secret: secret.base32 });
  } catch (error) {
    next(error);
  }
};

const disableMFA = async (req, res, next) => {
  try {
    const { password } = req.body;
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) return res.status(401).json({ success: false, error: 'Invalid password' });

    user.totpSecret = null;
    await user.save();

    await AuditLog.create({
      userId: user._id,
      action: 'disable_mfa',
      resource: 'auth',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] || ''
    });

    res.json({ success: true, message: 'MFA disabled' });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  register,
  login,
  changePassword,
  enableMFA,
  disableMFA
};