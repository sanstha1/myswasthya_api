const AuditLog = require('../models/AuditLog');

const logAction = (action) => async (req, res, next) => {
  try {
    if (req.user) {
      await AuditLog.create({
        userId: req.user.userId,
        action,
        resource: req.originalUrl,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] || ''
      });
    }
    next();
  } catch (error) {
    next(error);
  }
};

module.exports = { logAction };