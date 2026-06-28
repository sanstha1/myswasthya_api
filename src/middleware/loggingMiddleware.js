const AuditLog = require('../models/AuditLog');
const User = require('../models/User');

/**
 * Log an action to the audit trail
 * SECURITY: Comprehensive audit logging for forensic analysis and compliance
 */
async function logAction(userId, action, req, details = {}) {
  try {
    // Strip any sensitive fields from details before logging
    const safeDetails = sanitizeLogDetails(details);

    await AuditLog.create({
      userId: userId || null,
      action,
      resource: req?.originalUrl || null,
      ipAddress: getClientIP(req),
      userAgent: req?.headers?.['user-agent']?.slice(0, 500) || null,
      details: safeDetails,
      timestamp: new Date(),
    });

    //Real-time monitoring - check for suspicious patterns
    await checkSecurityAlerts(userId, action, req);
  } catch (err) {
    //Log failures should NOT break the main request flow
    console.error('Audit log creation failed:', err.message);
  }
}


function getClientIP(req) {
  if (!req) return null;
  const forwarded = req.headers?.['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return req.connection?.remoteAddress || req.socket?.remoteAddress || null;
}


function sanitizeLogDetails(details) {
  if (!details || typeof details !== 'object') return {};

  const SENSITIVE_KEYS = [
    'password', 'passwordHash', 'token', 'secret', 'totpSecret',
    'backupCodes', 'cardNumber', 'cvv', 'ssn', 'creditCard',
    'authorization', 'cookie', 'key', 'apiKey',
  ];

  const sanitized = {};
  for (const [key, value] of Object.entries(details)) {
    const lowerKey = key.toLowerCase();
    const isSensitive = SENSITIVE_KEYS.some((s) => lowerKey.includes(s));
    if (!isSensitive) {
      sanitized[key] = value;
    }
  }
  return sanitized;
}


async function checkSecurityAlerts(userId, action, req) {
  if (!userId) return;

  const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);

  // SECURITY ALERT: Brute-force detection - 5 failed logins in 15 minutes
  if (action === 'login_failed') {
    const recentFailures = await AuditLog.countDocuments({
      userId,
      action: 'login_failed',
      timestamp: { $gte: fifteenMinutesAgo },
    });

    if (recentFailures >= 5) {
      console.warn(`[SECURITY ALERT] Brute-force detected for userId: ${userId} - ${recentFailures} failed logins in 15 minutes`);
    }
  }

  // SECURITY ALERT: Multiple session detection - same account from 3+ IPs in 1 hour
  if (action === 'login') {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const recentLogins = await AuditLog.find({
      userId,
      action: 'login',
      timestamp: { $gte: oneHourAgo },
    }).select('ipAddress');

    const uniqueIPs = new Set(recentLogins.map((l) => l.ipAddress));
    if (uniqueIPs.size >= 3) {
      console.warn(`[SECURITY ALERT] Multiple session IPs for userId: ${userId} - ${uniqueIPs.size} distinct IPs in 1 hour`);
    }
  }
}

module.exports = { logAction, getClientIP };