const mongoose = require('mongoose');

/**
 * IDOR Protection Middleware
 */
function protectResource(req, res, next) {
  try {
    const authenticatedUserId = req.user?.userId;

    if (!authenticatedUserId) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
      });
    }

    // If request specifies a userId param, it MUST match the authenticated user
    if (req.params.userId) {
      if (req.params.userId !== authenticatedUserId.toString()) {
        return res.status(403).json({
          success: false,
          message: 'Access denied - you can only access your own data',
        });
      }
    }

    //  If request body specifies a userId, it MUST match the authenticated user
    if (req.body?.userId) {
      if (req.body.userId !== authenticatedUserId.toString()) {
        return res.status(403).json({
          success: false,
          message: 'Access denied - userId mismatch',
        });
      }
    }

    next();
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Authorization error',
    });
  }
}

/**
 * Role check middleware
 */
function requireRole(...roles) {
  return (req, res, next) => {
    const userRole = req.user?.role || 'user';
    if (!roles.includes(userRole)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied - insufficient permissions',
      });
    }
    next();
  };
}

/**
 * Validate MongoDB ObjectId in request params
 * SECURITY: Prevents MongoDB injection via malformed IDs
 */
function validateObjectId(paramName = 'id') {
  return (req, res, next) => {
    const id = req.params[paramName];
    if (id && !mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid resource ID format',
      });
    }
    next();
  };
}

module.exports = { protectResource, requireRole, validateObjectId };