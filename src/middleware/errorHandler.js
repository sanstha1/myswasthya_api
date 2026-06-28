/**
 * Centralized Error Handling Middleware
 * SECURITY: Prevents stack trace and internal details from leaking to clients
 */
function errorHandler(err, req, res, next) {
  const isDevelopment = process.env.NODE_ENV === 'development';

  // Always log full error server-side for debugging
  console.error('[ERROR]', {
    message: err.message,
    stack: isDevelopment ? err.stack : '[hidden in production]',
    url: req?.originalUrl,
    method: req?.method,
    ip: req?.ip,
    timestamp: new Date().toISOString(),
  });

  //Mongoose validation error - expose field errors but not stack
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map((e) => e.message);
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors,
    });
  }

  //Mongoose duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyPattern || {})[0] || 'field';
    return res.status(409).json({
      success: false,
      message: `${field.charAt(0).toUpperCase() + field.slice(1)} already exists`,
    });
  }

  // SECURITY: JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      message: 'Invalid authentication token',
    });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      message: 'Session expired, please login again',
    });
  }

  // Custom application errors with status codes
  if (err.statusCode) {
    return res.status(err.statusCode).json({
      success: false,
      message: err.message,
    });
  }

  // All other errors return generic 500 message in production
  // Stack trace NEVER sent to client
  return res.status(500).json({
    success: false,
    message: isDevelopment ? err.message : 'Internal server error',
  });
}

function notFoundHandler(req, res) {
  return res.status(404).json({
    success: false,
    message: 'Resource not found',
  });
}

module.exports = { errorHandler, notFoundHandler };