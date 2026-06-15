function protectResource(resourceField) {
  return async (req, res, next) => {
    const userId = req.user.userId;
    const resourceOwnerId = req.body[resourceField] || req.query[resourceField] || req.params.id;
    
    if (resourceOwnerId && resourceOwnerId !== userId) {
      return res.status(403).json({ 
        error: 'Access denied', 
        message: 'You can only access your own data' 
      });
    }
    
    next();
  };
}

function requireRole(allowedRoles) {
  return async (req, res, next) => {
    const userRole = req.user.role || 'user';
    
    if (!allowedRoles.includes(userRole)) {
      return res.status(403).json({ 
        error: 'Access denied', 
        message: 'Insufficient permissions' 
      });
    }
    
    next();
  };
}

module.exports = { protectResource, requireRole };