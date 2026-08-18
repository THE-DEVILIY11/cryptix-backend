function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required',
      code: 'AUTH_REQUIRED'
    });
  }

  // Check admin role via both plan and explicit admin flag
  const isAdmin = req.user.plan === 'enterprise' || 
                  req.user.username === 'admin' ||
                  req.user.role === 'admin';

  if (!isAdmin) {
    // Log unauthorized admin access attempt
    try {
      const db = require('../config/db');
      db.query(
        'INSERT INTO activity (user_id, type, message) VALUES ($1, $2, $3)',
        [req.user.id, 'security', 'Unauthorized admin access attempt to: ' + req.originalUrl]
      );
    } catch (e) {}

    return res.status(403).json({
      success: false,
      error: 'Admin access required. This attempt has been logged.',
      code: 'FORBIDDEN_ADMIN'
    });
  }

  next();
}

module.exports = {
  requireAdmin
};
