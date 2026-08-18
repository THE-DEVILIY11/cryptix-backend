const {
  verifyToken
} = require('../config/jwt');
const {
  query
} = require('../config/db');

async function authenticate(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: 'No token provided',
        code: 'AUTH_NO_TOKEN'
      });
    }

    const token = authHeader.split(' ')[1];
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        success: false,
        error: 'Invalid or expired token',
        code: 'AUTH_INVALID_TOKEN'
      });
    }

    // Verify user still exists and is active
    const result = await query(
      'SELECT id, username, email, full_name, license_key, plan, status, storage_used, total_crypts, created_at FROM users WHERE id = $1 AND status = $2',
      [decoded.userId, 'active']
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: 'User not found or inactive',
        code: 'AUTH_USER_INACTIVE'
      });
    }

    req.user = result.rows[0];
    req.token = token;
    next();
  } catch (err) {
    console.error('[AUTH] Error:', err.message);
    return res.status(500).json({
      success: false,
      error: 'Authentication error',
      code: 'AUTH_ERROR'
    });
  }
}

function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authenticate(req, res, next);
  }
  req.user = null;
  next();
}

module.exports = {
  authenticate,
  optionalAuth
};
