const express = require('express');
const bcrypt = require('bcryptjs');
const {
  v4: uuidv4
} = require('uuid');
const {
  query
} = require('../config/db');
const {
  generateToken,
  verifyToken
} = require('../config/jwt');
const {
  authenticate
} = require('../middleware/auth');
const {
  authLimiter
} = require('../middleware/rateLimit');

const router = express.Router();

// Track login attempts per IP to prevent brute-force
const loginAttempts = new Map();

// POST /api/auth/login — License key login
router.post('/login', authLimiter, async (req, res) => {
  // Brute-force protection
  const ip = req.ip || 'unknown';
  const attempts = loginAttempts.get(ip) || 0;
  if (attempts >= 5) {
    return res.status(429).json({
      success: false,
      error: 'Too many login attempts. Account temporarily locked for 15 minutes.',
      code: 'BRUTE_FORCE_LOCKED'
    });
  }
  try {
    const {
      licenseKey
    } = req.body;

    if (!licenseKey) {
      return res.status(400).json({
        success: false,
        error: 'License key is required',
        code: 'MISSING_LICENSE'
      });
    }

    const key = licenseKey.toUpperCase().trim();
    const keyPattern = /^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$/;

    if (!keyPattern.test(key)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid license key format. Use: XXXXX-XXXXX-XXXXX-XXXXX',
        code: 'INVALID_FORMAT'
      });
    }

    // Check license
    const licResult = await query(
      'SELECT * FROM licenses WHERE license_key = $1',
      [key]
    );

    if (licResult.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: 'Invalid license key. Access denied.',
        code: 'LICENSE_NOT_FOUND'
      });
    }

    const license = licResult.rows[0];

    if (license.status !== 'active') {
      return res.status(401).json({
        success: false,
        error: 'License is ' + license.status + '. Please contact support.',
        code: 'LICENSE_INACTIVE'
      });
    }

    if (license.expires_at && new Date(license.expires_at) < new Date()) {
      return res.status(401).json({
        success: false,
        error: 'License has expired. Please renew.',
        code: 'LICENSE_EXPIRED'
      });
    }

    // Find or create user
    let userResult = await query(
      'SELECT * FROM users WHERE license_key = $1',
      [key]
    );

    let user;
    if (userResult.rows.length === 0) {
      // Auto-create user from license
      const username = 'user_' + key.substring(0, 5).toLowerCase();
      const tempPassword = uuidv4().substring(0, 16);
      const passwordHash = await bcrypt.hash(tempPassword, 10);

      userResult = await query(
        `INSERT INTO users (username, email, password_hash, full_name, license_key, plan, status)
         VALUES ($1, $2, $3, $4, $5, $6, 'active')
         RETURNING id, username, email, full_name, license_key, plan, status, created_at`,
        [username, username + '@cryptix.io', passwordHash, license.plan + ' User', key, license.plan]
      );
      user = userResult.rows[0];

      // Log activity
      await query(
        'INSERT INTO activity (user_id, type, message) VALUES ($1, $2, $3)',
        [user.id, 'account', 'Account auto-created via license activation']
      );
    } else {
      user = userResult.rows[0];

      if (user.status !== 'active') {
        return res.status(401).json({
          success: false,
          error: 'Account is ' + user.status,
          code: 'USER_INACTIVE'
        });
      }
    }

    // Update last login
    await query(
      'UPDATE users SET last_login = NOW() WHERE id = $1',
      [user.id]
    );

    // Update license activation
    if (!license.activated_at) {
      await query(
        'UPDATE licenses SET activated_at = NOW(), user_id = $1 WHERE id = $2',
        [user.id, license.id]
      );
    }

    // Reset login attempts on success
    loginAttempts.delete(ip);

    // Generate token
    const token = generateToken({
      userId: user.id,
      username: user.username,
      plan: user.plan,
      licenseKey: key
    });

    // Log activity
    await query(
      'INSERT INTO activity (user_id, type, message) VALUES ($1, $2, $3)',
      [user.id, 'auth', 'User logged in from ' + (req.ip || 'unknown')]
    );

    // Record session
    await query(
      `INSERT INTO sessions (user_id, token, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, NOW() + INTERVAL '24 hours')`,
      [user.id, token, req.ip || 'unknown', req.get('User-Agent') || 'unknown']
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        fullName: user.full_name,
        licenseKey: user.license_key,
        plan: user.plan,
        status: user.status
      }
    });

  } catch (err) {
    // Track failed attempt
    const ip = req.ip || 'unknown';
    loginAttempts.set(ip, (loginAttempts.get(ip) || 0) + 1);
    // Expire after 15 minutes
    setTimeout(() => loginAttempts.delete(ip), 900000);

    console.error('[AUTH] Login error:', err);
    res.status(500).json({
      success: false,
      error: 'Login failed',
      code: 'LOGIN_ERROR'
    });
  }
});

// Clean up old login attempts every 10 minutes — PREVENTS MEMORY LEAK
setInterval(() => {
  loginAttempts.clear();
  if (process.env.NODE_ENV === 'development') {
    console.log('[AUTH] Cleared login attempt tracking');
  }
}, 600000);

// POST /api/auth/logout
router.post('/logout', authenticate, async (req, res) => {
  try {
    // Invalidate session
    await query(
      'UPDATE sessions SET is_active = false WHERE token = $1',
      [req.token]
    );

    await query(
      'INSERT INTO activity (user_id, type, message) VALUES ($1, $2, $3)',
      [req.user.id, 'auth', 'User logged out']
    );

    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (err) {
    console.error('[AUTH] Logout error:', err);
    res.status(500).json({
      success: false,
      error: 'Logout failed'
    });
  }
});

// POST /api/auth/validate — Validate token
router.post('/validate', authenticate, async (req, res) => {
  try {
    // Check license still valid
    const licResult = await query(
      'SELECT status, expires_at FROM licenses WHERE license_key = $1',
      [req.user.license_key]
    );

    if (licResult.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: 'License not found',
        code: 'LICENSE_NOT_FOUND'
      });
    }

    const lic = licResult.rows[0];

    if (lic.status !== 'active' || (lic.expires_at && new Date(lic.expires_at) < new Date())) {
      return res.status(401).json({
        success: false,
        error: 'License is no longer valid',
        code: 'LICENSE_INVALID'
      });
    }

    res.json({
      success: true,
      user: req.user,
      license: lic
    });
  } catch (err) {
    console.error('[AUTH] Validate error:', err);
    res.status(500).json({
      success: false,
      error: 'Validation failed'
    });
  }
});

module.exports = router;
