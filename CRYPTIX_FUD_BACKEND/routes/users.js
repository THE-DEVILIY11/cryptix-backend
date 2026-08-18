const express = require('express');
const bcrypt = require('bcryptjs');
const {
  query
} = require('../config/db');
const {
  authenticate
} = require('../middleware/auth');
const {
  calculateStorageUsed
} = require('../config/storage');

const router = express.Router();

// GET /api/users/profile
router.get('/profile', authenticate, async (req, res) => {
  try {
    const storageUsed = calculateStorageUsed(req.user.id);

    const result = await query(
      `SELECT id, username, email, full_name, license_key, plan, status,
              total_crypts, last_login, created_at
       FROM users WHERE id = $1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    const user = result.rows[0];

    // Get license info
    const licResult = await query(
      'SELECT plan, duration_days, activated_at, expires_at FROM licenses WHERE license_key = $1',
      [user.license_key]
    );

    res.json({
      success: true,
      user: {
        ...user,
        storageUsed,
        storageLimit: 524288000, // 500MB
        license: licResult.rows[0] || null
      }
    });
  } catch (err) {
    console.error('[USERS] Profile error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to load profile'
    });
  }
});

// PUT /api/users/profile
router.put('/profile', authenticate, async (req, res) => {
  try {
    const {
      fullName,
      email
    } = req.body;

    const result = await query(
      `UPDATE users SET full_name = COALESCE($1, full_name),
                         email = COALESCE($2, email),
                         updated_at = NOW()
       WHERE id = $3 RETURNING id, username, email, full_name, plan, status`,
      [fullName || null, email || null, req.user.id]
    );

    await query(
      'INSERT INTO activity (user_id, type, message) VALUES ($1, $2, $3)',
      [req.user.id, 'settings', 'Profile updated']
    );

    res.json({
      success: true,
      user: result.rows[0]
    });
  } catch (err) {
    console.error('[USERS] Update profile error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to update profile'
    });
  }
});

// PUT /api/users/password
router.put('/password', authenticate, async (req, res) => {
  try {
    const {
      currentPassword,
      newPassword
    } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        error: 'Current password and new password are required'
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        error: 'New password must be at least 8 characters'
      });
    }

    // Get current password hash
    const result = await query(
      'SELECT password_hash FROM users WHERE id = $1',
      [req.user.id]
    );

    const valid = await bcrypt.compare(currentPassword, result.rows[0].password_hash);
    if (!valid) {
      return res.status(400).json({
        success: false,
        error: 'Current password is incorrect'
      });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);
    await query(
      'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
      [passwordHash, req.user.id]
    );

    await query(
      'INSERT INTO activity (user_id, type, message) VALUES ($1, $2, $3)',
      [req.user.id, 'security', 'Password changed']
    );

    res.json({
      success: true,
      message: 'Password updated successfully'
    });
  } catch (err) {
    console.error('[USERS] Password error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to update password'
    });
  }
});

// GET /api/users/activity
router.get('/activity', authenticate, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    const result = await query(
      'SELECT id, type, message, created_at FROM activity WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2',
      [req.user.id, limit]
    );

    res.json({
      success: true,
      activities: result.rows
    });
  } catch (err) {
    console.error('[USERS] Activity error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to load activity'
    });
  }
});

module.exports = router;
