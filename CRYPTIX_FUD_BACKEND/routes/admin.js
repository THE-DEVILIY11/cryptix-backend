const express = require('express');
const bcrypt = require('bcryptjs');
const {
  v4: uuidv4
} = require('uuid');
const {
  query
} = require('../config/db');
const {
  authenticate
} = require('../middleware/auth');
const {
  requireAdmin
} = require('../middleware/admin');

const router = express.Router();

// Apply admin middleware to all routes
router.use(authenticate);
router.use(requireAdmin);

// GET /api/admin/stats — Dashboard statistics
router.get('/stats', async (req, res) => {
  try {
    const totalUsers = await query('SELECT COUNT(*) FROM users');
    const activeUsers = await query("SELECT COUNT(*) FROM users WHERE status = 'active'");
    const totalLicenses = await query("SELECT COUNT(*) FROM licenses WHERE status = 'active'");
    const totalFiles = await query('SELECT COUNT(*) FROM files');
    const cryptedFiles = await query("SELECT COUNT(*) FROM files WHERE status = 'completed'");
    const totalDownloads = await query('SELECT COUNT(*) FROM downloads');
    const totalRevenue = await query("SELECT COALESCE(SUM(amount), 0) FROM invoices WHERE status = 'paid'");
    const pendingInvoices = await query("SELECT COUNT(*) FROM invoices WHERE status = 'pending'");

    // Recent registrations (last 7 days)
    const recentUsers = await query(
      "SELECT COUNT(*) FROM users WHERE created_at > NOW() - INTERVAL '7 days'"
    );

    // Files crypted today
    const todayFiles = await query(
      "SELECT COUNT(*) FROM files WHERE created_at::date = CURRENT_DATE"
    );

    // Plan distribution
    const planDist = await query(
      'SELECT plan, COUNT(*) as count FROM users GROUP BY plan ORDER BY count DESC'
    );

    res.json({
      success: true,
      stats: {
        totalUsers: parseInt(totalUsers.rows[0].count),
        activeUsers: parseInt(activeUsers.rows[0].count),
        totalLicenses: parseInt(totalLicenses.rows[0].count),
        totalFiles: parseInt(totalFiles.rows[0].count),
        cryptedFiles: parseInt(cryptedFiles.rows[0].count),
        totalDownloads: parseInt(totalDownloads.rows[0].count),
        totalRevenue: parseFloat(totalRevenue.rows[0].coalesce),
        pendingInvoices: parseInt(pendingInvoices.rows[0].count),
        newUsersWeek: parseInt(recentUsers.rows[0].count),
        todayCrypts: parseInt(todayFiles.rows[0].count),
        planDistribution: planDist.rows
      }
    });

  } catch (err) {
    console.error('[ADMIN] Stats error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get stats'
    });
  }
});

// GET /api/admin/users — List all users
router.get('/users', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;
    const search = req.query.search || null;

    let whereClause = '';
    let params = [];
    let paramIndex = 1;

    if (search) {
      whereClause = `WHERE (username ILIKE $${paramIndex} OR email ILIKE $${paramIndex} OR full_name ILIKE $${paramIndex} OR license_key ILIKE $${paramIndex})`;
      params.push(`%${search}%`);
      paramIndex++;
    }

    const countResult = await query(`SELECT COUNT(*) FROM users ${whereClause}`, params);
    const total = parseInt(countResult.rows[0].count);

    const result = await query(
      `SELECT id, username, email, full_name, license_key, plan, status,
              total_crypts, storage_used, last_login, created_at
       FROM users ${whereClause}
       ORDER BY created_at DESC
       LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`,
      [...params, limit, offset]
    );

    res.json({
      success: true,
      users: result.rows.map(u => ({
        ...u,
        storageUsed: u.storage_used,
        storageReadable: u.storage_used < 1024 * 1024 ?
          (u.storage_used / 1024).toFixed(1) + ' KB' :
          (u.storage_used / (1024 * 1024)).toFixed(2) + ' MB'
      })),
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    });

  } catch (err) {
    console.error('[ADMIN] Users list error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to list users'
    });
  }
});

// GET /api/admin/users/:id — Single user details
router.get('/users/:id', async (req, res) => {
  try {
    const result = await query(
      `SELECT id, username, email, full_name, license_key, plan, status,
              total_crypts, storage_used, last_login, created_at, updated_at
       FROM users WHERE id = $1`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    const user = result.rows[0];

    // Get user's files
    const filesResult = await query(
      `SELECT COUNT(*) as total, 
              COUNT(*) FILTER (WHERE status = 'completed') as crypted,
              COUNT(*) FILTER (WHERE status = 'detected') as detected
       FROM files WHERE user_id = $1`,
      [user.id]
    );

    // Get user's activity
    const activityResult = await query(
      'SELECT id, type, message, created_at FROM activity WHERE user_id = $1 ORDER BY created_at DESC LIMIT 10',
      [user.id]
    );

    res.json({
      success: true,
      user: {
        ...user,
        files: filesResult.rows[0],
        recentActivity: activityResult.rows
      }
    });

  } catch (err) {
    console.error('[ADMIN] User detail error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get user'
    });
  }
});

// POST /api/admin/users — Create user
router.post('/users', async (req, res) => {
  try {
    const {
      username,
      email,
      password,
      fullName,
      plan
    } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Username, email, and password are required'
      });
    }

    // Check existing
    const existCheck = await query(
      'SELECT id FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );

    if (existCheck.rows.length > 0) {
      return res.status(400).json({
        success: false,
        error: 'Username or email already exists'
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const licenseKey = generateLicenseKey();

    const result = await query(
      `INSERT INTO users (username, email, password_hash, full_name, license_key, plan, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'active')
       RETURNING id, username, email, full_name, license_key, plan, status, created_at`,
      [username, email, passwordHash, fullName || '', licenseKey, plan || 'basic']
    );

    // Create license
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 90);

    await query(
      `INSERT INTO licenses (license_key, user_id, plan, duration_days, status, activated_at, expires_at)
       VALUES ($1, $2, $3, 90, 'active', NOW(), $4)`,
      [licenseKey, result.rows[0].id, plan || 'basic', expiresAt]
    );

    // Log
    await query(
      'INSERT INTO activity (user_id, type, message) VALUES ($1, $2, $3)',
      [req.user.id, 'admin', 'Created user: ' + username + ' (' + (plan || 'basic') + ')']
    );

    res.json({
      success: true,
      user: result.rows[0],
      licenseKey
    });

  } catch (err) {
    console.error('[ADMIN] Create user error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to create user'
    });
  }
});

// PUT /api/admin/users/:id — Update user
router.put('/users/:id', async (req, res) => {
  try {
    const {
      fullName,
      plan,
      status
    } = req.body;

    const result = await query(
      `UPDATE users SET
         full_name = COALESCE($1, full_name),
         plan = COALESCE($2, plan),
         status = COALESCE($3, status),
         updated_at = NOW()
       WHERE id = $4
       RETURNING id, username, email, full_name, license_key, plan, status`,
      [fullName, plan, status, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    await query(
      'INSERT INTO activity (user_id, type, message) VALUES ($1, $2, $3)',
      [req.user.id, 'admin', 'Updated user: ' + result.rows[0].username]
    );

    res.json({
      success: true,
      user: result.rows[0]
    });

  } catch (err) {
    console.error('[ADMIN] Update user error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to update user'
    });
  }
});

// DELETE /api/admin/users/:id — Delete user
router.delete('/users/:id', async (req, res) => {
  try {
    const result = await query(
      'DELETE FROM users WHERE id = $1 RETURNING id, username',
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    await query(
      'INSERT INTO activity (user_id, type, message) VALUES ($1, $2, $3)',
      [req.user.id, 'admin', 'Deleted user: ' + result.rows[0].username]
    );

    res.json({
      success: true,
      message: 'User deleted'
    });

  } catch (err) {
    console.error('[ADMIN] Delete user error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to delete user'
    });
  }
});

// POST /api/admin/licenses — Generate license key
router.post('/licenses', async (req, res) => {
  try {
    const {
      plan,
      durationDays,
      customerName
    } = req.body;

    const planName = plan || 'pro';
    const duration = parseInt(durationDays) || 90;
    const licenseKey = generateLicenseKey();

    // If customer name provided, create user
    let userId = null;
    if (customerName) {
      const username = customerName.toLowerCase().replace(/\s+/g, '_') + '_' + Math.floor(Math.random() * 1000);
      const tempPassword = uuidv4().substring(0, 12);
      const passwordHash = await bcrypt.hash(tempPassword, 10);

      const userResult = await query(
        `INSERT INTO users (username, email, password_hash, full_name, license_key, plan, status)
         VALUES ($1, $2, $3, $4, $5, $6, 'active')
         RETURNING id`,
        [username, username + '@cryptix.io', passwordHash, customerName, licenseKey, planName]
      );
      userId = userResult.rows[0].id;
    }

    // Create license record
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + duration);

    const licResult = await query(
      `INSERT INTO licenses (license_key, user_id, plan, duration_days, status, activated_at, expires_at)
       VALUES ($1, $2, $3, $4, 'active', NOW(), $5)
       RETURNING id, license_key, plan, duration_days, status, expires_at`,
      [licenseKey, userId, planName, duration, expiresAt]
    );

    // Log
    await query(
      'INSERT INTO activity (user_id, type, message) VALUES ($1, $2, $3)',
      [req.user.id, 'admin', 'Generated license: ' + licenseKey + ' (' + planName + ', ' + duration + 'd)']
    );

    res.json({
      success: true,
      license: licResult.rows[0],
      customerName: customerName || null,
      durationDays: duration
    });

  } catch (err) {
    console.error('[ADMIN] Generate license error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to generate license'
    });
  }
});

// GET /api/admin/licenses — List all licenses
router.get('/licenses', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    const countResult = await query('SELECT COUNT(*) FROM licenses');
    const total = parseInt(countResult.rows[0].count);

    const result = await query(
      `SELECT l.id, l.license_key, l.plan, l.duration_days, l.status,
              l.activated_at, l.expires_at, l.created_at,
              u.username, u.full_name, u.email
       FROM licenses l
       LEFT JOIN users u ON l.user_id = u.id
       ORDER BY l.created_at DESC
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    res.json({
      success: true,
      licenses: result.rows,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    });

  } catch (err) {
    console.error('[ADMIN] Licenses list error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to list licenses'
    });
  }
});

// PUT /api/admin/licenses/:id — Update license
router.put('/licenses/:id', async (req, res) => {
  try {
    const {
      status,
      plan,
      durationDays
    } = req.body;

    let queryStr = 'UPDATE licenses SET';
    const updates = [];
    const params = [];
    let paramIdx = 1;

    if (status) {
      updates.push(` status = $${paramIdx}`);
      params.push(status);
      paramIdx++;
    }
    if (plan) {
      updates.push(` plan = $${paramIdx}`);
      params.push(plan);
      paramIdx++;
    }
    if (durationDays) {
      updates.push(` duration_days = $${paramIdx}`);
      params.push(parseInt(durationDays));
      paramIdx++;
      // Update expires_at
      updates.push(` expires_at = NOW() + INTERVAL '1 day' * $${paramIdx}`);
      params.push(parseInt(durationDays));
      paramIdx++;
    }

    if (updates.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'No fields to update'
      });
    }

    updates.push(` updated_at = NOW()`);
    queryStr += updates.join(',') + ` WHERE id = $${paramIdx} RETURNING id, license_key, plan, status, expires_at`;
    params.push(req.params.id);

    const result = await query(queryStr, params);

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'License not found'
      });
    }

    await query(
      'INSERT INTO activity (user_id, type, message) VALUES ($1, $2, $3)',
      [req.user.id, 'admin', 'Updated license: ' + result.rows[0].license_key]
    );

    res.json({
      success: true,
      license: result.rows[0]
    });

  } catch (err) {
    console.error('[ADMIN] Update license error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to update license'
    });
  }
});

// DELETE /api/admin/licenses/:id — Revoke license
router.delete('/licenses/:id', async (req, res) => {
  try {
    const result = await query(
      "UPDATE licenses SET status = 'revoked' WHERE id = $1 RETURNING id, license_key",
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'License not found'
      });
    }

    await query(
      'INSERT INTO activity (user_id, type, message) VALUES ($1, $2, $3)',
      [req.user.id, 'admin', 'Revoked license: ' + result.rows[0].license_key]
    );

    res.json({
      success: true,
      message: 'License revoked'
    });

  } catch (err) {
    console.error('[ADMIN] Revoke license error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to revoke license'
    });
  }
});

// GET /api/admin/activity — All system activity
router.get('/activity', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 30;
    const type = req.query.type || null;

    let whereClause = '';
    let params = [];
    let paramIdx = 1;

    if (type && type !== 'all') {
      whereClause = `WHERE a.type = $${paramIdx}`;
      params.push(type);
      paramIdx++;
    }

    const result = await query(
      `SELECT a.id, a.type, a.message, a.created_at,
              u.username, u.full_name
       FROM activity a
       LEFT JOIN users u ON a.user_id = u.id
       ${whereClause}
       ORDER BY a.created_at DESC
       LIMIT $${paramIdx}`,
      [...params, limit]
    );

    res.json({
      success: true,
      activities: result.rows
    });

  } catch (err) {
    console.error('[ADMIN] Activity error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get activity'
    });
  }
});

// GET /api/admin/files — All files (admin view)
router.get('/files', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    const countResult = await query('SELECT COUNT(*) FROM files');
    const total = parseInt(countResult.rows[0].count);

    const result = await query(
      `SELECT f.id, f.original_name, f.crypted_name, f.file_size, f.method,
              f.status, f.detections, f.fud_rate, f.download_count, f.created_at,
              u.username, u.full_name
       FROM files f
       LEFT JOIN users u ON f.user_id = u.id
       ORDER BY f.created_at DESC
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    res.json({
      success: true,
      files: result.rows.map(f => ({
        ...f,
        readableSize: f.file_size < 1024 * 1024 ?
          (f.file_size / 1024).toFixed(1) + ' KB' :
          (f.file_size / (1024 * 1024)).toFixed(2) + ' MB'
      })),
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    });

  } catch (err) {
    console.error('[ADMIN] Files error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to list files'
    });
  }
});

function generateLicenseKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const segments = [];
  for (let s = 0; s < 4; s++) {
    let seg = '';
    for (let i = 0; i < 5; i++) {
      seg += chars[Math.floor(Math.random() * chars.length)];
    }
    segments.push(seg);
  }
  return 'CRYPT-' + segments.join('-');
}

module.exports = router;
