const express = require('express');
const {
  query
} = require('../config/db');
const {
  authenticate
} = require('../middleware/auth');

const router = express.Router();

// GET /api/analytics/stats — Main dashboard stats
router.get('/stats', authenticate, async (req, res) => {
  try {
    // Total files crypted
    const totalResult = await query(
      "SELECT COUNT(*) FROM files WHERE user_id = $1 AND status = 'completed'",
      [req.user.id]
    );
    const totalCrypts = parseInt(totalResult.rows[0].count);

    // Files this week
    const weekResult = await query(
      `SELECT COUNT(*) FROM files 
       WHERE user_id = $1 
       AND created_at > NOW() - INTERVAL '7 days'`,
      [req.user.id]
    );
    const thisWeek = parseInt(weekResult.rows[0].count);

    // Files today
    const todayResult = await query(
      `SELECT COUNT(*) FROM files 
       WHERE user_id = $1 
       AND created_at::date = CURRENT_DATE`,
      [req.user.id]
    );
    const today = parseInt(todayResult.rows[0].count);

    // Total downloads
    const dlResult = await query(
      'SELECT COUNT(*) FROM downloads WHERE user_id = $1',
      [req.user.id]
    );
    const totalDownloads = parseInt(dlResult.rows[0].count);

    // Downloads this month
    const monthDlResult = await query(
      `SELECT COUNT(*) FROM downloads 
       WHERE user_id = $1 
       AND EXTRACT(MONTH FROM created_at) = EXTRACT(MONTH FROM NOW())
       AND EXTRACT(YEAR FROM created_at) = EXTRACT(YEAR FROM NOW())`,
      [req.user.id]
    );
    const monthDownloads = parseInt(monthDlResult.rows[0].count);

    // FUD rate
    const cleanResult = await query(
      "SELECT COUNT(*) FROM files WHERE user_id = $1 AND status = 'completed' AND detections = 0",
      [req.user.id]
    );
    const cleanFiles = parseInt(cleanResult.rows[0].count);
    const fudRate = totalCrypts > 0 ? Math.round((cleanFiles / totalCrypts) * 100) : 0;

    // Detected files
    const detectedResult = await query(
      'SELECT COUNT(*) FROM files WHERE user_id = $1 AND detections > 0',
      [req.user.id]
    );
    const detectedFiles = parseInt(detectedResult.rows[0].count);

    // Storage used
    const storageResult = await query(
      'SELECT COALESCE(SUM(file_size), 0) FROM files WHERE user_id = $1',
      [req.user.id]
    );
    const storageUsed = parseInt(storageResult.rows[0].coalesce);

    // Average FUD rate
    const avgResult = await query(
      "SELECT COALESCE(AVG(fud_rate), 0) FROM files WHERE user_id = $1 AND status = 'completed'",
      [req.user.id]
    );
    const avgFudRate = parseFloat(avgResult.rows[0].coalesce).toFixed(1);

    res.json({
      success: true,
      stats: {
        totalCrypts,
        thisWeek,
        today,
        totalDownloads,
        monthDownloads,
        cleanFiles,
        detectedFiles,
        fudRate,
        avgFudRate: parseFloat(avgFudRate),
        storageUsed,
        storageReadable: storageUsed < 1024 * 1024 ?
          (storageUsed / 1024).toFixed(1) + ' KB' :
          (storageUsed / (1024 * 1024)).toFixed(2) + ' MB'
      }
    });

  } catch (err) {
    console.error('[ANALYTICS] Stats error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get stats'
    });
  }
});

// GET /api/analytics/daily — Daily crypts for charts
router.get('/daily', authenticate, async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 14;

    const result = await query(
      `SELECT DATE(created_at) as date, COUNT(*) as count
       FROM files
       WHERE user_id = $1
         AND created_at > NOW() - ($2 || ' days')::INTERVAL
       GROUP BY DATE(created_at)
       ORDER BY date ASC`,
      [req.user.id, days]
    );

    // Fill in missing days with zero
    const data = [];
    const dates = {};
    result.rows.forEach(r => {
      dates[r.date.toISOString().split('T')[0]] = parseInt(r.count);
    });

    for (let i = days - 1; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const key = d.toISOString().split('T')[0];
      data.push({
        date: key,
        label: d.toLocaleDateString('en-US', {
          month: 'short',
          day: 'numeric'
        }),
        count: dates[key] || 0
      });
    }

    res.json({
      success: true,
      daily: data
    });

  } catch (err) {
    console.error('[ANALYTICS] Daily error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get daily data'
    });
  }
});

// GET /api/analytics/methods — Method usage distribution
router.get('/methods', authenticate, async (req, res) => {
  try {
    const result = await query(
      `SELECT method, COUNT(*) as count
       FROM files
       WHERE user_id = $1 AND method IS NOT NULL
       GROUP BY method
       ORDER BY count DESC`,
      [req.user.id]
    );

    // If no data, return defaults
    if (result.rows.length === 0) {
      return res.json({
        success: true,
        methods: [{
            method: 'aes',
            count: 2,
            label: 'AES-256'
          },
          {
            method: 'xor',
            count: 1,
            label: 'XOR + Obfuscation'
          },
          {
            method: 'polymorphic',
            count: 1,
            label: 'Polymorphic'
          },
          {
            method: 'hybrid',
            count: 2,
            label: 'Hybrid'
          }
        ]
      });
    }

    const methodLabels = {
      aes: 'AES-256',
      xor: 'XOR + Obfuscation',
      polymorphic: 'Polymorphic',
      hybrid: 'Hybrid'
    };

    res.json({
      success: true,
      methods: result.rows.map(r => ({
        method: r.method,
        count: parseInt(r.count),
        label: methodLabels[r.method] || r.method
      }))
    });

  } catch (err) {
    console.error('[ANALYTICS] Methods error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get method distribution'
    });
  }
});

// GET /api/analytics/top-files — Most downloaded files
router.get('/top-files', authenticate, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 5;

    const result = await query(
      `SELECT f.id, f.original_name, f.crypted_name, f.file_size, f.method,
              f.status, f.detections, f.fud_rate, f.download_count, f.created_at
       FROM files f
       WHERE f.user_id = $1
       ORDER BY f.download_count DESC, f.created_at DESC
       LIMIT $2`,
      [req.user.id, limit]
    );

    res.json({
      success: true,
      files: result.rows.map(f => ({
        id: f.id,
        name: f.crypted_name || f.original_name,
        originalName: f.original_name,
        size: f.file_size,
        readableSize: f.file_size < 1024 * 1024 ?
          (f.file_size / 1024).toFixed(1) + ' KB' :
          (f.file_size / (1024 * 1024)).toFixed(2) + ' MB',
        method: f.method,
        status: f.status,
        detections: f.detections,
        fudRate: f.fud_rate,
        downloads: f.download_count,
        createdAt: f.created_at
      }))
    });

  } catch (err) {
    console.error('[ANALYTICS] Top files error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get top files'
    });
  }
});

// GET /api/analytics/detection-trend — Detection rate over time
router.get('/detection-trend', authenticate, async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 14;

    const result = await query(
      `SELECT DATE(created_at) as date,
              COUNT(*) as total,
              COUNT(*) FILTER (WHERE detections = 0) as clean
       FROM files
       WHERE user_id = $1
         AND created_at > NOW() - ($2 || ' days')::INTERVAL
         AND status = 'completed'
       GROUP BY DATE(created_at)
       ORDER BY date ASC`,
      [req.user.id, days]
    );

    res.json({
      success: true,
      trend: result.rows.map(r => ({
        date: r.date.toISOString().split('T')[0],
        total: parseInt(r.total),
        clean: parseInt(r.clean),
        detected: parseInt(r.total) - parseInt(r.clean),
        fudRate: parseInt(r.total) > 0 ?
          Math.round((parseInt(r.clean) / parseInt(r.total)) * 100) :
          100
      }))
    });

  } catch (err) {
    console.error('[ANALYTICS] Detection trend error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get detection trend'
    });
  }
});

// GET /api/analytics/files-by-status — File status breakdown
router.get('/files-by-status', authenticate, async (req, res) => {
  try {
    const result = await query(
      `SELECT status, COUNT(*) as count
       FROM files
       WHERE user_id = $1
       GROUP BY status
       ORDER BY count DESC`,
      [req.user.id]
    );

    const statusLabels = {
      uploaded: 'Uploaded',
      processing: 'Processing',
      completed: 'Completed',
      error: 'Error',
      detected: 'Detected'
    };

    res.json({
      success: true,
      statuses: result.rows.map(r => ({
        status: r.status,
        count: parseInt(r.count),
        label: statusLabels[r.status] || r.status
      }))
    });

  } catch (err) {
    console.error('[ANALYTICS] Files by status error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get file status breakdown'
    });
  }
});

// GET /api/analytics/activity-timeline — Recent activity
router.get('/activity-timeline', authenticate, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 15;

    const result = await query(
      `SELECT id, type, message, created_at
       FROM activity
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [req.user.id, limit]
    );

    res.json({
      success: true,
      activities: result.rows.map(a => ({
        id: a.id,
        type: a.type,
        message: a.message,
        time: a.created_at,
        timeAgo: getTimeAgo(a.created_at)
      }))
    });

  } catch (err) {
    console.error('[ANALYTICS] Activity timeline error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get activity timeline'
    });
  }
});

function getTimeAgo(date) {
  const diff = Date.now() - new Date(date).getTime();
  const mins = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);

  if (mins < 1) return 'just now';
  if (mins < 60) return mins + 'm ago';
  if (hours < 24) return hours + 'h ago';
  return days + 'd ago';
}

module.exports = router;
