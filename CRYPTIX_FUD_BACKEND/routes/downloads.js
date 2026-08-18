const express = require('express');
const path = require('path');
const fs = require('fs');
const {
  query
} = require('../config/db');
const {
  authenticate
} = require('../middleware/auth');
const {
  getCryptedPath,
  getFileSize
} = require('../config/storage');

const router = express.Router();

// GET /api/downloads/:fileId — Download a crypted file
router.get('/:fileId', authenticate, async (req, res) => {
  try {
    const result = await query(
      `SELECT id, user_id, original_name, crypted_name, file_size, method, 
              status, detections, fud_rate, storage_path, created_at
       FROM files WHERE id = $1 AND user_id = $2`,
      [req.params.fileId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'File not found or access denied',
        code: 'FILE_NOT_FOUND'
      });
    }

    const file = result.rows[0];

    if (file.status !== 'completed') {
      return res.status(400).json({
        success: false,
        error: 'File is not ready yet. Status: ' + file.status,
        code: 'FILE_NOT_READY'
      });
    }

    // Get crypted file path
    const cryptedPath = getCryptedPath(req.user.id, file.id);
    if (!fs.existsSync(cryptedPath)) {
      return res.status(500).json({
        success: false,
        error: 'Crypted file not found on storage',
        code: 'STORAGE_MISSING'
      });
    }

    const downloadName = file.crypted_name || file.original_name.replace('.apk', '_crypted.apk');
    const stat = fs.statSync(cryptedPath);

    // Log download
    await query(
      `INSERT INTO downloads (file_id, user_id, ip_address, user_agent)
       VALUES ($1, $2, $3, $4)`,
      [file.id, req.user.id, req.ip || 'unknown', req.get('User-Agent') || 'unknown']
    );

    // Increment download count
    await query(
      'UPDATE files SET download_count = download_count + 1 WHERE id = $1',
      [file.id]
    );

    // Log activity
    await query(
      'INSERT INTO activity (user_id, type, message) VALUES ($1, $2, $3)',
      [req.user.id, 'download', 'Downloaded: ' + downloadName]
    );

    // Send file
    res.setHeader('Content-Type', 'application/vnd.android.package-archive');
    res.setHeader('Content-Disposition', 'attachment; filename="' + downloadName + '"');
    res.setHeader('Content-Length', stat.size);
    res.setHeader('X-FUD-Rate', file.fud_rate + '%');
    res.setHeader('X-Detections', file.detections);

    const readStream = fs.createReadStream(cryptedPath);
    readStream.pipe(res);

  } catch (err) {
    console.error('[DOWNLOADS] Error:', err);
    res.status(500).json({
      success: false,
      error: 'Download failed',
      code: 'DOWNLOAD_ERROR'
    });
  }
});

// GET /api/downloads/history — Get download history
router.get('/history/list', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const countResult = await query(
      `SELECT COUNT(*) FROM downloads WHERE user_id = $1`,
      [req.user.id]
    );
    const total = parseInt(countResult.rows[0].count);

    const result = await query(
      `SELECT d.id, d.file_id, d.ip_address, d.created_at,
              f.original_name, f.crypted_name, f.file_size, f.method, f.fud_rate
       FROM downloads d
       LEFT JOIN files f ON d.file_id = f.id
       WHERE d.user_id = $1
       ORDER BY d.created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.user.id, limit, offset]
    );

    res.json({
      success: true,
      downloads: result.rows.map(d => ({
        id: d.id,
        fileId: d.file_id,
        fileName: d.crypted_name || d.original_name,
        size: d.file_size,
        method: d.method,
        fudRate: d.fud_rate,
        ip: d.ip_address,
        downloadedAt: d.created_at
      })),
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    });

  } catch (err) {
    console.error('[DOWNLOADS] History error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get download history'
    });
  }
});

// GET /api/downloads/stats — Download statistics
router.get('/stats/summary', authenticate, async (req, res) => {
  try {
    // Total downloads
    const totalResult = await query(
      'SELECT COUNT(*) FROM downloads WHERE user_id = $1',
      [req.user.id]
    );
    const totalDownloads = parseInt(totalResult.rows[0].count);

    // This month
    const monthResult = await query(
      `SELECT COUNT(*) FROM downloads 
       WHERE user_id = $1 
       AND EXTRACT(MONTH FROM created_at) = EXTRACT(MONTH FROM NOW())
       AND EXTRACT(YEAR FROM created_at) = EXTRACT(YEAR FROM NOW())`,
      [req.user.id]
    );
    const thisMonth = parseInt(monthResult.rows[0].count);

    // Latest download
    const latestResult = await query(
      `SELECT MAX(created_at) as latest FROM downloads WHERE user_id = $1`,
      [req.user.id]
    );
    const latest = latestResult.rows[0]?.latest;

    // Top downloaded files
    const topResult = await query(
      `SELECT f.original_name, f.crypted_name, COUNT(d.id) as dl_count
       FROM downloads d
       JOIN files f ON d.file_id = f.id
       WHERE d.user_id = $1
       GROUP BY f.id, f.original_name, f.crypted_name
       ORDER BY dl_count DESC
       LIMIT 5`,
      [req.user.id]
    );

    res.json({
      success: true,
      stats: {
        totalDownloads,
        thisMonth,
        latestDownload: latest,
        topFiles: topResult.rows.map(f => ({
          name: f.crypted_name || f.original_name,
          downloads: parseInt(f.dl_count)
        }))
      }
    });

  } catch (err) {
    console.error('[DOWNLOADS] Stats error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get download stats'
    });
  }
});

module.exports = router;
