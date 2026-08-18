const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
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
  getOriginalPath,
  getCryptedPath,
  getTempPath,
  MAX_FILE_SIZE,
  deleteFile
} = require('../config/storage');

const router = express.Router();

// Multer config
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const tempPath = path.join(__dirname, '..', 'uploads', 'temp');
      if (!fs.existsSync(tempPath)) {
        fs.mkdirSync(tempPath, {
          recursive: true
        });
      }
      cb(null, tempPath);
    },
    filename: (req, file, cb) => {
      cb(null, `${uuidv4()}_${Date.now()}.apk`);
    }
  }),
  limits: {
    fileSize: MAX_FILE_SIZE  // 50MB limit from .env
  },
  fileFilter: (req, file, cb) => {
    if (path.extname(file.originalname).toLowerCase() !== '.apk') {
      return cb(new Error('Only APK files are allowed'), false);
    }
    cb(null, true);
  }
});

// POST /api/files/upload
router.post('/upload', authenticate, (req, res) => {
  upload.single('file')(req, res, async (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({
          success: false,
          error: 'File too large. Maximum 50MB.',
          code: 'FILE_TOO_LARGE'
        });
      }
      return res.status(400).json({
        success: false,
        error: err.message,
        code: 'UPLOAD_ERROR'
      });
    }

    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No file uploaded',
        code: 'NO_FILE'
      });
    }

    try {
      const fileId = uuidv4();
      const tempPath = req.file.path;
      const originalName = req.file.originalname;

      // Calculate file hash
      const fileBuffer = fs.readFileSync(tempPath);
      const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

      // Move to permanent storage
      const permPath = getOriginalPath(req.user.id, fileId);
      const permDir = path.dirname(permPath);
      if (!fs.existsSync(permDir)) {
        fs.mkdirSync(permDir, {
          recursive: true
        });
      }
      fs.renameSync(tempPath, permPath);

      // Insert file record
      const result = await query(
        `INSERT INTO files (id, user_id, original_name, file_size, method, status,
                            storage_path, original_hash, download_count, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, NOW())
         RETURNING id, original_name, file_size, method, status, created_at`,
        [
          fileId,
          req.user.id,
          originalName,
          req.file.size,
          req.body.method || 'hybrid',
          'uploaded',
          permPath,
          hash
        ]
      );

      // Update user storage
      await query(
        'UPDATE users SET storage_used = storage_used + $1 WHERE id = $2',
        [req.file.size, req.user.id]
      );

      // Log activity
      await query(
        'INSERT INTO activity (user_id, type, message) VALUES ($1, $2, $3)',
        [req.user.id, 'upload', `Uploaded: ${originalName} (${(req.file.size / 1024 / 1024).toFixed(2)} MB)`]
      );

      res.json({
        success: true,
        file: {
          id: result.rows[0].id,
          name: result.rows[0].original_name,
          size: result.rows[0].file_size,
          method: result.rows[0].method,
          status: result.rows[0].status,
          createdAt: result.rows[0].created_at,
          hash: hash
        }
      });

    } catch (dbErr) {
      console.error('[FILES] Upload DB error:', dbErr);
      // Clean up temp file
      if (req.file && req.file.path) {
        deleteFile(req.file.path);
      }
      res.status(500).json({
        success: false,
        error: 'Failed to process upload',
        code: 'UPLOAD_DB_ERROR'
      });
    }
  });
});

// GET /api/files — List user's files
router.get('/', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    const status = req.query.status || null;
    const search = req.query.search || null;

    let whereClause = 'WHERE user_id = $1';
    let params = [req.user.id];
    let paramIndex = 2;

    if (status && status !== 'all') {
      whereClause += ` AND status = $${paramIndex}`;
      params.push(status);
      paramIndex++;
    }

    if (search) {
      whereClause += ` AND original_name ILIKE $${paramIndex}`;
      params.push(`%${search}%`);
      paramIndex++;
    }

    const countResult = await query(
      `SELECT COUNT(*) FROM files ${whereClause}`,
      params
    );
    const total = parseInt(countResult.rows[0].count);

    const result = await query(
      `SELECT id, original_name, crypted_name, file_size, method, status,
              detections, fud_rate, download_count, created_at, expires_at, processed_at
       FROM files ${whereClause}
       ORDER BY created_at DESC
       LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`,
      [...params, limit, offset]
    );

    res.json({
      success: true,
      files: result.rows.map(f => ({
        ...f,
        size: f.file_size,
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
    console.error('[FILES] List error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to list files'
    });
  }
});

// GET /api/files/:id — Get single file details
router.get('/:id', authenticate, async (req, res) => {
  try {
    const result = await query(
      'SELECT * FROM files WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'File not found'
      });
    }

    res.json({
      success: true,
      file: result.rows[0]
    });
  } catch (err) {
    console.error('[FILES] Get error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get file'
    });
  }
});

// DELETE /api/files/:id
router.delete('/:id', authenticate, async (req, res) => {
  try {
    const result = await query(
      'SELECT * FROM files WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'File not found'
      });
    }

    const file = result.rows[0];

    // Delete physical files
    deleteFile(file.storage_path);
    if (file.crypted_name) {
      const cryptedPath = getCryptedPath(req.user.id, file.id);
      deleteFile(cryptedPath);
    }

    // Delete from DB
    await query('DELETE FROM files WHERE id = $1', [file.id]);

    // Update storage used
    await query(
      'UPDATE users SET storage_used = GREATEST(0, storage_used - $1) WHERE id = $2',
      [file.file_size, req.user.id]
    );

    await query(
      'INSERT INTO activity (user_id, type, message) VALUES ($1, $2, $3)',
      [req.user.id, 'file', `Deleted: ${file.original_name}`]
    );

    res.json({
      success: true,
      message: 'File deleted'
    });
  } catch (err) {
    console.error('[FILES] Delete error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to delete file'
    });
  }
});

module.exports = router;
