const express = require('express');
const fs = require('fs');
const path = require('path');
const {
  query
} = require('../config/db');
const {
  authenticate
} = require('../middleware/auth');
const {
  cryptLimiter
} = require('../middleware/rateLimit');
const {
  getCryptedPath,
  getFileSize
} = require('../config/storage');
const cryptWorker = require('../workers/cryptWorker');

const router = express.Router();

/**
 * POST /api/crypt/process
 * Start processing a file through the FUD pipeline
 * This runs the real crypter, obfuscator, signer, and scanner
 */
router.post('/process', authenticate, cryptLimiter, async (req, res) => {
  try {
    const {
      fileId,
      method
    } = req.body;

    if (!fileId) {
      return res.status(400).json({
        success: false,
        error: 'File ID is required',
        code: 'MISSING_FILE_ID'
      });
    }

    const validMethods = ['aes', 'xor', 'polymorphic', 'hybrid'];
    const cryptMethod = (method || 'hybrid').toLowerCase();

    if (!validMethods.includes(cryptMethod)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid method. Use: aes, xor, polymorphic, or hybrid',
        code: 'INVALID_METHOD'
      });
    }

    // Verify file belongs to user and is in a processable state
    const fileResult = await query(
      'SELECT * FROM files WHERE id = $1 AND user_id = $2',
      [fileId, req.user.id]
    );

    if (fileResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'File not found',
        code: 'FILE_NOT_FOUND'
      });
    }

    const file = fileResult.rows[0];

    // Check if already processed or processing
    if (file.status === 'completed' || file.status === 'processing') {
      return res.status(400).json({
        success: false,
        error: 'File is already ' + file.status,
        code: 'FILE_ALREADY_PROCESSED'
      });
    }

    // Verify original file exists on disk
    const storagePath = file.storage_path;
    if (!fs.existsSync(storagePath)) {
      return res.status(500).json({
        success: false,
        error: 'Original file not found on storage. Please re-upload.',
        code: 'STORAGE_MISSING'
      });
    }

    // Update status to processing
    await query(
      "UPDATE files SET status = 'processing', method = $1, updated_at = NOW() WHERE id = $2",
      [cryptMethod, fileId]
    );

    // Log the start of processing
    await query(
      `INSERT INTO activity (user_id, type, message, metadata)
       VALUES ($1, 'info', $2, $3)`,
      [req.user.id, 'Starting crypt: ' + file.original_name + ' (' + cryptMethod + ')',
        JSON.stringify({
          fileId,
          progress: 0
        })
      ]
    );

    // Get remaining crypts for response
    let remaining = null;
    try {
      const dailyResult = await query(
        `SELECT COUNT(*) as count FROM files 
         WHERE user_id = $1 AND created_at::date = CURRENT_DATE`,
        [req.user.id]
      );
      const dailyCount = parseInt(dailyResult.rows[0].count);
      const limits = require('../middleware/rateLimit').PLAN_LIMITS[req.user.plan] || 
                     require('../middleware/rateLimit').PLAN_LIMITS.basic;
      remaining = {
        plan: req.user.plan,
        dailyLimit: limits.perDay,
        dailyUsed: dailyCount,
        dailyRemaining: Math.max(0, limits.perDay - dailyCount),
        concurrentLimit: limits.concurrent
      };
    } catch (e) {}

    // Respond immediately — processing runs synchronously
    // Send back initial response with remaining crypt info
    res.json({
      success: true,
      message: 'Crypt processing started',
      fileId,
      method: cryptMethod,
      status: 'processing',
      originalName: file.original_name,
      fileSize: file.file_size,
      remaining
    });

    // Process asynchronously in the background
    setImmediate(async () => {
      try {
        const result = await cryptWorker.processSync(
          req.user.id,
          fileId,
          cryptMethod,
          file.original_name
        );

        if (result.success) {
          console.log('[Crypt] ✅ Completed:', fileId, result.fudRate + '% FUD');
        } else {
          console.error('[Crypt] ❌ Failed:', fileId, result.error);
        }
      } catch (err) {
        console.error('[Crypt] Async error:', err.message);

        // Mark as error in database
        try {
          await query(
            "UPDATE files SET status = 'error', updated_at = NOW() WHERE id = $1",
            [fileId]
          );
        } catch (dbErr) {
          console.error('[Crypt] DB update error:', dbErr.message);
        }
      }
    });

  } catch (err) {
    console.error('[Crypt] Process error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to start crypt processing',
      code: 'CRYPT_START_ERROR'
    });
  }
});

/**
 * GET /api/crypt/status/:fileId
 * Check the processing status of a file
 */
router.get('/status/:fileId', authenticate, async (req, res) => {
  try {
    // Verify file belongs to user directly from DB
    const fileResult = await query(
      'SELECT id, user_id FROM files WHERE id = $1',
      [req.params.fileId]
    );

    if (fileResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'File not found',
        code: 'FILE_NOT_FOUND'
      });
    }

    if (fileResult.rows[0].user_id !== req.user.id) {
      return res.status(403).json({
        success: false,
        error: 'Access denied',
        code: 'FORBIDDEN'
      });
    }

    const status = await cryptWorker.getStatus(req.params.fileId);

    res.json({
      success: true,
      status: status.status,
      file: {
        id: status.fileId,
        name: status.name,
        originalName: status.originalName,
        method: status.method,
        detections: status.detections,
        fudRate: status.fudRate,
        size: status.size,
        processedAt: status.processedAt,
        createdAt: status.createdAt,
        downloadUrl: status.isComplete ? '/api/downloads/' + status.fileId : null
      },
      progress: {
        percent: status.isComplete ? 100 : 50,
        message: status.isComplete ? 'Complete' : status.status
      }
    });

  } catch (err) {
    console.error('[Crypt] Status error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get status'
    });
  }
});

/**
 * GET /api/crypt/log/:fileId
 * Get the processing log for a file
 */
router.get('/log/:fileId', authenticate, async (req, res) => {
  try {
    // Verify file belongs to user
    const fileResult = await query(
      'SELECT id, user_id FROM files WHERE id = $1',
      [req.params.fileId]
    );

    if (fileResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'File not found'
      });
    }

    if (fileResult.rows[0].user_id !== req.user.id) {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    const logs = await cryptWorker.getLogs(req.params.fileId, req.user.id);

    res.json({
      success: true,
      logs
    });

  } catch (err) {
    console.error('[Crypt] Log error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get log'
    });
  }
});

/**
 * GET /api/crypt/methods
 * List available encryption methods with descriptions
 */
router.get('/methods', (req, res) => {
  res.json({
    success: true,
    methods: [{
        id: 'aes',
        name: 'AES-256',
        icon: '🔐',
        description: 'Standard AES-256-CBC encryption with native decryptor stub',
        complexity: 'Medium',
        fudRate: 'High'
      },
      {
        id: 'xor',
        name: 'XOR + Obfuscation',
        icon: '🌀',
        description: 'Dual-layer XOR encryption with string obfuscation',
        complexity: 'Low',
        fudRate: 'Medium-High'
      },
      {
        id: 'polymorphic',
        name: 'Polymorphic',
        icon: '🧬',
        description: 'Morphing encryption that produces unique output each run',
        complexity: 'High',
        fudRate: 'Very High'
      },
      {
        id: 'hybrid',
        name: 'Hybrid',
        icon: '⚡',
        description: 'Combines AES + XOR + Polymorphic + Anti-debug for maximum protection',
        complexity: 'Very High',
        fudRate: 'Maximum'
      }
    ]
  });
});

module.exports = router;
