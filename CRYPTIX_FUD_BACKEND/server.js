const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const {
  apiLimiter
} = require('./middleware/rateLimit');
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const fileRoutes = require('./routes/files');
const cryptRoutes = require('./routes/crypt');
const downloadRoutes = require('./routes/downloads');
const billingRoutes = require('./routes/billing');
const adminRoutes = require('./routes/admin');
const analyticsRoutes = require('./routes/analytics');

const app = express();
const PORT = process.env.PORT || 3000;

// =====================
// MIDDLEWARE
// =====================

// Security hardening
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.tailwindcss.com", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'", process.env.CORS_ORIGIN || '*'],
      frameAncestors: ["'none'"],
      formAction: ["'self'"]
    }
  },
}));

// CORS — restrict to your Netlify domain in production
const allowedOrigins = process.env.NODE_ENV === 'production'
  ? (process.env.CORS_ORIGIN || '').split(',').filter(Boolean)
  : ['*'];

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (curl, mobile apps, etc.)
    if (!origin || allowedOrigins.includes('*')) return callback(null, true);
    if (allowedOrigins.some(a => origin.startsWith(a) || origin.includes(a.replace('https://', '')))) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS. Configure CORS_ORIGIN in .env'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400
}));

// JSON body parser with size limit — PREVENT DOS ATTACKS
app.use(express.json({
  limit: '1mb'
}));
app.use(express.urlencoded({
  extended: true,
  limit: '1mb'
}));

// API rate limiting
app.use('/api/', apiLimiter);

// ⚠️ CRITICAL: Upload directory NOT exposed publicly — files served only via auth
// If you ever add express.static for uploads, REMOVE IT. That's a security hole.
// Remove: app.use('/uploads', express.static(...)) — SECURITY

// Request logging
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    if (process.env.NODE_ENV === 'development') {
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} → ${res.statusCode} (${duration}ms)`);
    }
  });
  next();
});

// =====================
// ROUTES
// =====================

app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    name: 'CRYPTIX FUD Engine',
    version: '3.2.0',
    status: 'online',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/files', fileRoutes);
app.use('/api/crypt', cryptRoutes);
app.use('/api/downloads', downloadRoutes);
app.use('/api/billing', billingRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/analytics', analyticsRoutes);

// =====================
// ERROR HANDLING
// =====================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route not found',
    code: 'NOT_FOUND'
  });
});

app.use((err, req, res, next) => {
  console.error('[SERVER] Error:', err);
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal server error',
    code: err.code || 'INTERNAL_ERROR'
  });
});

// =====================
// START SERVER
// =====================

app.listen(PORT, () => {
  console.log('');
  console.log('🦊 CRYPTIX FUD Engine v3.2');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`  Server:   http://localhost:${PORT}`);
  console.log(`  Health:   http://localhost:${PORT}/api/health`);
  console.log(`  Uploads:  ./uploads`);
  console.log(`  Env:      ${process.env.NODE_ENV || 'development'}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');
});

module.exports = app;
