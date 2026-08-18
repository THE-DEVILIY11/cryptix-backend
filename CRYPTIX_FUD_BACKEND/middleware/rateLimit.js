const rateLimit = require('express-rate-limit');
const db = require('../config/db');
const { query } = db;
require('dotenv').config();

const WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 3600000;

/**
 * Plan-based rate limits for APK crypting
 * Basic:   3 APKs per day
 * Pro:    10 APKs per day
 * Enterprise: 50 APKs per day
 * Lifetime: Unlimited (but capped at 100/day to prevent abuse)
 */
const PLAN_LIMITS = {
  basic:       { perDay: 3,   perHour: 1,   concurrent: 1 },
  pro:         { perDay: 10,  perHour: 3,   concurrent: 2 },
  enterprise:  { perDay: 50,  perHour: 10,  concurrent: 5 },
  lifetime:    { perDay: 100, perHour: 20,  concurrent: 10 },
};

/**
 * Plan-based crypt limiter — checks real DB counts against plan limits
 * This is a dynamic limiter that queries the actual crypt count for the user.
 */
async function cryptLimiter(req, res, next) {
  try {
    // If no user (shouldn't happen after auth), use strict default
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    const plan = req.user.plan || 'basic';
    const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.basic;

    // Check concurrent crypts (those currently processing)
    const concurrencyResult = await query(
      `SELECT COUNT(*) as count FROM files 
       WHERE user_id = $1 AND status = 'processing'`,
      [req.user.id]
    );
    const concurrentCount = parseInt(concurrencyResult.rows[0].count);

    if (concurrentCount >= limits.concurrent) {
      return res.status(429).json({
        success: false,
        error: `Plan limit reached: ${limits.concurrent} concurrent crypt(s) allowed on ${plan} plan. Wait for current processing to finish.`,
        code: 'CONCURRENT_LIMIT_EXCEEDED',
        plan,
        limit: limits.concurrent,
        current: concurrentCount,
        upgradeUrl: '/billing'
      });
    }

    // Check daily crypt count
    const dailyResult = await query(
      `SELECT COUNT(*) as count FROM files 
       WHERE user_id = $1 AND created_at::date = CURRENT_DATE`,
      [req.user.id]
    );
    const dailyCount = parseInt(dailyResult.rows[0].count);

    if (dailyCount >= limits.perDay) {
      return res.status(429).json({
        success: false,
        error: `Daily crypt limit reached: ${limits.perDay} crypt(s) per day allowed on ${plan} plan. Upgrade your plan for higher limits.`,
        code: 'DAILY_LIMIT_EXCEEDED',
        plan,
        limit: limits.perDay,
        current: dailyCount,
        upgradeUrl: '/billing'
      });
    }

    // Check hourly crypt count
    const hourlyResult = await query(
      `SELECT COUNT(*) as count FROM files 
       WHERE user_id = $1 AND created_at > NOW() - INTERVAL '1 hour'`,
      [req.user.id]
    );
    const hourlyCount = parseInt(hourlyResult.rows[0].count);

    if (hourlyCount >= limits.perHour) {
      return res.status(429).json({
        success: false,
        error: `Hourly crypt limit reached: ${limits.perHour} crypt(s) per hour allowed on ${plan} plan. Please wait before submitting another.`,
        code: 'HOURLY_LIMIT_EXCEEDED',
        plan,
        limit: limits.perHour,
        current: hourlyCount,
        upgradeUrl: '/billing'
      });
    }

    // All checks passed
    next();
  } catch (err) {
    console.error('[RATE_LIMIT] Crypt limiter error:', err.message);
    // If DB fails, allow through with a warning
    next();
  }
}

const apiLimiter = rateLimit({
  windowMs: 900000, // 15 minutes
  max: 100, // 100 requests per 15 min — PREVENTS API ABUSE
  message: {
    success: false,
    error: 'Too many API requests',
    code: 'API_RATE_LIMIT'
  }
});

const authLimiter = rateLimit({
  windowMs: 900000,
  max: 10,
  message: {
    success: false,
    error: 'Too many login attempts. Try again in 15 minutes.',
    code: 'AUTH_RATE_LIMIT'
  }
});

module.exports = {
  cryptLimiter,
  apiLimiter,
  authLimiter,
  PLAN_LIMITS
};
