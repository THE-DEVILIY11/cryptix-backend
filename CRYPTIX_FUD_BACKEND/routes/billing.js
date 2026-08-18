const express = require('express');
const {
  v4: uuidv4
} = require('uuid');
const {
  query
} = require('../config/db');
const {
  authenticate
} = require('../middleware/auth');

const router = express.Router();

// Plan definitions
const PLANS = {
  basic: {
    name: 'Basic',
    price: 49,
    duration: 30,
    label: 'Basic — $49/mo'
  },
  pro: {
    name: 'Pro',
    price: 99,
    duration: 90,
    label: 'Pro — $99/90d'
  },
  enterprise: {
    name: 'Enterprise',
    price: 249,
    duration: 180,
    label: 'Enterprise — $249/180d'
  },
  lifetime: {
    name: 'Lifetime',
    price: 499,
    duration: 36500,
    label: 'Lifetime — $499'
  }
};

// GET /api/billing/plans — Available plans
router.get('/plans', (req, res) => {
  res.json({
    success: true,
    plans: Object.entries(PLANS).map(([key, plan]) => ({
      id: key,
      name: plan.name,
      price: plan.price,
      duration: plan.duration,
      label: plan.label,
      features: getPlanFeatures(key)
    }))
  });
});

// GET /api/billing/current — Current subscription info
router.get('/current', authenticate, async (req, res) => {
  try {
    // Get license info
    const licResult = await query(
      `SELECT l.license_key, l.plan, l.duration_days, l.status, 
              l.activated_at, l.expires_at, l.created_at
       FROM licenses l
       WHERE l.license_key = $1`,
      [req.user.license_key]
    );

    const license = licResult.rows[0] || null;

    // Calculate renewal info
    let daysLeft = 0;
    let isExpired = false;
    if (license && license.expires_at) {
      const diff = new Date(license.expires_at) - new Date();
      daysLeft = Math.max(0, Math.ceil(diff / 86400000));
      isExpired = diff <= 0;
    }

    // Get invoice count
    const invResult = await query(
      'SELECT COUNT(*) as count, COALESCE(SUM(amount), 0) as total FROM invoices WHERE user_id = $1 AND status = $2',
      [req.user.id, 'paid']
    );

    res.json({
      success: true,
      subscription: {
        plan: req.user.plan,
        planName: PLANS[req.user.plan]?.name || req.user.plan,
        licenseKey: req.user.license_key,
        status: isExpired ? 'expired' : license?.status || 'active',
        activatedAt: license?.activated_at,
        expiresAt: license?.expires_at,
        daysLeft,
        isExpiring: daysLeft > 0 && daysLeft <= 7,
        features: getPlanFeatures(req.user.plan)
      },
      billing: {
        totalSpent: parseFloat(invResult.rows[0]?.total || 0),
        totalInvoices: parseInt(invResult.rows[0]?.count || 0),
        currency: 'USD'
      }
    });

  } catch (err) {
    console.error('[BILLING] Current error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get billing info'
    });
  }
});

// POST /api/billing/upgrade — Upgrade/downgrade plan
router.post('/upgrade', authenticate, async (req, res) => {
  try {
    const {
      planId
    } = req.body;

    if (!planId || !PLANS[planId]) {
      return res.status(400).json({
        success: false,
        error: 'Invalid plan. Choose: basic, pro, enterprise, or lifetime',
        code: 'INVALID_PLAN'
      });
    }

    const newPlan = PLANS[planId];
    const currentPlan = PLANS[req.user.plan];

    // Generate invoice
    const invoiceNumber = 'INV-' + String(Date.now()).slice(-6) + '-' + Math.floor(Math.random() * 1000);

    await query(
      `INSERT INTO invoices (user_id, invoice_number, amount, currency, status, plan)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [req.user.id, invoiceNumber, newPlan.price, 'USD', 'paid', planId]
    );

    // Generate new license key
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let newKey = 'CRYPT-';
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 4; j++) {
        newKey += chars[Math.floor(Math.random() * chars.length)];
      }
      if (i < 2) newKey += '-';
    }

    // Deactivate old license
    await query(
      "UPDATE licenses SET status = 'replaced' WHERE license_key = $1 AND user_id = $2",
      [req.user.license_key, req.user.id]
    );

    // Create new license
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + newPlan.duration);

    await query(
      `INSERT INTO licenses (license_key, user_id, plan, duration_days, status, activated_at, expires_at)
       VALUES ($1, $2, $3, $4, 'active', NOW(), $5)`,
      [newKey, req.user.id, planId, newPlan.duration, expiresAt]
    );

    // Update user
    await query(
      'UPDATE users SET plan = $1, license_key = $2, updated_at = NOW() WHERE id = $3',
      [planId, newKey, req.user.id]
    );

    // Log activity
    await query(
      'INSERT INTO activity (user_id, type, message) VALUES ($1, $2, $3)',
      [req.user.id, 'billing', 'Plan upgraded from ' + (currentPlan?.name || 'unknown') + ' to ' + newPlan.name + ' — $' + newPlan.price]
    );

    res.json({
      success: true,
      message: 'Upgraded to ' + newPlan.name + ' plan',
      newLicenseKey: newKey,
      plan: {
        id: planId,
        name: newPlan.name,
        price: newPlan.price,
        duration: newPlan.duration + ' days',
        expiresAt: expiresAt
      }
    });

  } catch (err) {
    console.error('[BILLING] Upgrade error:', err);
    res.status(500).json({
      success: false,
      error: 'Upgrade failed',
      code: 'UPGRADE_ERROR'
    });
  }
});

// GET /api/billing/invoices — Invoice history
router.get('/invoices', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const countResult = await query(
      'SELECT COUNT(*) FROM invoices WHERE user_id = $1',
      [req.user.id]
    );
    const total = parseInt(countResult.rows[0].count);

    const result = await query(
      `SELECT id, invoice_number, amount, currency, status, plan, 
              description, paid_at, created_at
       FROM invoices WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.user.id, limit, offset]
    );

    res.json({
      success: true,
      invoices: result.rows.map(inv => ({
        id: inv.invoice_number,
        amount: inv.amount,
        currency: inv.currency,
        status: inv.status,
        plan: inv.plan,
        paidAt: inv.paid_at,
        createdAt: inv.created_at
      })),
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    });

  } catch (err) {
    console.error('[BILLING] Invoices error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to get invoices'
    });
  }
});

// POST /api/billing/cancel — Cancel subscription
router.post('/cancel', authenticate, async (req, res) => {
  try {
    // Deactivate license
    await query(
      "UPDATE licenses SET status = 'cancelled' WHERE license_key = $1 AND user_id = $2",
      [req.user.license_key, req.user.id]
    );

    // Update user
    await query(
      "UPDATE users SET plan = 'basic', status = 'cancelled', updated_at = NOW() WHERE id = $1",
      [req.user.id]
    );

    await query(
      'INSERT INTO activity (user_id, type, message) VALUES ($1, $2, $3)',
      [req.user.id, 'billing', 'Subscription cancelled']
    );

    res.json({
      success: true,
      message: 'Subscription cancelled. Access will end at expiry.'
    });

  } catch (err) {
    console.error('[BILLING] Cancel error:', err);
    res.status(500).json({
      success: false,
      error: 'Cancel failed'
    });
  }
});

// POST /api/billing/payment-method — Add payment method (stub)
router.post('/payment-method', authenticate, async (req, res) => {
  try {
    const {
      type,
      details
    } = req.body;

    // In production this integrates with Stripe
    await query(
      'INSERT INTO activity (user_id, type, message) VALUES ($1, $2, $3)',
      [req.user.id, 'billing', 'Payment method added: ' + (type || 'unknown')]
    );

    res.json({
      success: true,
      message: 'Payment method saved',
      method: {
        type: type || 'credit_card',
        last4: details?.last4 || '****',
        isDefault: true
      }
    });

  } catch (err) {
    console.error('[BILLING] Payment method error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to save payment method'
    });
  }
});

function getPlanFeatures(planId) {
    const features = {
      basic: [
        'Up to 3 APK crypts per day (90/mo)',
        'AES-256 encryption only',
        'Basic support (48h response)',
        '7-day file storage',
        'Standard detection check',
        '1 concurrent crypt at a time'
      ],
      pro: [
        'Up to 10 APK crypts per day (300/mo)',
        'All encryption methods: AES, XOR, Polymorphic',
        'Priority support (12h response)',
        '30-day file storage',
        'Real-time FUD monitoring',
        'Download history',
        '3 concurrent crypts'
      ],
      enterprise: [
        'Up to 50 APK crypts per day (1500/mo)',
        'All encryption methods + Hybrid',
        'Dedicated support (2h response)',
        '90-day file storage',
        'Real-time FUD monitoring',
        'API access',
        'Custom obfuscation rules',
        'Team accounts (up to 5)',
        '5 concurrent crypts',
        'Priority processing queue'
      ],
      lifetime: [
        'Everything in Enterprise',
        'Never expires',
        'Priority 24/7 support',
        'Early access to new methods',
        'Private Telegram group',
        'Custom feature requests',
        'Lifetime updates',
        '10 concurrent crypts'
      ]
    };
    return features[planId] || features.basic;
  }

module.exports = router;
