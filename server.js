require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const Tesseract = require('tesseract.js');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const sharp = require('sharp');
// RAW body parser for Stripe
const bodyParser = require('body-parser');

const JWT_SECRET = 'super-secret-snap2excel-key-change-later'; // later we move to env var
const TINK_CLIENT_ID = process.env.TINK_CLIENT_ID;
const TINK_CLIENT_SECRET = process.env.TINK_CLIENT_SECRET;

const TINK_REDIRECT_URI = process.env.TINK_REDIRECT_URI;

const app = express();
app.use(cors());

app.use(cors({
  origin: [ 'https://snap2excel.com', 'http://localhost:3000' ],
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  credentials: true,
}));

// Stripe webhook MUST be before express.json
app.post(
  '/api/stripe/webhook',
  bodyParser.raw({ type: 'application/json' }),
  (req, res) => {
    const sig = req.headers['stripe-signature'];

    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error('Webhook signature verify failed:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const userId = Number(session.metadata?.user_id || 0);
        const planType = session.metadata?.plan_type || 'free';

        if (userId) {
          db.run(
            `UPDATE users
             SET plan_type = ?,
                 subscription_status = 'active'
             WHERE id = ?`,
            [planType, userId],
            (err) => {
              if (err) console.error('Webhook plan update error:', err);
            }
          );
        }
        break;
      }

      case 'customer.subscription.updated':
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        const customerId = sub.customer;

        db.run(
          `UPDATE users
           SET subscription_status = ?,
               stripe_subscription_id = ?
           WHERE stripe_customer_id = ?`,
          [sub.status, sub.id, customerId],
          (err) => {
            if (err) console.error('Webhook sub update error:', err);
          }
        );
        break;
      }
    }

    res.json({ received: true });
  }
);

app.use(express.json());
// Profile avatars
app.use('/profile-uploads', express.static('profile_uploads'));

// Receipt images
app.use('/uploads', express.static('uploads'));

const db = new sqlite3.Database('./receipts.db');

// Create users table
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
  )
`);

// Add extra profile fields if they don't exist
db.run(`ALTER TABLE users ADD COLUMN plan_type TEXT DEFAULT 'free'`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding plan_type column:', err.message);
  }
});

db.run(`ALTER TABLE users ADD COLUMN billing_info TEXT`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding billing_info column:', err.message);
  }
});

db.run(`ALTER TABLE users ADD COLUMN profile_photo TEXT`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding profile_photo column:', err.message);
  }
});

db.run(`ALTER TABLE users ADD COLUMN job_title TEXT`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding job_title column:', err.message);
  }
});

db.run(`ALTER TABLE users ADD COLUMN weekly_price REAL DEFAULT 0.99`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding weekly_price column:', err.message);
  }
});

db.run(`ALTER TABLE users ADD COLUMN stripe_customer_id TEXT`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding stripe_customer_id:', err.message);
  }
});

db.run(`ALTER TABLE users ADD COLUMN stripe_subscription_id TEXT`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding stripe_subscription_id:', err.message);
  }
});

db.run(`ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding is_admin column:', err.message);
  }
});

db.run(`ALTER TABLE users ADD COLUMN banned INTEGER DEFAULT 0`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding banned column:', err.message);
  }
});

db.run(`ALTER TABLE users ADD COLUMN credits REAL DEFAULT 0`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding credits column:', err.message);
  }
});

db.run(`ALTER TABLE users ADD COLUMN subscription_status TEXT DEFAULT 'none'`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding subscription_status column:', err.message);
  }
});

db.run(`ALTER TABLE users ADD COLUMN full_name TEXT`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding full_name column:', err.message);
  }
});

db.run(`ALTER TABLE users ADD COLUMN account_type TEXT DEFAULT 'personal'`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding account_type column:', err.message);
  }
});

db.run(`ALTER TABLE users ADD COLUMN business_name TEXT`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding business_name column:', err.message);
  }
});

db.run(`ALTER TABLE users ADD COLUMN country TEXT`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding country column:', err.message);
  }
});

db.run(`ALTER TABLE users ADD COLUMN city TEXT`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding city column:', err.message);
  }
});

db.run(`ALTER TABLE users ADD COLUMN role TEXT`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding role column:', err.message);
  }
});

db.run(`ALTER TABLE users ADD COLUMN usage_mode TEXT DEFAULT 'personal_budget'`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding usage_mode column:', err.message);
  }
});

// Create receipts table (if not exists)
db.run(`
  CREATE TABLE IF NOT EXISTS receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shop TEXT,
    date TEXT,
    total REAL,
    vat REAL,
    raw_text TEXT,
    user_id INTEGER,
    category TEXT,
    enhanced INTEGER DEFAULT 0,
    image_path TEXT          -- 👈 NEW: filename of the original photo
  )
`);

db.run(`ALTER TABLE users ADD COLUMN date_of_birth TEXT`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding date_of_birth column:', err.message);
  }
});

db.run(`ALTER TABLE users ADD COLUMN experience_mode TEXT DEFAULT 'adult'`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding experience_mode column:', err.message);
  }
});

// Personal finance settings (one row per user)
db.run(`
  CREATE TABLE IF NOT EXISTS user_finance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE,
    income_amount REAL,
    income_frequency TEXT, -- 'weekly' or 'monthly'
    bills_json TEXT,       -- JSON array of { name, amount, frequency }
    FOREIGN KEY(user_id) REFERENCES users(id)
  )
`);


// ---- Multer upload config ----
const upload = multer({ dest: 'uploads/' });

// ---- OCR parsing helpers ----

function cleanLines(text) {
  return text
    .split('\n')
    .map(l => l.replace(/\s+/g, ' ').trim())
    .filter(l => l.length > 0);
}

function isMostlyDigits(str) {
  const digits = (str.match(/[0-9]/g) || []).length;
  return digits > 0 && digits / str.length > 0.5;
}

function isLikelyShopName(line) {
  const lower = line.toLowerCase();

  // ignore lines that clearly look like meta
  if (lower.includes('receipt')) return false;
  if (lower.includes('invoice')) return false;
  if (lower.includes('tax')) return false;
  if (lower.includes('vat')) return false;
  if (lower.includes('total')) return false;
  if (lower.includes('subtotal')) return false;
  if (lower.includes('amount due')) return false;

  // must contain at least one letter
  if (!/[a-zA-Z]/.test(line)) return false;

  // avoid lines that are mostly digits
  if (isMostlyDigits(line)) return false;

  return true;
}

function cleanShopString(line) {
  return line
    .replace(/[<>]/g, '')        // remove weird bracket chars
    .replace(/\s{2,}/g, ' ')     // collapse double spaces
    .trim();
}

function findShopName(text) {
  // Use the cleaned lines helper we already have
  const lines = cleanLines(text); // collapses spaces + removes blanks

  // Only look at the first N lines – header area
  const headerLines = lines.slice(0, 10);

  const footerBadWords = [
    'thank you',
    'shopping',
    'please keep',
    'receipt',
    'invoice',
    'tax invoice',
    'vat invoice',
  ];

  const knownStores = [
    'Tesco', 'Asda', 'Aldi', 'Lidl', 'Morrisons', 'Coop', 'Co-op', 'Boots',
    'Sainsbury', 'Costa', 'Starbucks', 'McDonalds', 'KFC', 'Burger King',
    'Dominos', 'Subway', 'Primark', 'Ikea', 'B&M', 'Wilko', 'Home Bargains',
    'Supermart' // our test one
  ];

  // 1) Exact brand match in header
  for (const line of headerLines) {
    const lower = line.toLowerCase();
    for (const store of knownStores) {
      if (lower.includes(store.toLowerCase())) {
        return store;
      }
    }
  }

  // 2) First line in the header that "looks like" a shop name
  for (const line of headerLines) {
    if (isLikelyShopName(line)) {
      return cleanShopString(line);
    }
  }

  // 3) Fallback: any line with letters that is NOT a footer / thank-you text
  for (const line of lines) {
    const clean = cleanShopString(line);
    const lower = clean.toLowerCase();

    if (!/[a-zA-Z]/.test(clean)) continue; // must have letters

    if (footerBadWords.some((w) => lower.includes(w))) {
      continue; // skip "THANK YOU FOR SHOPPING", "RECEIPT" etc.
    }

    if (clean.length >= 3 && clean.length <= 40) {
      return clean;
    }
  }

  // 4) Last resort
  return 'Unknown shop';
}


function findDate(text) {
  // Handle common UK/EU/ISO patterns
  const patterns = [
    /(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})/,     // 20/04/2024, 20-04-24, 20.04.2024
    /(\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2})/,       // 2024-04-20
  ];

  for (const p of patterns) {
    const match = text.match(p);
    if (match) return match[1];
  }

  return null;
}

function extractAmountsFromLine(line) {
  const matches = [];
  const regex = /£\s*([\d.,]+)|\b([\d]{1,4}[.,]\d{2})\b/g;
  let m;
  while ((m = regex.exec(line)) !== null) {
    const numStr = (m[1] || m[2]).replace(',', '.');
    const val = parseFloat(numStr);
    if (!isNaN(val)) matches.push(val);
  }
  return matches;
}

function findAllAmounts(text) {
  const amounts = [];
  const lines = cleanLines(text);
  lines.forEach(line => {
    extractAmountsFromLine(line).forEach(val => amounts.push({ line, val }));
  });
  return amounts;
}

function findTotalAmount(text) {
  const lowerText = text.toLowerCase();
  const lines = cleanLines(text);

  const totalKeywords = [
    'grand total',
    'amount due',
    'amount payable',
    'balance to pay',
    'total to pay',
    'total',
    'card payment',
    'cash payment'
  ];

  let best = null;

  // 1) Look for lines with total-related keywords
  for (const line of lines) {
    const lower = line.toLowerCase();
    if (totalKeywords.some(k => lower.includes(k))) {
      const nums = extractAmountsFromLine(line);
      if (nums.length > 0) {
        const candidate = nums[nums.length - 1]; // usually last amount on that line
        if (best === null || candidate > best) best = candidate;
      }
    }
  }

  // 2) Fallback: take the largest amount on the whole receipt
  if (best === null) {
    const amounts = findAllAmounts(text);
    if (amounts.length > 0) {
      best = amounts.reduce((max, a) => (a.val > max ? a.val : max), amounts[0].val);
    }
  }

  return best;
}

function findVatAmount(text, total) {
  const lines = cleanLines(text);
  let best = null;

  for (const line of lines) {
    const lower = line.toLowerCase();
    if (lower.includes('vat') || lower.includes('tax')) {
      const nums = extractAmountsFromLine(line);
      // prefer currency-like numbers under, say, 30% of total if we know it
      nums.forEach(val => {
        if (total && total > 0) {
          const ratio = val / total;
          if (ratio > 0.01 && ratio < 0.3) {
            // looks like a VAT amount, not a percentage
            if (best === null || val > best) best = val;
          }
        } else {
          // no total yet, just pick the biggest currency-like amount on VAT lines
          if (best === null || val > best) best = val;
        }
      });
    }
  }

  return best;
}

function parseReceiptText(text) {
  const shop = findShopName(text);
  const date = findDate(text);
  const total = findTotalAmount(text);
  const vat = findVatAmount(text, total || 0);
function guessCategory(shop) {
  const s = shop.toLowerCase();

  if (s.includes('tesco') || s.includes('sains') || s.includes('aldi') || s.includes('lidl'))
    return 'Groceries';

  if (s.includes('amazon')) return 'Shopping';
  if (s.includes('b&q') || s.includes('screwfix')) return 'DIY';
  if (s.includes('uber') || s.includes('deliveroo') || s.includes('just eat'))
    return 'Food Delivery';
  if (s.includes('boots') || s.includes('superdrug')) return 'Pharmacy';
  if (s.includes('bp') || s.includes('shell') || s.includes('esso'))
    return 'Fuel';
  if (s.includes('ikea')) return 'Home';
  if (s.includes('argos')) return 'Retail';

  return 'Other';
}

  return {
    shop,
    date,
    total: total || null,
    vat: vat || null,
    category: guessCategory(shop)
  };
}

// Normalize a date string to "YYYY-MM" for grouping
function normalizeMonth(dateStr) {
  if (!dateStr) return 'unknown';

  const m = String(dateStr).match(/(\d{1,4})[\/\-\.](\d{1,2})[\/\-\.](\d{1,4})/);
  if (!m) return 'unknown';

  let a = parseInt(m[1], 10);
  let b = parseInt(m[2], 10);
  let c = parseInt(m[3], 10);

  let year, month;

  // Try to guess which part is the year
  if (a > 1900) {
    year = a;
    month = b;
  } else if (c > 1900) {
    year = c;
    month = b;
  } else {
    // fallback: treat last as year
    year = c < 100 ? 2000 + c : c;
    month = b;
  }

  if (!month || month < 1 || month > 12) return 'unknown';

  return `${year}-${String(month).padStart(2, '0')}`;
}

function requirePro(req, res) {
  if (!req.user || req.user.plan_type === 'free') {
    return res.status(403).json({
      error: 'This feature is for Pro users. Upgrade in your profile to unlock it.',
    });
  }
  return null;
}

// ---- Auth routes ----

// Register new user
app.post('/api/register', async (req, res) => {
   try {
    const {
      full_name,
      email,
      password,
      account_type,
      business_name,
      country,
      city,
      role,
      usage_mode,
      date_of_birth,
    } = req.body;

    if (!full_name || !email || !password || !account_type) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

        // decide safe account_type + usage_mode
    // we only trust specific values from frontend
    let safeAccountType;
    let safeUsageMode;

    if (account_type === 'business') {
      // business owner account (future multi-user)
      safeAccountType = 'business';
      safeUsageMode = 'business_owner';
    } else {
      // default: personal profile
      safeAccountType = 'personal';

      if (usage_mode === 'self_employed') {
        safeUsageMode = 'self_employed';
      } else {
        // student / personal budgeting
        safeUsageMode = 'personal_budget';
      }
    }

    // --- AUTO EXPERIENCE MODE ---
// calculate age from DOB
let experience_mode = 'adult';
if (date_of_birth) {
  const year = parseInt(date_of_birth.split('-')[0]);
  const currentYear = new Date().getFullYear();
  const age = currentYear - year;
  if (age <= 25) experience_mode = 'youth';
}

    // Check if user exists
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (row) {
        return res.status(400).json({ error: 'Email already registered' });
      }

      const saltRounds = 10;
      const hash = await bcrypt.hash(password, saltRounds);

      // inside your /api/register route, where you currently have db.run(...)
db.run(
  `INSERT INTO users
    (full_name,
     email,
     password_hash,
     account_type,
     business_name,
     country,
     city,
     role,
     plan_type,
     is_admin,
     usage_mode,
     date_of_birth,
     experience_mode)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  [
    full_name,
    email,
    hash,
    safeAccountType,
    business_name || null,
    country || null,
    city || null,
    role || null,
    'free', // plan_type
    0, // is_admin
    safeUsageMode,
    date_of_birth || null,
    experience_mode
  ],
  function (err2) {
    if (err2) {
      console.error('REGISTER INSERT ERROR:', err2);
      return res.status(500).json({ error: 'Failed to create user', detail: err2.message });
    }

    const userId = this.lastID;
    // return both token and user id for frontend verification
    const token = jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '7d' });

    console.log(`New user created: id=${userId} email=${email}`);
    return res.json({ token, userId });
  }
);

    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});


app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};

  console.log('LOGIN attempt:', email); // debug

  if (!email || !password) {
    return res.status(400).json({ error: 'Missing email or password' });
  }

  // 🔹 1) DEMO GUEST ACCOUNT – works even with empty DB
  if (
    email === 'guest@snap2excel.com' &&
    password === 'guest-demo'
  ) {
    console.log('Guest demo login OK');

    const token = jwt.sign(
      {
        id: -1,
        email,
        name: 'Guest',
        plan: 'personal',
        is_admin: 0,
      },
      SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      token,
      user: {
        id: -1,
        email,
        name: 'Guest',
        plan: 'personal',
        is_admin: 0,
      },
    });
  }

  // 🔹 2) NORMAL USER LOGIN (DB)
  const sql =
    'SELECT id, email, name, password_hash, plan, is_admin FROM users WHERE email = ?';

  db.get(sql, [email.toLowerCase()], (err, user) => {
    if (err) {
      console.error('DB error on login', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user) {
      console.log('No user found for', email);
      return res.status(400).json({ error: 'Wrong email or password' });
    }

    bcrypt.compare(password, user.password_hash, (err2, same) => {
      if (err2) {
        console.error('bcrypt error', err2);
        return res.status(500).json({ error: 'Password check failed' });
      }

      if (!same) {
        console.log('Bad password for', email);
        return res.status(400).json({ error: 'Wrong email or password' });
      }

      const token = jwt.sign(
        {
          id: user.id,
          email: user.email,
          name: user.name,
          plan: user.plan || 'personal',
          is_admin: user.is_admin || 0,
        },
        SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          plan: user.plan || 'personal',
          is_admin: user.is_admin || 0,
        },
      });
    });
  });
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  let token = authHeader && authHeader.split(' ')[1]; // "Bearer <token>"

  // Allow token via query string for downloads like CSV
  if (!token && req.query && req.query.token) {
    token = req.query.token;
  }

  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) {
      console.error('JWT error:', err);
      return res.status(403).json({ error: 'Invalid token' });
    }

    // payload = { id, email }
db.get(
    `SELECT
     id,
     email,
     full_name,
     account_type,
     business_name,
     country,
     city,
     role,
     plan_type,
     billing_info,
     profile_photo,
     is_admin,
     job_title,
     weekly_price,
     stripe_customer_id,
     stripe_subscription_id,
     banned,
     credits,
     subscription_status,
     usage_mode,
     date_of_birth,
     experience_mode
   FROM users
   WHERE id = ?`,

  [payload.id],
  (dbErr, row) => {

      if (dbErr) {
        console.error('Auth DB error:', dbErr);
        return res.status(500).json({ error: 'DB error' });
      }
      if (!row) {
        return res.status(401).json({ error: 'User not found' });
      }
            if (row.banned) {
        return res.status(403).json({ error: 'Account disabled. Please contact support.' });
      }

      req.user = row; // { id, email, plan_type, billing_info, profile_photo }
      next();
    });
  });
}

// ---- ADMIN ROUTES ----
// High-level product/ revenue summary for admin
app.get('/api/admin/summary', authenticateToken, requireAdmin, (req, res) => {
  // First: user counts (total, pro, free)
  const userSql = `
    SELECT
      COUNT(*) AS total_users,
      SUM(CASE WHEN plan_type IS NOT NULL AND plan_type != 'free' THEN 1 ELSE 0 END) AS pro_users
    FROM users
  `;

  db.get(userSql, [], (err, userRow) => {
    if (err) {
      console.error('Admin summary user error:', err);
      return res.status(500).json({ error: 'DB error' });
    }

    const totalUsers = userRow?.total_users || 0;
    const proUsers = userRow?.pro_users || 0;
    const freeUsers = totalUsers - proUsers;

    // Second: receipts summary
    const receiptsSql = `
      SELECT
        COUNT(*) AS total_receipts,
        COALESCE(SUM(total), 0) AS total_spend
      FROM receipts
    `;

    db.get(receiptsSql, [], (err2, recRow) => {
      if (err2) {
        console.error('Admin summary receipts error:', err2);
        return res.status(500).json({ error: 'DB error' });
      }

      const totalReceipts = recRow?.total_receipts || 0;
      const totalSpend = recRow?.total_spend || 0;

      // Third: estimated weekly MRR (sum of weekly_price for non-free plans)
      const mrrSql = `
        SELECT COALESCE(SUM(weekly_price), 0) AS weekly_mrr
        FROM users
        WHERE plan_type IS NOT NULL
          AND plan_type != 'free'
      `;

      db.get(mrrSql, [], (err3, mrrRow) => {
        if (err3) {
          console.error('Admin summary MRR error:', err3);
          return res.status(500).json({ error: 'DB error' });
        }

        res.json({
          total_users: totalUsers,
          pro_users: proUsers,
          free_users: freeUsers,
          total_receipts: totalReceipts,
          total_spend: totalSpend,
          weekly_mrr: mrrRow?.weekly_mrr || 0,
        });
      });
    });
  });
});

// List users + their receipts & total spend
app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
  const sql = `
    SELECT
      u.id,
      u.email,
      u.plan_type,
      u.credits,
      u.subscription_status,
      u.is_admin,
      u.banned,
      u.weekly_price,
      COUNT(r.id) AS receipt_count,
      COALESCE(SUM(r.total), 0) AS total_spend
    FROM users u
    LEFT JOIN receipts r
      ON r.user_id = u.id
    GROUP BY u.id
    ORDER BY u.id ASC
  `;

  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error('Admin users error:', err);
      return res.status(500).json({ error: 'DB error' });
    }
    res.json(rows || []);
  });
});

// Change a user's plan or admin flag
app.post('/api/admin/users/:id/plan', authenticateToken, requireAdmin, (req, res) => {
  const userId = req.params.id;
  const { plan_type, is_admin } = req.body; // plan_type like 'free' | 'weekly_099' | 'weekly_149'

  db.run(
    `UPDATE users
     SET plan_type = COALESCE(?, plan_type),
         is_admin = COALESCE(?, is_admin)
     WHERE id = ?`,
    [plan_type || null, typeof is_admin === 'number' ? is_admin : null, userId],
    function (err) {
      if (err) {
        console.error('Admin update user error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      res.json({ success: true });
    }
  );
});

// Delete a user and all their receipts
app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, (req, res) => {
  const userId = req.params.id;

  db.run(`DELETE FROM receipts WHERE user_id = ?`, [userId], function (err) {
    if (err) {
      console.error('Admin delete receipts error:', err);
      return res.status(500).json({ error: 'DB error' });
    }

    db.run(`DELETE FROM users WHERE id = ?`, [userId], function (err2) {
      if (err2) {
        console.error('Admin delete user error:', err2);
        return res.status(500).json({ error: 'DB error' });
      }
      res.json({ success: true });
    });
  });
});

app.get('/api/admin/users/:id/receipts', authenticateToken, requireAdmin, (req, res) => {
  const userId = req.params.id;

  db.all(
    `SELECT * FROM receipts WHERE user_id = ? ORDER BY id DESC`,
    [userId],
    (err, rows) => {
      if (err) {
        console.error('Admin user receipts error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      res.json(rows);
    }
  );
});

app.post('/api/admin/users/:id/ban', authenticateToken, requireAdmin, (req, res) => {
  const userId = req.params.id;
  const { banned } = req.body; // 0 or 1

  db.run(
    `UPDATE users SET banned = ? WHERE id = ?`,
    [banned ? 1 : 0, userId],
    function (err) {
      if (err) {
        console.error('Admin ban user error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      res.json({ success: true });
    }
  );
});

app.post('/api/admin/users/:id/credits', authenticateToken, requireAdmin, (req, res) => {
  const userId = req.params.id;
  const { delta } = req.body; // can be positive or negative

  if (typeof delta !== 'number') {
    return res.status(400).json({ error: 'delta (number) required' });
  }

  db.run(
    `UPDATE users
     SET credits = IFNULL(credits, 0) + ?
     WHERE id = ?`,
    [delta, userId],
    function (err) {
      if (err) {
        console.error('Admin credits error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      res.json({ success: true });
    }
  );
});

app.post('/api/admin/users/:id/reset-password', authenticateToken, requireAdmin, async (req, res) => {
  const userId = req.params.id;
  const { newPassword } = req.body;

  const passwordToSet =
    newPassword && newPassword.length >= 6
      ? newPassword
      : Math.random().toString(36).slice(-10); // random 10-char password

  try {
    const newHash = await bcrypt.hash(passwordToSet, 10);

    db.run(
      `UPDATE users SET password_hash = ? WHERE id = ?`,
      [newHash, userId],
      function (err) {
        if (err) {
          console.error('Admin reset password error:', err);
          return res.status(500).json({ error: 'DB error' });
        }
        if (this.changes === 0) {
          return res.status(404).json({ error: 'User not found' });
        }
        // Return plain password so you can tell the user manually
        res.json({ success: true, newPassword: passwordToSet });
      }
    );
  } catch (err) {
    console.error('Admin reset password hash error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/analytics', authenticateToken, requireAdmin, (req, res) => {
  const result = {};

  db.all(
    `SELECT date, COUNT(*) AS count, IFNULL(SUM(total),0) AS total
     FROM receipts
     GROUP BY date
     ORDER BY date ASC`,
    [],
    (err, rows) => {
      if (err) {
        console.error('Admin analytics error:', err);
        return res.status(500).json({ error: 'DB error' });
      }

      result.byDate = rows;

      db.get(
        `SELECT COUNT(DISTINCT user_id) AS active_users FROM receipts`,
        [],
        (err2, row2) => {
          if (err2) {
            console.error('Admin analytics active users error:', err2);
            return res.status(500).json({ error: 'DB error' });
          }

          result.active_users = row2.active_users;
          res.json(result);
        }
      );
    }
  );
});

async function mlCorrectReceipt(parsed, fullText) {
  // If no API key, just skip ML correction
  if (!process.env.OPENAI_API_KEY) {
    console.warn('ML correction skipped: OPENAI_API_KEY not set');
    return null;
  }

  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
      },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        response_format: { type: 'json_object' },
        messages: [
          {
            role: 'system',
            content:
              'You are an assistant that cleans up noisy OCR from receipts. ' +
              'You must return a STRICT JSON object with fields: shop, date, total, vat. ' +
              'Total and vat must be numbers in pounds (use dot decimal). Date in format MM/DD/YYYY if possible.',
          },
          {
            role: 'user',
            content:
              'Here is noisy OCR text from a receipt. Fix it and extract the key fields.\n\n' +
              'OCR_TEXT:\n' +
              fullText +
              '\n\n' +
              'CURRENT_PARSED_JSON:\n' +
              JSON.stringify(parsed),
          },
        ],
      }),
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => '');
      console.error('ML correction HTTP error:', response.status, errText);
      return null;
    }

    const data = await response.json();
    let content = data.choices?.[0]?.message?.content || '{}';

    let ml;
    try {
      ml = JSON.parse(content);
    } catch (e) {
      // Sometimes the model already returns JSON, sometimes stringified JSON.
      ml = content;
    }

    if (!ml || typeof ml !== 'object') return null;

    const cleaned = {
      shop: ml.shop || parsed.shop || null,
      date: ml.date || parsed.date || null,
      total:
        typeof ml.total === 'number'
          ? ml.total
          : ml.total
          ? Number(String(ml.total).replace(',', '.'))
          : parsed.total || null,
      vat:
        typeof ml.vat === 'number'
          ? ml.vat
          : ml.vat
          ? Number(String(ml.vat).replace(',', '.'))
          : parsed.vat || null,
    };

    return cleaned;
  } catch (err) {
    console.error('ML correction error:', err);
    return null;
  }
}

// Last Stripe events (simple log preview)
app.get('/api/admin/stripe/events', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const events = await stripe.events.list({ limit: 20 });
    const simplified = events.data.map((e) => ({
      id: e.id,
      type: e.type,
      created: e.created,
      livemode: e.livemode,
    }));
    res.json(simplified);
  } catch (err) {
    console.error('Admin stripe events error:', err);
    res.status(500).json({ error: 'Stripe error' });
  }
});

// Active subscriptions
app.get('/api/admin/stripe/subscriptions', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const subs = await stripe.subscriptions.list({ limit: 50 });
    const simplified = subs.data.map((s) => ({
      id: s.id,
      status: s.status,
      customer: s.customer,
      current_period_end: s.current_period_end,
      amount: s.items.data[0]?.price?.unit_amount || 0,
      currency: s.items.data[0]?.price?.currency || 'gbp',
    }));
    res.json(simplified);
  } catch (err) {
    console.error('Admin stripe subscriptions error:', err);
    res.status(500).json({ error: 'Stripe error' });
  }
});

async function preprocessForOcr(srcPath) {
  const processedPath = `${srcPath}-ocr.png`;

  // Resize, grayscale, normalize contrast, auto-rotate
  await sharp(srcPath)
    .rotate() // use EXIF orientation
    .resize(1800, null, { fit: 'inside' }) // keep it big enough but not huge
    .grayscale()
    .normalize()
    .toFile(processedPath);

  return processedPath;
}

app.post('/api/scan-receipt',
  authenticateToken,
  upload.single('receipt'),
  (req, res) => {
    const filePath = req.file.path;
    const mime = req.file.mimetype;
    const ext = path.extname(req.file.originalname || '').toLowerCase();
    const imageFileName = path.basename(filePath); // now filePath exists ✅

    const FREE_RECEIPT_LIMIT = 50;
    
    async function processFile() {
      let ocrPath = filePath;
      let processedPath = null;

      try {
        const isPdf = mime === 'application/pdf' || ext === '.pdf';
        const isHeic = mime === 'image/heic' || mime === 'image/heif' || ext === '.heic' || ext === '.heif';

        if (isPdf) {
          return res.status(400).json({ error: "PDF not supported" });
        }

        if (isHeic) {
          return res.status(400).json({ error: "HEIC blocked – please screenshot" });
        }

        const allowedImageTypes = ['image/jpeg', 'image/jpg', 'image/png'];
        if (!allowedImageTypes.includes(mime)) {
          return res.status(400).json({ error: 'Unsupported image type' });
        }

        // Preprocessing
        try {
          processedPath = await preprocessForOcr(filePath);
          ocrPath = processedPath;
        } catch (err) {
          console.error('Preprocess failed, using original:', err);
        }

        // Initial OCR pass
        const result = await Tesseract.recognize(ocrPath, 'eng', {
          tessedit_char_whitelist: '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz£.:/-, ',
          tessedit_pageseg_mode: 6,
        });

        const text = result.data.text || '';
        if (!text.trim()) {
          return res.status(400).json({ error: "Unreadable image" });
        }

        const parsed = parseReceiptText(text);

        db.run(
          `INSERT INTO receipts (shop, date, total, vat, raw_text, user_id, category, enhanced)
           VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
          [
            parsed.shop,
            parsed.date,
            parsed.total,
            parsed.vat,
            text,
            req.user.id,
            parsed.category,
          ],
          function (err) {
            if (err) {
              console.error(err);
              return res.status(500).json({ error: "DB write error" });
            }

            const receiptId = this.lastID;

            // --- Save original image for later viewing ---
            const userDir = path.join('uploads', 'receipts', String(req.user.id));
            const imageExt = ext || '.jpg';
            const relativeImagePath = path.join(
              'receipts',
              String(req.user.id),
              `${receiptId}${imageExt}`
            );
            const absoluteImagePath = path.join('uploads', relativeImagePath);

            fs.mkdir(userDir, { recursive: true }, (mkErr) => {
              if (mkErr) {
                console.error('Failed to create user receipts dir:', mkErr);
              } else {
                fs.copyFile(filePath, absoluteImagePath, (cpErr) => {
                  if (cpErr) {
                    console.error('Failed to copy receipt image:', cpErr);
                  } else {
                    db.run(
                      `UPDATE receipts SET image_path = ? WHERE id = ?`,
                      [relativeImagePath, receiptId],
                      (upErr) => {
                        if (upErr) {
                          console.error('Failed to save image_path:', upErr);
                        }
                      }
                    );
                  }
                });
              }
            });

            // === Immediate response to user ===
            res.json({
              id: receiptId,
              ...parsed,
              raw_text: text,
              enhanced: 0,
            });

            // === Background Enhanced Scan ===
            setTimeout(() => {
              runEnhancedScan(receiptId, filePath).catch((err) =>
                console.error('Enhanced scan failed:', err)
              );
            }, 200);
          }
        );


      } catch (err) {
        console.error('scan-receipt error:', err);
        return res.status(500).json({ error: "OCR failed" });
      }
    }

    if (req.user.plan_type === 'free') {
      db.get(`SELECT COUNT(*) AS cnt FROM receipts WHERE user_id = ?`, [req.user.id], (err, row) => {
        if (err) return res.status(500).json({ error: "DB error" });

        if (row && row.cnt >= FREE_RECEIPT_LIMIT) {
          return res.status(403).json({ error: "Free plan limit reached" });
        }

        processFile(); // allowed
      });
    } else {
      processFile();
    }
  }
);


async function runEnhancedScan(receiptId, originalPath) {
  try {
    const enhancedPath = `${originalPath}-enhanced.png`;

    // Advanced preprocessing (local, no AI)
    await sharp(originalPath)
      .grayscale()
      .normalize()   // or .normalise(), both are fine in sharp
      .sharpen()
      .resize(2100)  // HQ OCR size
      .toFile(enhancedPath);

    // Second OCR pass on the enhanced image
    const result = await Tesseract.recognize(enhancedPath, 'eng', {
      tessedit_char_whitelist:
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789£:.%/- ',
      tessedit_pageseg_mode: 6,
    });

    const improvedText = (result.data.text || '').trim();
    const improved = parseReceiptText(improvedText); // your existing parser

    // Compare with what we already have in the DB
    db.get('SELECT * FROM receipts WHERE id = ?', [receiptId], (err, row) => {
      if (err) {
        console.error('Enhanced scan DB error:', err);
        return;
      }
      if (!row) {
        console.warn(`Enhanced scan: receipt #${receiptId} not found`);
        return;
      }

      // Decide what is "better"
      const betterShop =
        improved.shop && improved.shop.length > (row.shop?.length || 0);

      const betterTotal =
        typeof improved.total === 'number' &&
        improved.total > 0 &&
        (!row.total || improved.total >= row.total);

      const betterVat =
        typeof improved.vat === 'number' &&
        improved.vat >= 0 &&
        (!row.vat || improved.vat >= row.vat);

      const betterText =
        improvedText.length > (row.raw_text?.length || 0);

      if (betterShop || betterTotal || betterVat || betterText) {
        const newShop = betterShop ? improved.shop : row.shop;
        const newTotal = betterTotal ? improved.total : row.total;
        const newVat = betterVat ? improved.vat : row.vat;
        const newText = betterText ? improvedText : row.raw_text;

        db.run(
          `UPDATE receipts
           SET shop = ?, total = ?, vat = ?, raw_text = ?, enhanced = 1
           WHERE id = ?`,
          [newShop, newTotal, newVat, newText, receiptId],
          (uErr) => {
            if (uErr) {
              console.error('Enhanced update error:', uErr);
            } else {
              console.log(
                `Receipt #${receiptId} improved via enhanced scan (no ML)`
              );
            }
          }
        );
      } else {
        console.log(`Receipt #${receiptId} unchanged after enhanced scan`);
      }
    });

    // Clean up temp file
    fs.unlink(enhancedPath, () => {});
  } catch (error) {
    console.error('Enhanced scan process error:', error);
  }
}


// ---- Route: list receipts ----
app.get('/api/receipts', authenticateToken, (req, res) => {
  db.all(
    `SELECT * FROM receipts WHERE user_id = ? ORDER BY id DESC`,
    [req.user.id],
    (err, rows) => {

    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});

// Update a receipt (only your own)
app.put('/api/receipts/:id', authenticateToken, (req, res) => {
  const receiptId = req.params.id;
  const { shop, date, total, vat } = req.body;

  db.run(
    `UPDATE receipts
     SET shop = ?, date = ?, total = ?, vat = ?
     WHERE id = ? AND user_id = ?`,
    [shop || null, date || null, total || null, vat || null, receiptId, req.user.id],
    function (err) {
      if (err) {
        console.error('Update receipt error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Receipt not found' });
      }
      res.json({ success: true });
    }
  );
});

// Delete a receipt (only your own)
app.delete('/api/receipts/:id', authenticateToken, (req, res) => {
  const receiptId = req.params.id;

  db.run(
    `DELETE FROM receipts
     WHERE id = ? AND user_id = ?`,
    [receiptId, req.user.id],
    function (err) {
      if (err) {
        console.error('Delete receipt error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Receipt not found' });
      }
      res.json({ success: true });
    }
  );
});

// ---- Dashboard stats ----
app.get('/api/dashboard', authenticateToken, (req, res) => {
  db.all(
    `SELECT date, total, vat FROM receipts WHERE user_id = ?`,
    [req.user.id],
    (err, rows) => {
      if (err) {
        console.error('Dashboard DB error:', err);
        return res.status(500).json({ error: 'DB error' });
      }

      let overallTotal = 0;
      let overallVat = 0;
      const byMonthMap = {};

      rows.forEach(row => {
        const total = row.total || 0;
        const vat = row.vat || 0;
        overallTotal += total;
        overallVat += vat;

        const key = normalizeMonth(row.date);

        if (!byMonthMap[key]) {
          byMonthMap[key] = { month: key, total: 0, vat: 0, count: 0 };
        }
        byMonthMap[key].total += total;
        byMonthMap[key].vat += vat;
        byMonthMap[key].count += 1;
      });

      const byMonth = Object.values(byMonthMap)
        .filter(m => m.month !== 'unknown')
        .sort((a, b) => a.month.localeCompare(b.month));

      res.json({
        overall: {
          count: rows.length,
          total: overallTotal,
          vat: overallVat,
        },
        byMonth,
      });
    }
  );
});

app.get('/api/export/csv', authenticateToken, (req, res) => {
  // Lock CSV export for free users
  if (requirePro(req, res)) return;

  db.all(
    `SELECT * FROM receipts WHERE user_id = ? ORDER BY id ASC`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB error' });

      const header = 'Shop,Date,Total,VAT\n';
      const lines = rows.map(r =>
        `"${r.shop || ''}",${r.date || ''},${r.total || ''},${r.vat || ''}`
      );
      const csv = header + lines.join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader(
        'Content-Disposition',
        'attachment; filename="receipts.csv"'
      );
      res.send(csv);
    }
  );
});

const PDFDocument = require('pdfkit');

app.get('/api/report/monthly', authenticateToken, (req, res) => {
  // Lock monthly PDF for Pro users
  if (requirePro(req, res)) return;

  db.all(
    `SELECT * FROM receipts WHERE user_id = ? ORDER BY date ASC`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB error' });

      const doc = new PDFDocument();
      let filename = `snap2excel_report_${Date.now()}.pdf`;
      filename = encodeURIComponent(filename);

      res.setHeader(
        'Content-disposition',
        'attachment; filename="' + filename + '"'
      );
      res.setHeader('Content-type', 'application/pdf');

      doc.fontSize(20).text('Snap2Excel Monthly Report', { underline: true });
      doc.moveDown();

      const total = rows.reduce((sum, r) => sum + (r.total || 0), 0);
      const vat = rows.reduce((sum, r) => sum + (r.vat || 0), 0);

      doc.fontSize(14).text(`Total receipts: ${rows.length}`);
      doc.text(`Total spent: £${total.toFixed(2)}`);
      doc.text(`Total VAT: £${vat.toFixed(2)}`);
      doc.moveDown();

      doc.fontSize(16).text('Details', { underline: true });
      doc.moveDown();

      rows.forEach(r => {
        doc
          .fontSize(12)
          .text(
            `${r.date || 'No date'} — ${r.shop} — £${r.total || 0} (VAT £${r.vat || 0})`
          );
      });

      doc.pipe(res);
      doc.end();
    }
  );
});


// ---- Profile routes ----

app.get('/api/profile', authenticateToken, (req, res) => {
  const {
    id,
    email,
    full_name,
    account_type,
    business_name,
    country,
    city,
    role,
    plan_type,
    billing_info,
    profile_photo,
    is_admin,
    job_title,
    weekly_price,
    credits,
    subscription_status,
    usage_mode,
    date_of_birth,
    experience_mode,
  } = req.user;

  res.json({
    id,
    email,
    full_name,
    account_type,
    business_name,
    country,
    city,
    role,
    plan_type,
    billing_info,
    profile_photo,
    is_admin,
    job_title,
    weekly_price,
    credits,
    subscription_status,
    usage_mode,
    date_of_birth,
    experience_mode,
    is_youth: experience_mode === 'youth',
    is_business: account_type === 'business',
  });
});


console.log('Registering /api/profile/details route');

app.post('/api/profile/details', authenticateToken, (req, res) => {
  const {
    full_name,
    account_type,
    business_name,
    country,
    city,
    role,
    usage_mode,
    date_of_birth,
  } = req.body;

  // Validate account type
  const safeAccountType =
    account_type === 'business' ? 'business' : 'personal';

  // Determine safe usage mode
  let safeUsageMode;
  if (safeAccountType === 'business') {
    safeUsageMode = 'business_owner';
  } else if (usage_mode === 'self_employed') {
    safeUsageMode = 'self_employed';
  } else {
    safeUsageMode = 'personal_budget';
  }

  // AUTO youth/adult mode
  let nextMode = req.user.experience_mode;

  if (date_of_birth) {
    const y = parseInt(date_of_birth.split('-')[0]);
    const age = new Date().getFullYear() - y;
    nextMode = age <= 25 ? 'youth' : 'adult';
  }

  db.run(
    `UPDATE users
     SET full_name = ?,
         account_type = ?,
         business_name = ?,
         country = ?,
         city = ?,
         role = ?,
         usage_mode = ?,
         date_of_birth = ?,
         experience_mode = ?
     WHERE id = ?`,
    [
      full_name || null,
      safeAccountType,
      safeAccountType === 'business' ? business_name || null : null,
      country || null,
      city || null,
      role || null,
      safeUsageMode,
      date_of_birth || req.user.date_of_birth || null,
      nextMode,
      req.user.id,
    ],
    function (err) {
      if (err) {
        console.error('Update profile details error:', err);
        return res.status(500).json({ error: 'DB error' });
      }

      return res.json({
        full_name: full_name || null,
        account_type: safeAccountType,
        business_name:
          safeAccountType === 'business' ? business_name || null : null,
        country: country || null,
        city: city || null,
        role: role || null,
        date_of_birth: date_of_birth || req.user.date_of_birth || null,
        experience_mode: nextMode,
      });
    }
  );
});


// Change email
app.post('/api/profile/email', authenticateToken, (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  db.run(
    `UPDATE users SET email = ? WHERE id = ?`,
    [email, req.user.id],
    function (err) {
      if (err) {
        if (String(err.message).includes('UNIQUE')) {
          return res.status(400).json({ error: 'Email already in use' });
        }
        console.error('Update email error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      res.json({ success: true, email });
    }
  );
});

// Change password
app.post('/api/profile/password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password required' });
  }

  db.get(`SELECT password_hash FROM users WHERE id = ?`, [req.user.id], async (err, row) => {
    if (err) {
      console.error('Get password error:', err);
      return res.status(500).json({ error: 'DB error' });
    }
    if (!row) return res.status(404).json({ error: 'User not found' });

    const match = await bcrypt.compare(currentPassword, row.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Current password incorrect' });
    }

    const newHash = await bcrypt.hash(newPassword, 10);
    db.run(`UPDATE users SET password_hash = ? WHERE id = ?`, [newHash, req.user.id], (uErr) => {
      if (uErr) {
        console.error('Update password error:', uErr);
        return res.status(500).json({ error: 'DB error' });
      }
      res.json({ success: true });
    });
  });
});

// Update billing info (notes, company name, etc.)
app.post('/api/profile/billing', authenticateToken, (req, res) => {
  const { billing_info } = req.body;

  db.run(
    `UPDATE users SET billing_info = ? WHERE id = ?`,
    [billing_info || null, req.user.id],
    function (err) {
      if (err) {
        console.error('Update billing error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      res.json({ success: true, billing_info });
    }
  );
});

// Upload profile photo
const avatarUpload = multer({ dest: 'profile_uploads/' });

app.post('/api/profile/photo', authenticateToken, avatarUpload.single('photo'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const filePath = req.file.path; // e.g. "profile_uploads/xyz.jpg"

  db.run(
    `UPDATE users SET profile_photo = ? WHERE id = ?`,
    [filePath, req.user.id],
    function (err) {
      if (err) {
        console.error('Update photo error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      res.json({ success: true, profile_photo: filePath });
    }
  );
});

// Delete account (and receipts) with password confirm
app.delete('/api/profile', authenticateToken, (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });

  db.get(`SELECT password_hash FROM users WHERE id = ?`, [req.user.id], async (err, row) => {
    if (err) {
      console.error('Delete account get error:', err);
      return res.status(500).json({ error: 'DB error' });
    }
    if (!row) return res.status(404).json({ error: 'User not found' });

    const match = await bcrypt.compare(password, row.password_hash);
    if (!match) return res.status(401).json({ error: 'Password incorrect' });

    db.run(`DELETE FROM receipts WHERE user_id = ?`, [req.user.id], function (delErr) {
      if (delErr) {
        console.error('Delete receipts error:', delErr);
        return res.status(500).json({ error: 'DB error' });
      }

      db.run(`DELETE FROM users WHERE id = ?`, [req.user.id], function (userErr) {
        if (userErr) {
          console.error('Delete user error:', userErr);
          return res.status(500).json({ error: 'DB error' });
        }
        res.json({ success: true });
      });
    });
  });
});

// Update job title ONLY (no plan_type change here)
app.post('/api/profile/job', authenticateToken, (req, res) => {
  const { job_title } = req.body;

  db.run(
    `UPDATE users
     SET job_title = ?
     WHERE id = ?`,
    [job_title || null, req.user.id],
    function (err) {
      if (err) {
        console.error('Update job error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      res.json({ success: true, job_title });
    }
  );
});

// Get personal finance settings
app.get('/api/money/settings', authenticateToken, (req, res) => {
  if (req.user.account_type !== 'personal') {
    return res.status(403).json({ error: 'Money planner is for personal accounts only.' });
  }

  db.get(
    `SELECT income_amount, income_frequency, bills_json
     FROM user_finance
     WHERE user_id = ?`,
    [req.user.id],
    (err, row) => {
      if (err) {
        console.error('Money settings DB error:', err);
        return res.status(500).json({ error: 'DB error' });
      }

      if (!row) {
        return res.json({
          income_amount: null,
          income_frequency: 'monthly',
          bills: [],
        });
      }

      let bills = [];
      if (row.bills_json) {
        try {
          bills = JSON.parse(row.bills_json);
        } catch (_) {
          bills = [];
        }
      }

      res.json({
        income_amount: row.income_amount,
        income_frequency: row.income_frequency || 'monthly',
        bills,
      });
    }
  );
});

// Save personal finance settings
app.post('/api/money/settings', authenticateToken, (req, res) => {
  if (req.user.account_type !== 'personal') {
    return res.status(403).json({ error: 'Money planner is for personal accounts only.' });
  }

  const { income_amount, income_frequency, bills } = req.body;

  const safeIncome = typeof income_amount === 'number' ? income_amount : null;
  const safeFreq =
    income_frequency === 'weekly' || income_frequency === 'monthly'
      ? income_frequency
      : 'monthly';

  let billsJson = null;
  try {
    billsJson = JSON.stringify(Array.isArray(bills) ? bills : []);
  } catch (e) {
    billsJson = '[]';
  }

  db.run(
    `
    INSERT INTO user_finance (user_id, income_amount, income_frequency, bills_json)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      income_amount = excluded.income_amount,
      income_frequency = excluded.income_frequency,
      bills_json = excluded.bills_json
    `,
    [req.user.id, safeIncome, safeFreq, billsJson],
    function (err) {
      if (err) {
        console.error('Money settings save error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      res.json({ success: true });
    }
  );
});

// Simple money plan summary (income vs bills + 50/30/20 rule)
// Personal accounts only
app.get('/api/money/plan', authenticateToken, (req, res) => {
  if (req.user.account_type !== 'personal') {
    return res.status(403).json({ error: 'Money planner is for personal accounts only.' });
  }

  db.get(
    `SELECT income_amount, income_frequency, bills_json
     FROM user_finance
     WHERE user_id = ?`,
    [req.user.id],
    (err, row) => {
      if (err) {
        console.error('Money plan DB error:', err);
        return res.status(500).json({ error: 'DB error' });
      }

      // If user hasn't set anything yet
      if (!row || !row.income_amount) {
        return res.json({ hasData: false });
      }

      const income = row.income_amount;
      const freq = row.income_frequency || 'monthly';

      // Normalize income to monthly
      const monthlyIncome = freq === 'weekly' ? (income * 52) / 12 : income;

      let bills = [];
      try {
        bills = row.bills_json ? JSON.parse(row.bills_json) : [];
      } catch (_) {
        bills = [];
      }

      // Each bill: { name, amount, frequency: 'weekly'|'monthly'|'yearly' }
      let monthlyBills = 0;
      bills.forEach((b) => {
        const amt = Number(b.amount) || 0;
        const f = b.frequency || 'monthly';

        if (f === 'monthly') {
          monthlyBills += amt;
        } else if (f === 'weekly') {
          monthlyBills += (amt * 52) / 12;
        } else if (f === 'yearly') {
          monthlyBills += amt / 12;
        }
      });

      const leftover = monthlyIncome - monthlyBills;
      const billsRatio = monthlyIncome > 0 ? monthlyBills / monthlyIncome : 0;

      // 50/30/20 rule (based on monthly income)
      const needsBudget = monthlyIncome * 0.5;
      const wantsBudget = monthlyIncome * 0.3;
      const savingsBudget = monthlyIncome * 0.2;

      // Recommended weekly investing from the 20% pot
      const weeklyInvest = savingsBudget / 4.33; // approx weeks per month

      // Are current bills above the "needs" budget?
      const needsOverBudget = monthlyBills > needsBudget;

      res.json({
        hasData: true,
        monthlyIncome,
        monthlyBills,
        leftover,
        billsRatio,
        needsBudget,
        wantsBudget,
        savingsBudget,
        weeklyInvest,
        needsOverBudget,
      });
    }
  );
});

app.post('/api/billing/create-checkout-session', authenticateToken, async (req, res) => {
  try {
    const { plan_type } = req.body; // 'pw_099', 'pm_299', 'bw_149', 'bm_349'

    const priceMap = {
      pw_099: process.env.STRIPE_PRICE_PW_099,
      pm_299: process.env.STRIPE_PRICE_PM_299,
      bw_149: process.env.STRIPE_PRICE_BW_149,
      bm_349: process.env.STRIPE_PRICE_BM_349,
    };

    const priceId = priceMap[plan_type];

    if (!priceId) {
      return res.status(400).json({ error: 'Invalid plan type' });
    }

    const clientBase = process.env.CLIENT_BASE_URL || 'http://localhost:3000';

    let customerId = req.user.stripe_customer_id || null;

    if (!customerId) {
      const customer = await stripe.customers.create({
        email: req.user.email,
        metadata: { user_id: String(req.user.id) },
      });

      customerId = customer.id;

      db.run(
        `UPDATE users SET stripe_customer_id = ? WHERE id = ?`,
        [customerId, req.user.id],
        (err) => {
          if (err) console.error('Error saving stripe_customer_id:', err);
        }
      );
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      customer: customerId,
      line_items: [{ price: priceId, quantity: 1 }],
      metadata: {
        user_id: String(req.user.id),
        plan_type,
      },
      success_url: `${clientBase}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${clientBase}/profile?canceled=1`,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe checkout session error:', err);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

app.post('/api/receipts/manual', authenticateToken, async (req, res) => {
  try {
    const { shop, date, total, vat, category } = req.body;

    if (!shop || total == null) {
      return res.status(400).json({ error: 'Shop and total are required' });
    }

    const userId = req.user.id;

    db.run(
      `INSERT INTO receipts (user_id, shop, date, total, vat, category, raw_text, enhanced, image_path)
       VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL)`,
      [
        userId,
        shop,
        date || null,
        total,
        vat || 0,
        category || 'Other',
        null, // raw_text (no OCR for manual entries)
      ],
      function (err) {
        if (err) {
          console.error('Manual receipt insert error:', err);
          return res.status(500).json({ error: 'DB error' });
        }
        res.json({ success: true, id: this.lastID });
      }
    );
  } catch (err) {
    console.error('Manual receipt insert error', err);
    res.status(500).json({ error: 'Failed to save receipt' });
  }
});

// Simple admin guard – adjust if you already have a middleware
function requireAdmin(req, res, next) {
  if (!req.user || !req.user.is_admin) {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
}

// Simple user stats for the extra "Total / Pro / Free" cards
app.get('/api/admin/user-stats', authenticateToken, requireAdmin, (req, res) => {
  const sql = `
    SELECT
      COUNT(*) AS total_users,
      SUM(CASE WHEN plan_type IS NOT NULL AND plan_type != 'free' THEN 1 ELSE 0 END) AS pro_users,
      SUM(CASE WHEN plan_type IS NULL OR plan_type = 'free' THEN 1 ELSE 0 END) AS free_users
    FROM users
  `;

  db.get(sql, [], (err, row) => {
    if (err) {
      console.error('Admin user-stats error:', err);
      return res.status(500).json({ error: 'DB error' });
    }
    res.json({
      total_users: row?.total_users || 0,
      pro_users: row?.pro_users || 0,
      free_users: row?.free_users || 0,
    });
  });
});

app.get('/api/admin/7day', authenticateToken, requireAdmin, (req, res) => {
  const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;

  const result = {
    new_users: 0,
    receipts_scanned: 0,
  };

  db.get(
    `SELECT COUNT(*) AS c FROM users WHERE created_at >= ?`,
    [sevenDaysAgo],
    (err, row) => {
      if (!err) result.new_users = row.c;

      db.get(
        `SELECT COUNT(*) AS c FROM receipts WHERE timestamp >= ?`,
        [sevenDaysAgo],
        (err2, row2) => {
          if (!err2) result.receipts_scanned = row2.c;
          res.json(result);
        }
      );
    }
  );
});

app.get('/api/admin/retention', authenticateToken, requireAdmin, (req, res) => {
  const sevenAgo = Date.now() - 7 * 86400000;
  const thirtyAgo = Date.now() - 30 * 86400000;

  const data = { ret7: 0, ret30: 0 };

  db.get(
    `SELECT COUNT(DISTINCT user_id) AS c FROM receipts WHERE timestamp >= ?`,
    [sevenAgo],
    (err, row) => {
      if (!err) data.ret7 = row.c;

      db.get(
        `SELECT COUNT(DISTINCT user_id) AS c FROM receipts WHERE timestamp >= ?`,
        [thirtyAgo],
        (err2, row2) => {
          if (!err2) data.ret30 = row2.c;
          res.json(data);
        }
      );
    }
  );
});


const TIPS = [
  "If it doesn't bring joy or value, skip it.",
  "£20 saved weekly = £1040 a year.",
  "Track your receipts — that's where profit appears.",
  "Try buying store brands for 2 weeks and compare results.",
  "Impulse buys vanish fast — savings stay forever.",
  "Spent too much yesterday? Balance it today.",
  "Your leftover is your real profit — protect it.",
];

// Tip is available to all logged-in users
app.get('/api/tip', authenticateToken, (req, res) => {
  const tip = TIPS[Math.floor(Math.random() * TIPS.length)];
  res.json({ tip });
});

// Simple spending insights per user – not admin only
app.get('/api/insights/spending', authenticateToken, (req, res) => {
  db.all(
    `SELECT shop, total FROM receipts WHERE user_id = ?`,
    [req.user.id],
    (err, rows) => {
      if (err) {
        console.error('Insights DB error:', err);
        return res.status(500).json({ error: 'DB error' });
      }

      let food = 0;
      let amazon = 0;
      let totalSpend = 0;

      rows.forEach((r) => {
        const shop = r.shop?.toLowerCase() || '';
        const amt = Number(r.total) || 0;
        totalSpend += amt;

        if (
          shop.includes('tesco') ||
          shop.includes('sainsbury') ||
          shop.includes('aldi') ||
          shop.includes('lidl')
        ) {
          food += amt;
        }

        if (shop.includes('amazon')) {
          amazon += amt;
        }
      });

      const insights = [];

      if (food > totalSpend * 0.4 && totalSpend > 0) {
        insights.push(
          'You are spending a big chunk of your money on food. Try swapping 1–2 shops to cheaper options this month.'
        );
      }

      if (amazon > 20) {
        insights.push(
          `You spent about £${amazon.toFixed(
            2
          )} on Amazon. Small orders there add up quickly.`
        );
      }

      if (insights.length === 0) {
        insights.push('Your spending looks balanced this month – keep going like this.');
      }

      res.json({ insights });
    }
  );
});


// DAU placeholder
app.get('/api/admin/dau', authenticateToken, requireAdmin, (req, res) => {
  res.json({
    today: 0,
    yesterday: 0,
    avg_7_days: 0,
  });
});

app.get('/api/admin/active-users', authenticateToken, requireAdmin, (req, res) => {
  const now = Date.now();
  const weekAgo = now - 7 * 86400000;
  const monthAgo = now - 30 * 86400000;

  const result = { wau: 0, mau: 0 };

  db.get(
    `SELECT COUNT(DISTINCT user_id) AS c FROM receipts WHERE timestamp >= ?`,
    [weekAgo],
    (err, r1) => {
      if (!err) result.wau = r1.c;

      db.get(
        `SELECT COUNT(DISTINCT user_id) AS c FROM receipts WHERE timestamp >= ?`,
        [monthAgo],
        (err2, r2) => {
          if (!err2) result.mau = r2.c;
          res.json(result);
        }
      );
    }
  );
});

// 📰 Activity feed (recent receipt scans) – RETURNS AN ARRAY
app.get('/api/admin/activity', authenticateToken, requireAdmin, (req, res) => {
  const sql = `
    SELECT
      r.id,
      r.user_id,
      u.email,
      r.shop,
      r.total,
      COALESCE(r.date, '') AS date
    FROM receipts r
    JOIN users u ON u.id = r.user_id
    ORDER BY r.id DESC
    LIMIT 50
  `;
  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error('Admin activity error:', err);
      return res.status(500).json({ error: 'DB error' });
    }
    res.json(rows || []);
  });
});

// 📤 Export all users as CSV
app.get('/api/admin/export/users', authenticateToken, requireAdmin, (req, res) => {
  const sql = `
    SELECT
      id,
      email,
      plan_type,
      credits,
      subscription_status,
      is_admin,
      banned
    FROM users
    ORDER BY id ASC
  `;
  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error('Admin export users error:', err);
      return res.status(500).json({ error: 'DB error' });
    }

    const header = [
      'id',
      'email',
      'plan_type',
      'credits',
      'subscription_status',
      'is_admin',
      'banned',
    ];

    const escape = (val) => {
      if (val == null) return '';
      const s = String(val);
      if (s.includes('"') || s.includes(',') || s.includes('\n')) {
        return `"${s.replace(/"/g, '""')}"`;
      }
      return s;
    };

    const lines = [
      header.join(','),
      ...rows.map((row) =>
        header.map((h) => escape(row[h])).join(',')
      ),
    ];
    const csv = lines.join('\n');

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="users.csv"');
    res.send(csv);
  });
});

// 📤 Export all receipts as CSV
app.get('/api/admin/export/receipts', authenticateToken, requireAdmin, (req, res) => {
  const sql = `
    SELECT
      r.id,
      r.user_id,
      u.email,
      r.shop,
      r.date,
      r.total,
      r.vat,
      r.category
    FROM receipts r
    JOIN users u ON u.id = r.user_id
    ORDER BY r.id ASC
  `;
  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error('Admin export receipts error:', err);
      return res.status(500).json({ error: 'DB error' });
    }

    const header = [
      'id',
      'user_id',
      'email',
      'shop',
      'date',
      'total',
      'vat',
      'category',
    ];

    const escape = (val) => {
      if (val == null) return '';
      const s = String(val);
      if (s.includes('"') || s.includes(',') || s.includes('\n')) {
        return `"${s.replace(/"/g, '""')}"`;
      }
      return s;
    };

    const lines = [
      header.join(','),
      ...rows.map((row) =>
        header.map((h) => escape(row[h])).join(',')
      ),
    ];
    const csv = lines.join('\n');

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader(
      'Content-Disposition',
      'attachment; filename="receipts.csv"'
    );
    res.send(csv);
  });
});

// Start Tink Link flow – returns a URL the frontend can redirect to
app.post('/api/tink/link', authenticateToken, (req, res) => {
  if (!TINK_CLIENT_ID || !TINK_REDIRECT_URI) {
    return res.status(500).json({ error: 'Tink not configured' });
  }

  const base = 'https://link.tink.com/1.0/authorize/';

  const params = new URLSearchParams({
    client_id: TINK_CLIENT_ID,
    redirect_uri: TINK_REDIRECT_URI,
    scope: 'accounts:read,transactions:read',
    market: 'GB',
    locale: 'en_GB',
    response_type: 'code',
  });

  const linkUrl = `${base}?${params.toString()}`;
  return res.json({ linkUrl });
});

// Start Tink Link flow (sandbox) – redirect browser to Tink
app.get('/api/tink/start', (req, res) => {
  if (!TINK_CLIENT_ID || !TINK_REDIRECT_URI) {
    console.error('Tink not configured – missing env vars');
    return res.status(500).send('Tink not configured');
  }

  const params = new URLSearchParams({
    client_id: TINK_CLIENT_ID,
    redirect_uri: TINK_REDIRECT_URI,      // use the env one
    scope: 'accounts:read,transactions:read',
    market: 'GB',
    locale: 'en_GB',
    response_type: 'code',
    test: 'true',                         // IMPORTANT for sandbox
  });

  const url = `https://link.tink.com/1.0/authorize/?${params.toString()}`;

  console.log('🔗 Redirecting to Tink Link:', url);
  return res.redirect(url);
});

app.get('/api/tink/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) {
    return res.status(400).send('Missing code from Tink');
  }

  console.log('✅ Tink auth code received:', code);

  // later: exchange code → token, fetch transactions, save them per user
  return res.redirect('http://localhost:3000/dashboard?bank=connected');
});


const PORT = process.env.PORT || 5001;   // 👈 use Render port in prod, 5001 locally
app.listen(PORT, () => {
  console.log(`Snap2Excel backend running on port ${PORT}`);
});

