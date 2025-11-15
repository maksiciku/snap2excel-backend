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

const JWT_SECRET = 'super-secret-snap2excel-key-change-later'; // later we move to env var

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('profile_uploads'));

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

// Create receipts table (if not exists)
db.run(`
  CREATE TABLE IF NOT EXISTS receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shop TEXT,
    date TEXT,
    total REAL,
    vat REAL,
    raw_text TEXT,
    user_id INTEGER
  )
`);

// Ensure user_id column exists on receipts (SQLite will ignore if it already exists and we catch the error)
db.run(`ALTER TABLE receipts ADD COLUMN user_id INTEGER`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding user_id column:', err.message);
  }
});

db.run(`ALTER TABLE receipts ADD COLUMN category TEXT`, (err) => {
  if (err && !String(err.message).includes('duplicate column')) {
    console.error('Error adding category column:', err.message);
  }
});


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

function findShopName(text) {
  const lines = cleanLines(text);
  for (const line of lines) {
    if (isLikelyShopName(line)) {
      return line;
    }
  }
  // fallback: first non-empty line
  return lines[0] || '';
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

// ---- Auth routes ----

// Register new user
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  try {
    const password_hash = await bcrypt.hash(password, 10);

    db.run(
      `INSERT INTO users (email, password_hash) VALUES (?, ?)`,
      [email, password_hash],
      function (err) {
        if (err) {
          if (String(err.message).includes('UNIQUE')) {
            return res.status(400).json({ error: 'Email already registered' });
          }
          console.error('Register error:', err);
          return res.status(500).json({ error: 'DB error' });
        }

        const user = { id: this.lastID, email };
        const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });

        res.json({ token, user });
      }
    );
  } catch (err) {
    console.error('Register hash error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login existing user
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, row) => {
    if (err) {
      console.error('Login DB error:', err);
      return res.status(500).json({ error: 'DB error' });
    }
    if (!row) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const match = await bcrypt.compare(password, row.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = { id: row.id, email: row.email };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });

    res.json({ token, user });
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
     subscription_status
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

function requireAdmin(req, res, next) {
  if (!req.user || !req.user.is_admin) {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
}

// ---- ADMIN ROUTES ----

// Overall summary for admin dashboard
app.get('/api/admin/summary', authenticateToken, requireAdmin, (req, res) => {
  const summary = {};

  // Total users
  db.get(`SELECT COUNT(*) AS total_users FROM users`, [], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    summary.total_users = row.total_users;

    // Pro users + weekly MRR estimate
    db.get(
      `SELECT
         COUNT(*) AS pro_users,
         IFNULL(SUM(weekly_price), 0) AS weekly_mrr
       FROM users
       WHERE plan_type LIKE 'weekly_%'`,
      [],
      (err2, row2) => {
        if (err2) return res.status(500).json({ error: 'DB error' });

        summary.pro_users = row2.pro_users;
        summary.weekly_mrr = row2.weekly_mrr;

        // Receipts + total spend
        db.get(
          `SELECT COUNT(*) AS total_receipts, IFNULL(SUM(total),0) AS total_spend
           FROM receipts`,
          [],
          (err3, row3) => {
            if (err3) return res.status(500).json({ error: 'DB error' });

            summary.total_receipts = row3.total_receipts;
            summary.total_spend = row3.total_spend;

            res.json(summary);
          }
        );
      }
    );
  });
});


// List all users with receipt counts and spend
app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
  const sql = `
    SELECT
      u.id,
      u.email,
      u.plan_type,
      u.is_admin,
      u.banned,
      u.credits,
      u.subscription_status,
      COUNT(r.id) AS receipt_count,
      IFNULL(SUM(r.total), 0) AS total_spend
    FROM users u
    LEFT JOIN receipts r ON r.user_id = u.id
    GROUP BY u.id
    ORDER BY u.id ASC
  `;

  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error('Admin users error:', err);
      return res.status(500).json({ error: 'DB error' });
    }
    res.json(rows);
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

app.post('/api/scan-receipt', authenticateToken, upload.single('receipt'), async (req, res) => {
  const filePath = req.file.path;
  const mime = req.file.mimetype;
  const ext = path.extname(req.file.originalname || '').toLowerCase();

    try {
    let text;

    // Reject PDFs for now – keep system stable
    if (mime === 'application/pdf' || ext === '.pdf') {
      fs.unlinkSync(filePath);
      return res.status(400).json({
        error: 'PDF files are not supported yet. Please upload a photo (JPG/PNG) or screenshot of the receipt.',
      });
    }

    // Image → use Tesseract
    const result = await Tesseract.recognize(filePath, 'eng');
    text = result.data.text || '';

    if (!text || text.trim().length === 0) {
      fs.unlinkSync(filePath);
      return res.status(400).json({ error: 'Could not read any text from file' });
    }

    const parsed = parseReceiptText(text);

    db.run(
      `INSERT INTO receipts (shop, date, total, vat, raw_text, user_id, category)
 VALUES (?, ?, ?, ?, ?, ?, ?)`,
[parsed.shop, parsed.date, parsed.total, parsed.vat, text, req.user.id, parsed.category],

      function (err) {
        fs.unlinkSync(filePath); // delete temp file

        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'DB error' });
        }

        res.json({
          id: this.lastID,
          ...parsed,
          raw_text: text,
        });
      }
    );
  } catch (err) {
    console.error('scan-receipt error:', err);
    try {
      fs.unlinkSync(filePath);
    } catch (e) {
      // ignore
    }
    res.status(500).json({ error: 'OCR failed' });
  }

});

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

// ---- Route: export CSV ----
app.get('/api/export/csv', authenticateToken, (req, res) => {
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
    res.setHeader('Content-Disposition', 'attachment; filename="receipts.csv"');
    res.send(csv);
  });
});

const PDFDocument = require('pdfkit');

app.get('/api/report/monthly', authenticateToken, (req, res) => {
  db.all(
    `SELECT * FROM receipts WHERE user_id = ? ORDER BY date ASC`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB error' });

      const doc = new PDFDocument();
      let filename = `snap2excel_report_${Date.now()}.pdf`;
      filename = encodeURIComponent(filename);

      res.setHeader('Content-disposition', 'attachment; filename="' + filename + '"');
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
        doc.fontSize(12).text(
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
    plan_type,
    billing_info,
    profile_photo,
    is_admin,
    job_title,
    weekly_price,
    credits,
    subscription_status
  } = req.user;

  res.json({
    id,
    email,
    plan_type,
    billing_info,
    profile_photo,
    is_admin,
    job_title,
    weekly_price,
    credits,
    subscription_status,
  });
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

// Update job title and plan type
app.post('/api/profile/job', authenticateToken, (req, res) => {
  const { job_title, plan_type } = req.body;

  db.run(
    `UPDATE users
     SET job_title = ?, plan_type = ?
     WHERE id = ?`,
    [job_title || null, plan_type || 'free', req.user.id],
    function (err) {
      if (err) {
        console.error('Update job error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      res.json({ success: true, job_title, plan_type });
    }
  );
});

// Create Stripe Checkout session for Pro £0.99/week
app.post('/api/billing/create-checkout-session', authenticateToken, async (req, res) => {
  try {
    const priceId = process.env.STRIPE_PRICE_ID;
    const clientBase = process.env.CLIENT_BASE_URL || 'http://localhost:3000';

    if (!priceId) {
      return res.status(500).json({ error: 'Stripe price ID not configured' });
    }

    let customerId = req.user.stripe_customer_id || null;

    // Create customer once, reuse later
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: req.user.email,
        metadata: {
          user_id: String(req.user.id),
        },
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
      line_items: [
        {
          price: priceId,
          quantity: 1,
        },
      ],
      metadata: {
        user_id: String(req.user.id),
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

const PORT = 5001;
app.listen(PORT, () => {
  console.log(`Snap2Excel backend running on http://localhost:${PORT}`);
});
