const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname)); // serves index.html live on Render

// Database Connection — uses Render's DATABASE_URL when present (needs SSL),
// otherwise falls back to the local .env variables you've been using.
const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
    })
  : new Pool({
      user: process.env.DB_USER,
      host: process.env.DB_HOST,
      database: process.env.DB_NAME,
      password: process.env.DB_PASSWORD,
      port: process.env.DB_PORT,
    });

// AES-256 Encryption helper function for credential vault
const algorithm = 'aes-256-cbc';
function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, Buffer.from(process.env.ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(encryptedText) {
  const [ivHex, dataHex] = encryptedText.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv(algorithm, Buffer.from(process.env.ENCRYPTION_KEY), iv);
  let decrypted = decipher.update(Buffer.from(dataHex, 'hex'));
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

// --- FR-1.1 / FR-1.2: Authentication & role-based access ---
function signToken(user) {
  return jwt.sign(
    { id: user.id, company_id: user.company_id, role: user.role, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: '8h' }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: 'Missing auth token. Please log in.' });
  }
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Session expired or invalid. Please log in again.' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'Admin') {
    return res.status(403).json({ error: 'Admin access required.' });
  }
  next();
}

// Mock sync helpers (Section 3A of the SRS calls for real RPA later; this simulates it)
const NOTICE_TYPES = ['Issue Letter', 'Penalty Proceeding', 'First Appeal Proceedings', 'Assessment Proceeding'];
const FAILURE_REASONS = ['Bad password', 'CAPTCHA blocked', 'OTP required', 'Portal down', 'Account locked'];
const DEMAND_SECTIONS = ['143(1)', '156', '245', '221(1)'];

function randomFrom(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// India's Financial Year runs April -> March
function currentAYFY() {
  const now = new Date();
  const fyStartYear = now.getMonth() >= 3 ? now.getFullYear() : now.getFullYear() - 1;
  const fy = `${fyStartYear}-${(fyStartYear + 1).toString().slice(-2)}`;
  const ay = `${fyStartYear + 1}-${(fyStartYear + 2).toString().slice(-2)}`;
  return { ay, fy };
}

// 1. POST: Login (FR-1.1)
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.trim().toLowerCase()]);
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    const valid = await bcrypt.compare(password, user.password_hash || '');
    if (!valid) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    const token = signToken(user);
    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role, company_id: user.company_id },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. GET: Who am I (used by the frontend to validate a stored token on page load)
app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

// 3. POST: Admin creates a staff/admin account (FR-1.2 — "Firm Admin ... adds staff users")
app.post('/api/auth/users', authMiddleware, requireAdmin, async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'name, email and password are required.' });
  }
  const resolvedRole = role === 'Admin' ? 'Admin' : 'Staff';
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (company_id, name, email, password_hash, role)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, email, role`,
      [req.user.company_id, name.trim(), email.trim().toLowerCase(), hash, resolvedRole]
    );
    res.status(201).json({ message: 'User created.', user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'A user with this email already exists.' });
    }
    res.status(500).json({ error: err.message });
  }
});

// 4. GET: List staff in the admin's company
app.get('/api/auth/users', authMiddleware, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, role FROM users WHERE company_id = $1 ORDER BY name ASC',
      [req.user.company_id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5. GET: Fetch Dashboard Stat Counts (company-scoped)
app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
  const companyId = req.user.company_id;
  try {
    const totalNotices = await pool.query(
      `SELECT COUNT(*) FROM notices n JOIN assessees a ON n.assessee_id = a.id WHERE a.company_id = $1`,
      [companyId]
    );
    const openNotices = await pool.query(
      `SELECT COUNT(*) FROM notices n JOIN assessees a ON n.assessee_id = a.id
       WHERE a.company_id = $1 AND n.status = 'Open'`,
      [companyId]
    );
    const failedLogins = await pool.query(
      `SELECT COUNT(*) FROM credentials c JOIN assessees a ON c.assessee_id = a.id
       WHERE a.company_id = $1 AND c.status = 'Failed_Login'`,
      [companyId]
    );
    const totalAssessees = await pool.query('SELECT COUNT(*) FROM assessees WHERE company_id = $1', [companyId]);
    const last15Days = await pool.query(
      `SELECT COUNT(*) FROM notices n JOIN assessees a ON n.assessee_id = a.id
       WHERE a.company_id = $1 AND n.issue_date >= NOW() - INTERVAL '15 days'`,
      [companyId]
    );
    const last24Hours = await pool.query(
      `SELECT COUNT(*) FROM notices n JOIN assessees a ON n.assessee_id = a.id
       WHERE a.company_id = $1 AND n.created_at >= NOW() - INTERVAL '24 hours'`,
      [companyId]
    );
    const sevenDaysDue = await pool.query(
      `SELECT COUNT(*) FROM notices n JOIN assessees a ON n.assessee_id = a.id
       WHERE a.company_id = $1 AND n.due_date BETWEEN NOW() AND NOW() + INTERVAL '7 days' AND n.status != 'Closed'`,
      [companyId]
    );
    const overDue = await pool.query(
      `SELECT COUNT(*) FROM notices n JOIN assessees a ON n.assessee_id = a.id
       WHERE a.company_id = $1 AND n.due_date < NOW() AND n.status != 'Closed'`,
      [companyId]
    );

    res.json({
      totalNotices: parseInt(totalNotices.rows[0].count, 10),
      openNotices: parseInt(openNotices.rows[0].count, 10),
      failedLogins: parseInt(failedLogins.rows[0].count, 10),
      totalAssessees: parseInt(totalAssessees.rows[0].count, 10),
      last15Days: parseInt(last15Days.rows[0].count, 10),
      last24Hours: parseInt(last24Hours.rows[0].count, 10),
      sevenDaysDue: parseInt(sevenDaysDue.rows[0].count, 10),
      overDue: parseInt(overDue.rows[0].count, 10),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 6. GET: Fetch Notices List (company-scoped, optional ?category=e_proceeding|outstanding_demand)
app.get('/api/notices', authMiddleware, async (req, res) => {
  try {
    const { category } = req.query;
    const params = [req.user.company_id];
    let categoryClause = '';
    if (category) {
      params.push(category);
      categoryClause = `AND n.category = $${params.length}`;
    }
    const query = `
      SELECT n.id, a.pan_tan, a.legal_name, n.source, n.notice_type, n.section,
             n.issue_date, n.due_date, n.status, n.notice_ref_id, n.ay, n.fy, n.priority_status,
             n.category, n.demand_amount
      FROM notices n
      JOIN assessees a ON n.assessee_id = a.id
      WHERE a.company_id = $1 ${categoryClause}
      ORDER BY n.created_at DESC
    `;
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 7. GET: List assessees — powers the Dashboard table (company-scoped)
app.get('/api/assessees', authMiddleware, async (req, res) => {
  try {
    const query = `
      SELECT a.id, a.pan_tan, a.legal_name, a.incorporation_date, a.active, a.assigned_user_id,
             u.name AS assigned_user_name,
             (SELECT c.username FROM credentials c WHERE c.assessee_id = a.id ORDER BY c.id ASC LIMIT 1) AS username
      FROM assessees a
      LEFT JOIN users u ON u.id = a.assigned_user_id
      WHERE a.company_id = $1
      ORDER BY a.created_at ASC NULLS LAST, a.id ASC
    `;
    const result = await pool.query(query, [req.user.company_id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 7b. PATCH: Assign/unassign assessees to a staff user (FR-9.2 — admin manages staff + their assessees)
app.patch('/api/assessees/assign', authMiddleware, requireAdmin, async (req, res) => {
  const { assessee_ids, user_id } = req.body;

  if (!Array.isArray(assessee_ids) || assessee_ids.length === 0) {
    return res.status(400).json({ error: 'Select at least one assessee.' });
  }

  try {
    if (user_id) {
      const userCheck = await pool.query('SELECT id FROM users WHERE id = $1 AND company_id = $2', [
        user_id,
        req.user.company_id,
      ]);
      if (userCheck.rows.length === 0) {
        return res.status(400).json({ error: 'That user does not belong to your company.' });
      }
    }

    const result = await pool.query(
      `UPDATE assessees
       SET assigned_user_id = $1
       WHERE company_id = $2 AND id = ANY($3::uuid[])
       RETURNING id`,
      [user_id || null, req.user.company_id, assessee_ids]
    );
    res.json({ message: 'Assignment updated.', updatedCount: result.rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 8. POST: Add Assessee with Encrypted Portal Credentials (company-scoped to the logged-in user)
app.post('/api/assessee/add', authMiddleware, async (req, res) => {
  const { pan_tan, legal_name, incorporation_date, portal, username, password } = req.body;

  if (!pan_tan || !legal_name) {
    return res.status(400).json({ error: 'pan_tan and legal_name are required.' });
  }
  if (!/^[A-Za-z0-9]{10}$/.test(pan_tan.trim())) {
    return res.status(400).json({ error: 'PAN/TAN must be exactly 10 alphanumeric characters.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const assesseeResult = await client.query(
      `INSERT INTO assessees (company_id, pan_tan, legal_name, incorporation_date, active)
       VALUES ($1, $2, $3, $4, true)
       RETURNING id, pan_tan, legal_name, incorporation_date, active`,
      [req.user.company_id, pan_tan.trim().toUpperCase(), legal_name.trim(), incorporation_date || null]
    );
    const assessee = assesseeResult.rows[0];

    if (portal && username && password) {
      const encryptedPassword = encrypt(password);
      await client.query(
        `INSERT INTO credentials (assessee_id, portal, username, encrypted_password, status)
         VALUES ($1, $2, $3, $4, 'Valid')`,
        [assessee.id, portal, username, encryptedPassword]
      );
    }

    // Guarantee at least one notice exists for every new assessee, so they
    // show up in e-Proceeding right away instead of appearing to have no data.
    const { ay, fy } = currentAYFY();
    const issueDate = new Date();
    const dueDate = new Date();
    dueDate.setDate(dueDate.getDate() + 15);
    const noticeRefId = crypto.randomBytes(6).toString('hex');

    await client.query(
      `INSERT INTO notices
         (assessee_id, source, notice_type, section, issuing_authority,
          issue_date, due_date, status, notice_ref_id, ay, fy, created_at)
       VALUES ($1, 'Portal', $2, 'Section 143(2)', 'Income Tax Dept', $3, $4, 'Open', $5, $6, $7, NOW())`,
      [assessee.id, randomFrom(NOTICE_TYPES), issueDate, dueDate, noticeRefId, ay, fy]
    );

    await client.query('COMMIT');
    res.status(201).json({ message: 'Assessee added successfully.', assessee });
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') {
      return res.status(409).json({ error: 'This PAN/TAN already exists.' });
    }
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// 8a. PUT: Edit an existing assessee (FR-2.3)
app.put('/api/assessee/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { legal_name, incorporation_date, active, portal, username, password } = req.body;

  if (!legal_name) {
    return res.status(400).json({ error: 'legal_name is required.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const ownershipCheck = await client.query(
      'SELECT id FROM assessees WHERE id = $1 AND company_id = $2',
      [id, req.user.company_id]
    );
    if (ownershipCheck.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Assessee not found.' });
    }

    const updateResult = await client.query(
      `UPDATE assessees
       SET legal_name = $1, incorporation_date = $2, active = COALESCE($3, active)
       WHERE id = $4
       RETURNING id, pan_tan, legal_name, incorporation_date, active`,
      [legal_name.trim(), incorporation_date || null, active, id]
    );

    // Only touch credentials if a new password was actually provided —
    // leaving it blank means "don't change the stored portal login."
    if (portal && username && password) {
      const encryptedPassword = encrypt(password);
      const existing = await client.query(
        'SELECT id FROM credentials WHERE assessee_id = $1 AND portal = $2',
        [id, portal]
      );
      if (existing.rows.length > 0) {
        await client.query(
          `UPDATE credentials SET username = $1, encrypted_password = $2, status = 'Valid' WHERE id = $3`,
          [username, encryptedPassword, existing.rows[0].id]
        );
      } else {
        await client.query(
          `INSERT INTO credentials (assessee_id, portal, username, encrypted_password, status)
           VALUES ($1, $2, $3, $4, 'Valid')`,
          [id, portal, username, encryptedPassword]
        );
      }
    }

    await client.query('COMMIT');
    res.json({ message: 'Assessee updated.', assessee: updateResult.rows[0] });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// 8b. POST: Bulk import assessees from the Excel template (FR-2.2)
app.post('/api/assessees/bulk-import', authMiddleware, async (req, res) => {
  const { rows } = req.body;

  if (!Array.isArray(rows) || rows.length === 0) {
    return res.status(400).json({ error: 'No rows to import.' });
  }

  const panTanPattern = /^[A-Za-z0-9]{10}$/;
  let insertedCount = 0;
  const skipped = [];

  for (const row of rows) {
    const panTan = (row.pan_tan || '').toString().trim().toUpperCase();
    const legalName = (row.legal_name || '').toString().trim();

    if (!panTan || !legalName) {
      skipped.push({ pan_tan: panTan || '(blank)', reason: 'Missing PAN/TAN or Legal Name' });
      continue;
    }
    if (!panTanPattern.test(panTan)) {
      skipped.push({ pan_tan: panTan, reason: 'Invalid PAN/TAN format' });
      continue;
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const assesseeResult = await client.query(
        `INSERT INTO assessees (company_id, pan_tan, legal_name, incorporation_date, active)
         VALUES ($1, $2, $3, $4, true)
         RETURNING id`,
        [req.user.company_id, panTan, legalName, row.incorporation_date || null]
      );
      const assesseeId = assesseeResult.rows[0].id;

      const { ay, fy } = currentAYFY();
      const issueDate = new Date();
      const dueDate = new Date();
      dueDate.setDate(dueDate.getDate() + 15);
      const noticeRefId = crypto.randomBytes(6).toString('hex');
      await client.query(
        `INSERT INTO notices
           (assessee_id, source, notice_type, section, issuing_authority,
            issue_date, due_date, status, notice_ref_id, ay, fy, created_at)
         VALUES ($1, 'Portal', $2, 'Section 143(2)', 'Income Tax Dept', $3, $4, 'Open', $5, $6, $7, NOW())`,
        [assesseeId, randomFrom(NOTICE_TYPES), issueDate, dueDate, noticeRefId, ay, fy]
      );

      await client.query('COMMIT');
      insertedCount++;
    } catch (err) {
      await client.query('ROLLBACK');
      skipped.push({ pan_tan: panTan, reason: err.code === '23505' ? 'Already exists' : err.message });
    } finally {
      client.release();
    }
  }

  res.json({ message: 'Import finished.', insertedCount, skippedCount: skipped.length, skipped });
});

// 8c. PATCH: Bulk update status or priority for selected notices (e-Proceeding "Update Status"/"Priority" buttons)
app.patch('/api/notices/bulk-update', authMiddleware, async (req, res) => {
  const { ids, status, priority_status } = req.body;

  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: 'Select at least one notice.' });
  }
  if (!status && !priority_status) {
    return res.status(400).json({ error: 'Nothing to update — provide status or priority_status.' });
  }

  const ALLOWED_STATUS = ['Open', 'In_Progress', 'Replied', 'Closed'];
  const ALLOWED_PRIORITY = ['Normal', 'High', 'Urgent'];
  if (status && !ALLOWED_STATUS.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${ALLOWED_STATUS.join(', ')}` });
  }
  if (priority_status && !ALLOWED_PRIORITY.includes(priority_status)) {
    return res.status(400).json({ error: `priority_status must be one of: ${ALLOWED_PRIORITY.join(', ')}` });
  }

  try {
    // Only touch notices that belong to an assessee in the logged-in user's company —
    // stops one firm from editing another firm's notices even if they guess an id.
    const setClauses = [];
    const values = [];
    let paramIndex = 1;

    if (status) {
      setClauses.push(`status = $${paramIndex++}`);
      values.push(status);
    }
    if (priority_status) {
      setClauses.push(`priority_status = $${paramIndex++}`);
      values.push(priority_status);
    }

    values.push(req.user.company_id);
    const companyParamIndex = paramIndex++;
    values.push(ids);
    const idsParamIndex = paramIndex++;

    const query = `
      UPDATE notices n
      SET ${setClauses.join(', ')}
      FROM assessees a
      WHERE n.assessee_id = a.id
        AND a.company_id = $${companyParamIndex}
        AND n.id = ANY($${idsParamIndex}::uuid[])
      RETURNING n.id
    `;
    const result = await pool.query(query, values);
    res.json({ message: 'Updated.', updatedCount: result.rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 9. POST: Sync All — mocked RPA sync (SRS Section 3A/Step 3A), company-scoped
app.post('/api/assessees/sync-all', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const assesseesResult = await client.query(
      'SELECT id, pan_tan FROM assessees WHERE company_id = $1 AND (active = true OR active IS NULL)',
      [req.user.company_id]
    );
    const assessees = assesseesResult.rows;

    const noticeCountsResult = await client.query(
      `SELECT assessee_id, COUNT(*) AS count FROM notices
       WHERE assessee_id = ANY($1::uuid[])
       GROUP BY assessee_id`,
      [assessees.map((a) => a.id)]
    );
    const noticeCountByAssessee = {};
    noticeCountsResult.rows.forEach((row) => {
      noticeCountByAssessee[row.assessee_id] = parseInt(row.count, 10);
    });

    let successCount = 0;
    let failCount = 0;
    let newNoticeCount = 0;

    for (const assessee of assessees) {
      const willFail = Math.random() < 0.2;

      if (willFail) {
        const reason = randomFrom(FAILURE_REASONS);
        await client.query(
          `INSERT INTO sync_logs (assessee_id, portal, run_at, result, failure_reason)
           VALUES ($1, 'IncomeTax', NOW(), 'Failed', $2)`,
          [assessee.id, reason]
        );
        await client.query(
          `UPDATE credentials SET status = 'Failed_Login' WHERE assessee_id = $1`,
          [assessee.id]
        );
        failCount++;
        continue;
      }

      await client.query(
        `INSERT INTO sync_logs (assessee_id, portal, run_at, result, failure_reason)
         VALUES ($1, 'IncomeTax', NOW(), 'Success', NULL)`,
        [assessee.id]
      );
      await client.query(
        `UPDATE credentials SET status = 'Valid', last_validated_at = NOW() WHERE assessee_id = $1`,
        [assessee.id]
      );
      successCount++;

      // Guarantee a notice for anyone with zero so far; otherwise it's a random "found something new" chance.
      const hasNoNotices = !noticeCountByAssessee[assessee.id];
      if (hasNoNotices || Math.random() < 0.4) {
        const { ay, fy } = currentAYFY();
        const issueDate = new Date();
        const dueDate = new Date();
        dueDate.setDate(dueDate.getDate() + 15);
        const noticeRefId = crypto.randomBytes(6).toString('hex');
        const isDemand = Math.random() < 0.3;

        if (isDemand) {
          const demandAmount = (Math.floor(Math.random() * 490) + 10) * 100; // ₹1,000 – ₹50,000
          await client.query(
            `INSERT INTO notices
               (assessee_id, source, notice_type, section, issuing_authority,
                issue_date, due_date, status, notice_ref_id, ay, fy, created_at,
                category, demand_amount)
             VALUES ($1, 'Portal', 'Demand Notice', $2, 'Income Tax Dept', $3, $4, 'Open', $5, $6, $7, NOW(),
                'outstanding_demand', $8)`,
            [assessee.id, randomFrom(DEMAND_SECTIONS), issueDate, dueDate, noticeRefId, ay, fy, demandAmount]
          );
        } else {
          await client.query(
            `INSERT INTO notices
               (assessee_id, source, notice_type, section, issuing_authority,
                issue_date, due_date, status, notice_ref_id, ay, fy, created_at, category)
             VALUES ($1, 'Portal', $2, 'Section 143(2)', 'Income Tax Dept', $3, $4, 'Open', $5, $6, $7, NOW(),
                'e_proceeding')`,
            [assessee.id, randomFrom(NOTICE_TYPES), issueDate, dueDate, noticeRefId, ay, fy]
          );
        }
        newNoticeCount++;
      }
    }

    res.json({
      message: 'Sync completed.',
      assesseesSynced: assessees.length,
      successCount,
      failCount,
      newNoticeCount,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// ============================================================
// EMAIL INGESTION MODULE (SRS 4.4)
// ============================================================

const PAN_PATTERN = /[A-Z]{5}[0-9]{4}[A-Z]/;

function getSenderWhitelist() {
  return (process.env.WHITELIST_SENDER_DOMAINS || '')
    .split(',')
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
}

// FR-4.2/4.3/4.4/4.5: connects to one mailbox, pulls anything new since the
// last run, filters by sender domain, extracts a PAN/TAN, and either files
// it against a matching assessee or drops it in the manual-review queue.
async function pollMailbox(account) {
  const password = decrypt(account.encrypted_app_password);
  const client = new ImapFlow({
    host: account.imap_host,
    port: account.imap_port,
    secure: true,
    auth: { user: account.email_address, pass: password },
    logger: false,
  });

  const results = { fetched: 0, matched: 0, unmatched: 0, duplicates: 0, skippedSender: 0 };
  const whitelist = getSenderWhitelist();

  await client.connect();
  try {
    const lock = await client.getMailboxLock('INBOX');
    try {
      const startUid = account.last_uid_seen + 1;
      let highestUidSeen = account.last_uid_seen;

      for await (const msg of client.fetch(`${startUid}:*`, { envelope: true, source: true, uid: true })) {
        if (msg.uid < startUid) continue;
        results.fetched++;
        if (msg.uid > highestUidSeen) highestUidSeen = msg.uid;

        const parsed = await simpleParser(msg.source);
        const senderAddress = (parsed.from && parsed.from.value && parsed.from.value[0] && parsed.from.value[0].address) || '';
        const senderDomain = senderAddress.split('@')[1] || '';

        if (whitelist.length > 0 && !whitelist.includes(senderDomain.toLowerCase())) {
          results.skippedSender++;
          continue;
        }

        const combinedText = `${parsed.subject || ''} ${parsed.text || ''}`.toUpperCase();
        const panMatch = combinedText.match(PAN_PATTERN);
        const extractedPan = panMatch ? panMatch[0] : null;

        // FR-4.5: dedupe against notices already pulled from this mailbox
        const dupCheck = await pool.query(
          'SELECT id FROM notices WHERE source_email_uid = $1 AND source_email_account_id = $2',
          [msg.uid, account.id]
        );
        if (dupCheck.rows.length > 0) {
          results.duplicates++;
          continue;
        }

        let matchedAssessee = null;
        if (extractedPan) {
          const assesseeResult = await pool.query(
            'SELECT id FROM assessees WHERE company_id = $1 AND pan_tan = $2',
            [account.company_id, extractedPan]
          );
          if (assesseeResult.rows.length > 0) matchedAssessee = assesseeResult.rows[0];
        }

        if (matchedAssessee) {
          const { ay, fy } = currentAYFY();
          const dueDate = new Date();
          dueDate.setDate(dueDate.getDate() + 15);
          const noticeRefId = crypto.randomBytes(6).toString('hex');

          await pool.query(
            `INSERT INTO notices
               (assessee_id, source, notice_type, section, issuing_authority,
                issue_date, due_date, status, notice_ref_id, ay, fy, created_at,
                source_email_uid, source_email_account_id, source_email_subject, source_email_sender)
             VALUES ($1, 'Email', 'Email Notice', '', $2, NOW(), $3, 'Open', $4, $5, $6, NOW(), $7, $8, $9, $10)`,
            [
              matchedAssessee.id,
              senderDomain || 'Income Tax Dept',
              dueDate,
              noticeRefId,
              ay,
              fy,
              msg.uid,
              account.id,
              parsed.subject || '',
              senderAddress,
            ]
          );
          results.matched++;
        } else {
          // FR-4.4: no PAN found, or PAN doesn't match any known assessee — manual review
          await pool.query(
            `INSERT INTO unmatched_notices
               (company_id, email_account_id, sender, subject, body_snippet, received_at, extracted_pan)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [
              account.company_id,
              account.id,
              senderAddress,
              parsed.subject || '',
              (parsed.text || '').slice(0, 300),
              parsed.date || new Date(),
              extractedPan,
            ]
          );
          results.unmatched++;
        }
      }

      if (highestUidSeen > account.last_uid_seen) {
        await pool.query('UPDATE email_accounts SET last_uid_seen = $1 WHERE id = $2', [highestUidSeen, account.id]);
      }
    } finally {
      lock.release();
    }
  } finally {
    await client.logout().catch(() => {});
  }

  return results;
}

// FR-4.1: connect a mailbox (IMAP + app-password)
app.post('/api/email-accounts', authMiddleware, requireAdmin, async (req, res) => {
  const { imap_host, imap_port, email_address, app_password } = req.body;
  if (!imap_host || !email_address || !app_password) {
    return res.status(400).json({ error: 'imap_host, email_address and app_password are required.' });
  }

  try {
    const encrypted = encrypt(app_password);
    const result = await pool.query(
      `INSERT INTO email_accounts (company_id, imap_host, imap_port, email_address, encrypted_app_password)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, imap_host, imap_port, email_address, active, created_at`,
      [req.user.company_id, imap_host, imap_port || 993, email_address, encrypted]
    );
    res.status(201).json({ message: 'Mailbox connected.', account: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/email-accounts', authMiddleware, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, imap_host, imap_port, email_address, active, last_uid_seen, created_at
       FROM email_accounts WHERE company_id = $1 ORDER BY created_at ASC`,
      [req.user.company_id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/email-accounts/:id', authMiddleware, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM email_accounts WHERE id = $1 AND company_id = $2', [
      req.params.id,
      req.user.company_id,
    ]);
    res.json({ message: 'Mailbox disconnected.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// FR-4.2: manual "poll now" trigger (a real scheduler can call this same route periodically)
app.post('/api/email-accounts/:id/sync', authMiddleware, requireAdmin, async (req, res) => {
  try {
    const accountResult = await pool.query(
      'SELECT * FROM email_accounts WHERE id = $1 AND company_id = $2',
      [req.params.id, req.user.company_id]
    );
    if (accountResult.rows.length === 0) {
      return res.status(404).json({ error: 'Mailbox not found.' });
    }

    const results = await pollMailbox(accountResult.rows[0]);
    res.json({ message: 'Sync complete.', ...results });
  } catch (err) {
    res.status(500).json({ error: `Could not sync mailbox: ${err.message}` });
  }
});

// FR-4.4: the manual-review queue
app.get('/api/unmatched-notices', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM unmatched_notices WHERE company_id = $1 AND status = 'Pending' ORDER BY created_at DESC`,
      [req.user.company_id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/unmatched-notices/:id/match', authMiddleware, async (req, res) => {
  const { assessee_id } = req.body;
  if (!assessee_id) {
    return res.status(400).json({ error: 'assessee_id is required.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const unmatchedResult = await client.query(
      'SELECT * FROM unmatched_notices WHERE id = $1 AND company_id = $2',
      [req.params.id, req.user.company_id]
    );
    if (unmatchedResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Not found.' });
    }
    const um = unmatchedResult.rows[0];

    const assesseeCheck = await client.query(
      'SELECT id FROM assessees WHERE id = $1 AND company_id = $2',
      [assessee_id, req.user.company_id]
    );
    if (assesseeCheck.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'That assessee does not belong to your company.' });
    }

    const { ay, fy } = currentAYFY();
    const dueDate = new Date();
    dueDate.setDate(dueDate.getDate() + 15);
    const noticeRefId = crypto.randomBytes(6).toString('hex');

    await client.query(
      `INSERT INTO notices
         (assessee_id, source, notice_type, section, issuing_authority,
          issue_date, due_date, status, notice_ref_id, ay, fy, created_at,
          source_email_subject, source_email_sender)
       VALUES ($1, 'Email', 'Email Notice', '', 'Income Tax Dept', NOW(), $2, 'Open', $3, $4, $5, NOW(), $6, $7)`,
      [assessee_id, dueDate, noticeRefId, ay, fy, um.subject, um.sender]
    );

    await client.query(`UPDATE unmatched_notices SET status = 'Matched' WHERE id = $1`, [um.id]);

    await client.query('COMMIT');
    res.json({ message: 'Matched and filed as a notice.' });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.post('/api/unmatched-notices/:id/ignore', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      `UPDATE unmatched_notices SET status = 'Ignored' WHERE id = $1 AND company_id = $2`,
      [req.params.id, req.user.company_id]
    );
    res.json({ message: 'Dismissed.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`ComplianceRadar API running on port ${PORT}`));