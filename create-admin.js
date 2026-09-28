// One-time setup script — creates a real admin login, or fixes an existing
// user's password if the row already exists.
//
// Usage: node create-admin.js <email> <password> [displayName]

require('dotenv').config();
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

async function main() {
  const [, , email, password, name] = process.argv;

  if (!email || !password) {
    console.log('Usage: node create-admin.js <email> <password> [displayName]');
    process.exit(1);
  }

  const hash = await bcrypt.hash(password, 10);
  const normalizedEmail = email.trim().toLowerCase();

  const existing = await pool.query('SELECT id, name FROM users WHERE email = $1', [normalizedEmail]);

  if (existing.rows.length > 0) {
    await pool.query('UPDATE users SET password_hash = $1, role = $2 WHERE email = $3', [
      hash,
      'Admin',
      normalizedEmail,
    ]);
    console.log(`Updated password for existing user: ${normalizedEmail} (${existing.rows[0].name})`);
  } else {
    const company = await pool.query('SELECT id FROM companies ORDER BY created_at ASC NULLS LAST LIMIT 1');
    if (company.rows.length === 0) {
      throw new Error('No company exists yet — insert one row into companies before creating an admin.');
    }
    const result = await pool.query(
      `INSERT INTO users (company_id, name, email, password_hash, role)
       VALUES ($1, $2, $3, $4, 'Admin')
       RETURNING id`,
      [company.rows[0].id, name || 'Admin', normalizedEmail, hash]
    );
    console.log(`Created new admin user: ${normalizedEmail} (id ${result.rows[0].id})`);
  }

  await pool.end();
}

main().catch((err) => {
  console.error('Error:', err.message);
  process.exit(1);
});