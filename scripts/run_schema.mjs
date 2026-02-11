import pg from 'pg';

const { Pool } = pg;

async function main() {
  console.log('Connecting to:', process.env.POSTGRES_URL ? 'URL SET' : 'URL MISSING');
  
  const pool = new Pool({
    connectionString: process.env.POSTGRES_URL,
    ssl: true
  });

  try {
    const testRes = await pool.query('SELECT 1 as connected');
    console.log('CONNECTION OK:', testRes.rows[0]);
  } catch (e) {
    console.error('CONNECTION FAILED:', e.message);
    console.error('FULL ERROR:', JSON.stringify(e, Object.getOwnPropertyNames(e)));
    process.exit(1);
  }

  const statements = [
    `CREATE TABLE IF NOT EXISTS receipts (
      receipt_hash TEXT PRIMARY KEY,
      parent_receipt_hash TEXT NOT NULL,
      intent_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      status TEXT NOT NULL,
      reason_code TEXT NOT NULL,
      canonical_intent JSONB NOT NULL,
      rule_trace JSONB NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS dag_head (
      id INT PRIMARY KEY,
      head_receipt_hash TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`,
    `INSERT INTO dag_head (id, head_receipt_hash) VALUES (1, '0000000000000000000000000000000000000000000000000000000000000000') ON CONFLICT (id) DO NOTHING`,
    `CREATE INDEX IF NOT EXISTS idx_receipts_parent ON receipts (parent_receipt_hash)`,
    `CREATE INDEX IF NOT EXISTS idx_receipts_created ON receipts (created_at ASC)`
  ];

  for (let i = 0; i < statements.length; i++) {
    try {
      await pool.query(statements[i]);
      console.log(`STMT ${i+1}/${statements.length}: OK`);
    } catch (e) {
      console.error(`STMT ${i+1}/${statements.length}: FAIL`);
      console.error('Error code:', e.code);
      console.error('Error message:', e.message);
      console.error('Error detail:', e.detail);
    }
  }

  try {
    const headRes = await pool.query('SELECT * FROM dag_head');
    console.log('dag_head:', JSON.stringify(headRes.rows));
    const receiptRes = await pool.query('SELECT COUNT(*) as cnt FROM receipts');
    console.log('receipts count:', receiptRes.rows[0].cnt);
  } catch (e) {
    console.error('QUERY FAIL:', e.message);
  }

  await pool.end();
}

main().catch(e => { console.error('FATAL:', e.message); process.exit(1); });
