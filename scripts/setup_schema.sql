-- ExecLayer Kernel V4 – Postgres Schema
-- Target: Vercel Postgres / Neon Postgres

CREATE TABLE IF NOT EXISTS receipts (
  receipt_hash TEXT PRIMARY KEY,
  parent_receipt_hash TEXT NOT NULL,
  intent_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  canonical_intent JSONB NOT NULL,
  rule_trace JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS dag_head (
  id INT PRIMARY KEY,
  head_receipt_hash TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Genesis initialization
INSERT INTO dag_head (id, head_receipt_hash)
VALUES (1, '0000000000000000000000000000000000000000000000000000000000000000')
ON CONFLICT (id) DO NOTHING;

-- Index for parent chain lookups
CREATE INDEX IF NOT EXISTS idx_receipts_parent ON receipts (parent_receipt_hash);
CREATE INDEX IF NOT EXISTS idx_receipts_created ON receipts (created_at ASC);
