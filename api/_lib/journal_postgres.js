import { sql } from '@vercel/postgres';
import { canonicalStringify } from './canonical.js';

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

export const PostgresJournal = {

  getHead: async () => {
    const { rows } = await sql`SELECT head_receipt_hash FROM dag_head WHERE id = 1`;
    if (rows.length === 0) {
      // Auto-initialize genesis
      await sql`INSERT INTO dag_head (id, head_receipt_hash) VALUES (1, ${GENESIS_HASH}) ON CONFLICT (id) DO NOTHING`;
      return GENESIS_HASH;
    }
    return rows[0].head_receipt_hash;
  },

  writeReceipt: async (receipt) => {
    if (!receipt.receipt_hash) {
      throw new Error('Receipt missing receipt_hash');
    }

    const parentHash = receipt.parent_receipt_hash;
    const receiptHash = receipt.receipt_hash;
    const intentHash = receipt.intent_hash;
    const status = receipt.status;
    const reasonCodes = (receipt.reason_codes || []).join(',');
    const canonicalIntent = JSON.stringify(receipt);
    const ruleTrace = JSON.stringify(receipt.rule_trace || []);
    const receiptSignature = receipt.receipt_signature || '';

    // SERIALIZABLE transaction: lock head, validate parent, insert, update head
    const client = await sql.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');

      // 1. Lock and read current head
      const headResult = await client.query(
        'SELECT head_receipt_hash FROM dag_head WHERE id = 1 FOR UPDATE'
      );

      let currentHead = GENESIS_HASH;
      if (headResult.rows.length === 0) {
        // Initialize genesis row inside transaction
        await client.query(
          'INSERT INTO dag_head (id, head_receipt_hash) VALUES (1, $1) ON CONFLICT (id) DO NOTHING',
          [GENESIS_HASH]
        );
      } else {
        currentHead = headResult.rows[0].head_receipt_hash;
      }

      // 2. Fork prevention: parent must match current head
      if (parentHash !== currentHead) {
        await client.query('ROLLBACK');
        throw new Error(`DAG_HEAD_MISMATCH: Expected parent ${currentHead}, got ${parentHash}`);
      }

      // 3. Verify parent exists (unless genesis)
      if (parentHash !== GENESIS_HASH) {
        const parentCheck = await client.query(
          'SELECT 1 FROM receipts WHERE receipt_hash = $1',
          [parentHash]
        );
        if (parentCheck.rows.length === 0) {
          await client.query('ROLLBACK');
          throw new Error(`PARENT_NOT_FOUND: Parent receipt ${parentHash} does not exist`);
        }
      }

      // 4. Insert receipt with signature
      await client.query(
        `INSERT INTO receipts (receipt_hash, parent_receipt_hash, intent_hash, status, reason_code, canonical_intent, rule_trace, receipt_signature)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8)`,
        [receiptHash, parentHash, intentHash, status, reasonCodes, canonicalIntent, ruleTrace, receiptSignature]
      );

      // 5. Update DAG head
      await client.query(
        'UPDATE dag_head SET head_receipt_hash = $1, updated_at = NOW() WHERE id = 1',
        [receiptHash]
      );

      await client.query('COMMIT');
      return true;

    } catch (err) {
      try { await client.query('ROLLBACK'); } catch (_) { /* rollback best-effort */ }
      throw new Error(`JOURNAL_PERSIST_FAILED: ${err.message}`);
    } finally {
      client.release();
    }
  },

  getReceipt: async (hash) => {
    const { rows } = await sql`SELECT * FROM receipts WHERE receipt_hash = ${hash}`;
    if (rows.length === 0) return null;
    return rows[0];
  },

  readAllReceipts: async () => {
    const { rows } = await sql`SELECT * FROM receipts ORDER BY created_at ASC`;
    return rows;
  }
};
