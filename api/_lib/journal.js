import fs from 'fs';
import path from 'path';
import { canonicalStringify } from './canonical.js';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const LEDGER_PATH = path.join(DATA_DIR, 'ledger.jsonl');
const HEAD_PATH = path.join(DATA_DIR, 'dag_head.json');
const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

// Production guard
if (process.env.NODE_ENV && process.env.NODE_ENV !== 'development') {
  throw new Error('FILESYSTEM_DISABLED_IN_PRODUCTION: FileJournal cannot be used outside development');
}

// Ensure data directory exists (dev only)
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

export const Journal = {
  getHead: () => {
    try {
      if (!fs.existsSync(HEAD_PATH)) {
        return GENESIS_HASH;
      }
      const data = fs.readFileSync(HEAD_PATH, 'utf8');
      const parsed = JSON.parse(data);
      return parsed.head_hash || GENESIS_HASH;
    } catch (err) {
      throw new Error('JOURNAL_CORRUPTION: Unable to read DAG head');
    }
  },

  writeReceipt: async (receipt) => {
    if (!receipt.receipt_hash) {
      throw new Error('Receipt missing receipt_hash');
    }

    try {
      const line = canonicalStringify(receipt) + '\n';
      fs.appendFileSync(LEDGER_PATH, line, { encoding: 'utf8', flush: true });

      const headData = JSON.stringify({ head_hash: receipt.receipt_hash });
      fs.writeFileSync(HEAD_PATH, headData, { encoding: 'utf8', flush: true });

      return true;
    } catch (err) {
      throw new Error(`JOURNAL_PERSIST_FAILED: ${err.message}`);
    }
  },

  readLedger: () => {
    if (!fs.existsSync(LEDGER_PATH)) return [];
    const content = fs.readFileSync(LEDGER_PATH, 'utf8');
    return content.trim().split('\n').map(line => {
      try {
        return JSON.parse(line);
      } catch (e) {
        return null;
      }
    }).filter(x => x !== null);
  }
};
