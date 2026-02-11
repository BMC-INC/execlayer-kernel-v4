import { sha256Hex } from './crypto.js';
import { canonicalStringify } from './canonical.js';

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

export const Integrity = {
  /**
   * Full chain verification — for admin endpoint only.
   * NOT called on cold start in serverless.
   * Accepts a list of receipt objects ordered by creation time.
   */
  verifyFullChain: async (receipts, currentHead) => {
    if (receipts.length === 0) {
      if (currentHead !== GENESIS_HASH) {
        return { valid: false, reason: 'Non-genesis head with empty ledger' };
      }
      return { valid: true };
    }

    let prevHash = GENESIS_HASH;

    for (let i = 0; i < receipts.length; i++) {
      const entry = receipts[i];

      // For Postgres rows, the full receipt is stored in canonical_intent
      let fullReceipt = entry;
      if (entry.canonical_intent && typeof entry.canonical_intent === 'object') {
        fullReceipt = entry.canonical_intent;
      } else if (entry.canonical_intent && typeof entry.canonical_intent === 'string') {
        try { fullReceipt = JSON.parse(entry.canonical_intent); } catch (e) { fullReceipt = entry; }
      }

      // 1. Verify parent link
      if (fullReceipt.parent_receipt_hash !== prevHash) {
        return {
          valid: false,
          reason: `Chain broken at height ${i}. Expected parent ${prevHash}, got ${fullReceipt.parent_receipt_hash}`
        };
      }

      // 2. Verify hash self-consistency
      const { receipt_hash, receipt_signature, next_parent_receipt_hash, ...core } = fullReceipt;
      const computedHash = await sha256Hex(canonicalStringify(core));
      if (computedHash !== receipt_hash) {
        return {
          valid: false,
          reason: `Hash mismatch at height ${i}. Computed ${computedHash}, stored ${receipt_hash}`
        };
      }

      prevHash = receipt_hash;
    }

    // 3. Verify head
    if (prevHash !== currentHead) {
      return {
        valid: false,
        reason: `Head mismatch. Ledger ends at ${prevHash}, HEAD points to ${currentHead}`
      };
    }

    return { valid: true };
  }
};
