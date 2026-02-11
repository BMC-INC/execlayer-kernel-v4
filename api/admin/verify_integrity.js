import { JournalAdapter } from '../_lib/journal_adapter.js';
import { hmacSha256Hex } from '../_lib/crypto.js';
import { UnifiedSerializer } from '../_lib/serializer.js';

export default async function handler(req, res) {
  try {
    if (req.method !== 'POST') {
      res.status(405).json(UnifiedSerializer.serializeError('METHOD_NOT_ALLOWED', 'Only POST allowed'));
      return;
    }

    const adminSecret = process.env.ADMIN_SECRET;
    if (adminSecret) {
      const authHeader = req.headers['authorization'] || '';
      const token = authHeader.replace('Bearer ', '');
      if (token !== adminSecret) {
        res.status(403).json(UnifiedSerializer.serializeError('UNAUTHORIZED', 'Invalid admin credentials'));
        return;
      }
    }

    const signingSecret = process.env.KERNEL_SIGNING_SECRET;
    const receipts = await JournalAdapter.readAllReceipts();
    const currentHead = await JournalAdapter.getHead();

    // Chain link verification
    let chainValid = true;
    let chainReason = null;
    const signatureResults = [];

    // Sort by created_at ascending for chain walk
    const sorted = [...receipts].sort((a, b) => new Date(a.created_at) - new Date(b.created_at));

    // Verify parent chain links
    for (let i = 0; i < sorted.length; i++) {
      const r = sorted[i];
      if (i === 0) {
        // First receipt's parent should be GENESIS
        if (r.parent_receipt_hash !== '0000000000000000000000000000000000000000000000000000000000000000') {
          chainValid = false;
          chainReason = `First receipt ${r.receipt_hash} has non-genesis parent: ${r.parent_receipt_hash}`;
          break;
        }
      } else {
        // Each receipt's parent should be the previous receipt's hash
        if (r.parent_receipt_hash !== sorted[i - 1].receipt_hash) {
          chainValid = false;
          chainReason = `Receipt ${r.receipt_hash} parent mismatch: expected ${sorted[i - 1].receipt_hash}, got ${r.parent_receipt_hash}`;
          break;
        }
      }

      // Verify HMAC signature if signing secret is available
      if (signingSecret && r.receipt_signature) {
        const expectedSig = await hmacSha256Hex(signingSecret, r.receipt_hash + r.parent_receipt_hash + r.intent_hash);
        const sigValid = expectedSig === r.receipt_signature;
        signatureResults.push({
          receipt_hash: r.receipt_hash.slice(0, 12) + '...',
          signature_valid: sigValid
        });
        if (!sigValid) {
          chainValid = false;
          chainReason = `Receipt ${r.receipt_hash} has invalid HMAC signature (possible tampering)`;
          break;
        }
      }
    }

    // Verify head matches last receipt
    if (chainValid && sorted.length > 0) {
      const lastReceipt = sorted[sorted.length - 1];
      if (currentHead !== lastReceipt.receipt_hash) {
        chainValid = false;
        chainReason = `Head ${currentHead} does not match newest receipt ${lastReceipt.receipt_hash}`;
      }
    }

    if (chainValid) {
      res.status(200).json({
        status: 'VALID',
        receipt_count: receipts.length,
        current_head: currentHead,
        signatures_verified: signatureResults.length,
        signature_results: signatureResults
      });
    } else {
      res.status(200).json({
        status: 'LOCKDOWN',
        reason: chainReason,
        receipt_count: receipts.length,
        current_head: currentHead,
        signatures_verified: signatureResults.length,
        signature_results: signatureResults
      });
    }
  } catch (err) {
    res.status(500).json(UnifiedSerializer.serializeError('INTEGRITY_CHECK_FAILED', err?.message || 'Unknown error'));
  }
}
