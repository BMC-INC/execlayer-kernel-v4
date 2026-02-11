import { JournalAdapter } from '../_lib/journal_adapter.js';
import { Integrity } from '../_lib/integrity.js';
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

    const receipts = await JournalAdapter.readAllReceipts();
    const currentHead = await JournalAdapter.getHead();

    const result = await Integrity.verifyFullChain(receipts, currentHead);

    if (result.valid) {
      res.status(200).json({
        status: 'VALID',
        receipt_count: receipts.length,
        current_head: currentHead
      });
    } else {
      res.status(200).json({
        status: 'LOCKDOWN',
        reason: result.reason,
        receipt_count: receipts.length,
        current_head: currentHead
      });
    }
  } catch (err) {
    res.status(500).json(UnifiedSerializer.serializeError('INTEGRITY_CHECK_FAILED', err?.message || 'Unknown error'));
  }
}
