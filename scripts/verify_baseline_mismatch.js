// verify_baseline_mismatch.js — EXECUTE with wrong baseline_version must REFUSE
const BASE = process.env.KERNEL_URL || 'https://execlayer-kernel-v4.vercel.app';

async function run() {
  const res = await fetch(`${BASE}/api/kernel`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      principal: { legal_name: 'Baseline Test', organizational_role: 'Director', authority_scope: 'Full_Access', delegation_chain_reference: 'Root' },
      session: { token_id: 'BL-MIS-001', trust_epoch: 2700000000, expiration_epoch: 2800000000, signature_hash: 'sig_bl2' },
      intent: { intent_type: 'EXECUTE', target_system: 'QUEUEFLOW', requested_action: 'READ_STATUS', declared_risk_tier: 'LOW', baseline_version: '0.9' },
      tenant_id: 'queueflow-prod',
      policy_context: { governing_policy_id: 'POL-001', jurisdiction: 'US-CA', compliance_class: 'L4' }
    })
  }).then(r => r.json());

  if (res.status === 'REFUSE' && res.reason_codes?.includes('BASELINE_VERSION_MISMATCH')) {
    console.log('PASS: baseline_version 0.9 → REFUSE BASELINE_VERSION_MISMATCH');
  } else {
    console.log('FAIL: Expected REFUSE BASELINE_VERSION_MISMATCH, got', res.status, res.reason_codes);
    process.exit(1);
  }
}

run().catch(e => { console.error('FATAL:', e.message); process.exit(1); });
