// verify_scope_enforcement.js — Cross-tenant and cross-system refusal tests
const BASE = process.env.KERNEL_URL || 'https://execlayer-kernel-v4.vercel.app';

const basePayload = (overrides) => ({
  principal: { legal_name: 'James Benton', organizational_role: 'Director', authority_scope: 'Full_Access', delegation_chain_reference: 'Root' },
  session: { token_id: 'VERIFY-SCOPE-001', trust_epoch: 2700000000, expiration_epoch: 2800000000, signature_hash: 'sig_verify' },
  intent: { intent_type: 'EXECUTE', target_system: 'QUEUEFLOW', requested_action: 'APPROVE_PRIOR_AUTH', declared_risk_tier: 'LOW', ...overrides.intent },
  tenant_id: overrides.tenant_id || 'queueflow-prod',
  policy_context: { governing_policy_id: 'POL-001', jurisdiction: 'US-CA', compliance_class: 'L4' }
});

async function run() {
  let pass = 0, fail = 0;

  // Test: Cross-tenant must REFUSE
  const t1 = await fetch(`${BASE}/api/kernel`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(basePayload({ tenant_id: 'priorauth-prod', intent: {} }))
  }).then(r => r.json());
  if (t1.status === 'REFUSE' && t1.reason_codes?.includes('TENANT_MISMATCH')) {
    console.log('PASS: Cross-tenant REFUSE with TENANT_MISMATCH');
    pass++;
  } else {
    console.log('FAIL: Cross-tenant returned', t1.status, t1.reason_codes);
    fail++;
  }

  // Test: Cross-system must REFUSE
  const t2 = await fetch(`${BASE}/api/kernel`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(basePayload({ tenant_id: 'queueflow-prod', intent: { target_system: 'PRIORAUTH_GUARD' } }))
  }).then(r => r.json());
  if (t2.status === 'REFUSE' && t2.reason_codes?.includes('SYSTEM_SCOPE_MISMATCH')) {
    console.log('PASS: Cross-system REFUSE with SYSTEM_SCOPE_MISMATCH');
    pass++;
  } else {
    console.log('FAIL: Cross-system returned', t2.status, t2.reason_codes);
    fail++;
  }

  console.log(`\nScope verification: ${pass} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch(e => { console.error('FATAL:', e.message); process.exit(1); });
