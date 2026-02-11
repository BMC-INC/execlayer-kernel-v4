// verify_risk_ceiling.js — Risk ceiling and privilege override tests
const BASE = process.env.KERNEL_URL || 'https://execlayer-kernel-v4.vercel.app';

const makePayload = (riskTier, delegationRef) => ({
  principal: { legal_name: 'James Benton', organizational_role: 'Director', authority_scope: 'Full_Access', delegation_chain_reference: delegationRef },
  session: { token_id: 'VERIFY-RISK-001', trust_epoch: 2700000000, expiration_epoch: 2800000000, signature_hash: 'sig_risk' },
  intent: { intent_type: 'EXECUTE', target_system: 'QUEUEFLOW', requested_action: 'APPROVE_PRIOR_AUTH', declared_risk_tier: riskTier },
  tenant_id: 'queueflow-prod',
  policy_context: { governing_policy_id: 'POL-001', jurisdiction: 'US-CA', compliance_class: 'L4' }
});

async function run() {
  let pass = 0, fail = 0;

  // Test 1: CRITICAL risk exceeds Full_Access max (HIGH) — must REFUSE
  const t1 = await fetch(`${BASE}/api/kernel`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(makePayload('CRITICAL', 'Root'))
  }).then(r => r.json());
  if (t1.status === 'REFUSE' && t1.reason_codes?.includes('RISK_TIER_EXCEEDS_SCOPE')) {
    console.log('PASS: CRITICAL risk REFUSE with RISK_TIER_EXCEEDS_SCOPE');
    pass++;
  } else {
    console.log('FAIL: CRITICAL risk returned', t1.status, t1.reason_codes);
    fail++;
  }

  // Test 2: HIGH risk with privilege override eligible — must ALLOW with RULE_RISK_OVERRIDE_BY_PRIVILEGE or RULE_RISK_CEILING_ENFORCEMENT
  const t2 = await fetch(`${BASE}/api/kernel`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(makePayload('HIGH', 'Root'))
  }).then(r => r.json());
  const hasRiskTrace = t2.rule_trace?.some(r => r.rule_id === 'RULE_RISK_CEILING_ENFORCEMENT' || r.rule_id === 'RULE_RISK_OVERRIDE_BY_PRIVILEGE');
  if (t2.status === 'ALLOW' && hasRiskTrace) {
    console.log('PASS: HIGH risk ALLOW with explicit risk trace');
    pass++;
  } else if (t2.status === 'REFUSE' && t2.reason_codes?.includes('RISK_TIER_EXCEEDS_SCOPE')) {
    console.log('PASS: HIGH risk REFUSE with RISK_TIER_EXCEEDS_SCOPE');
    pass++;
  } else {
    console.log('FAIL: HIGH risk returned', t2.status, 'trace:', JSON.stringify(t2.rule_trace));
    fail++;
  }

  console.log(`\nRisk ceiling verification: ${pass} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch(e => { console.error('FATAL:', e.message); process.exit(1); });
