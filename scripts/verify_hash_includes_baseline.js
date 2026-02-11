// verify_hash_includes_baseline.js — ALLOW must contain baseline_version in envelope and RULE_BASELINE_VERSION_ENFORCEMENT in trace
const BASE = process.env.KERNEL_URL || 'https://execlayer-kernel-v4.vercel.app';

async function run() {
  const res = await fetch(`${BASE}/api/kernel`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      principal: { legal_name: 'Baseline Test', organizational_role: 'Director', authority_scope: 'Full_Access', delegation_chain_reference: 'Root' },
      session: { token_id: 'BL-HASH-001', trust_epoch: 2700000000, expiration_epoch: 2800000000, signature_hash: 'sig_bl3' },
      intent: { intent_type: 'EXECUTE', target_system: 'QUEUEFLOW', requested_action: 'READ_STATUS', declared_risk_tier: 'LOW', baseline_version: '1.0' },
      tenant_id: 'queueflow-prod',
      policy_context: { governing_policy_id: 'POL-001', jurisdiction: 'US-CA', compliance_class: 'L4' }
    })
  }).then(r => r.json());

  let pass = 0, fail = 0;

  // Check baseline_version in response
  if (res.baseline_version === '1.0') {
    console.log('PASS: baseline_version = 1.0 in response');
    pass++;
  } else {
    console.log('FAIL: baseline_version missing or wrong:', res.baseline_version);
    fail++;
  }

  // Check RULE_BASELINE_VERSION_ENFORCEMENT is first in trace
  const firstRule = res.rule_trace?.[0];
  if (firstRule?.rule_id === 'RULE_BASELINE_VERSION_ENFORCEMENT' && firstRule?.result === 'ALLOW') {
    console.log('PASS: RULE_BASELINE_VERSION_ENFORCEMENT is first rule in trace');
    pass++;
  } else {
    console.log('FAIL: First rule is', firstRule?.rule_id, firstRule?.result);
    fail++;
  }

  // Check status
  if (res.status === 'ALLOW' || res.status === 'REFUSE') {
    console.log('PASS: Normal decision outcome:', res.status);
    pass++;
  } else {
    console.log('FAIL: Unexpected status:', res.status);
    fail++;
  }

  console.log(`\nBaseline hash verification: ${pass} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch(e => { console.error('FATAL:', e.message); process.exit(1); });
