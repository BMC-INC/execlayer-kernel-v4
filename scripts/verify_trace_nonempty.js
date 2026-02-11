// verify_trace_nonempty.js — Ensures ALLOW responses have non-empty rule_trace
const BASE = process.env.KERNEL_URL || 'https://execlayer-kernel-v4.vercel.app';

async function run() {
  let pass = 0, fail = 0;

  // Test: Valid EXECUTE with LOW risk — must ALLOW with non-empty rule_trace
  const payload = {
    principal: { legal_name: 'Trace Test', organizational_role: 'System Admin', authority_scope: 'Full_Access', delegation_chain_reference: 'ROOT_EXEC_AUTHORITY_V4' },
    session: { token_id: 'VERIFY-TRACE-001', trust_epoch: 2700000000, expiration_epoch: 2800000000, signature_hash: 'sig_trace' },
    intent: { intent_type: 'EXECUTE', target_system: 'QUEUEFLOW', requested_action: 'READ_STATUS', declared_risk_tier: 'LOW' },
    tenant_id: 'queueflow-prod',
    policy_context: { governing_policy_id: 'POL-001', jurisdiction: 'US-CA', compliance_class: 'L4' }
  };

  const res = await fetch(`${BASE}/api/kernel`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(r => r.json());

  if (res.status === 'ALLOW' && Array.isArray(res.rule_trace) && res.rule_trace.length > 0) {
    console.log('PASS: ALLOW with non-empty rule_trace (' + res.rule_trace.length + ' entries)');
    res.rule_trace.forEach(r => console.log('  -', r.rule_id, ':', r.result));
    pass++;
  } else if (res.status === 'ALLOW') {
    console.log('FAIL: ALLOW but rule_trace is empty or missing');
    fail++;
  } else {
    console.log('FAIL: Expected ALLOW, got', res.status, res.reason_codes);
    fail++;
  }

  // Test: GENERAL_REQUEST must also have trace
  const payload2 = {
    principal: { legal_name: 'Trace Test 2', organizational_role: 'Analyst', authority_scope: 'Full_Access', delegation_chain_reference: 'FINANCE_ANALYST_V1' },
    session: { token_id: 'VERIFY-TRACE-002', trust_epoch: 2700000000, expiration_epoch: 2800000000, signature_hash: 'sig_trace_2' },
    intent: { intent_type: 'GENERAL_REQUEST', target_system: 'ERP_CORE', requested_action: 'READ_STATUS', declared_risk_tier: 'LOW' },
    policy_context: { governing_policy_id: 'POL-001', jurisdiction: 'US-CA', compliance_class: 'L4' }
  };

  const res2 = await fetch(`${BASE}/api/kernel`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload2)
  }).then(r => r.json());

  if (res2.status === 'ALLOW' && Array.isArray(res2.rule_trace) && res2.rule_trace.length > 0) {
    console.log('PASS: GENERAL_REQUEST ALLOW with non-empty rule_trace (' + res2.rule_trace.length + ' entries)');
    pass++;
  } else if (res2.status === 'ALLOW') {
    console.log('FAIL: GENERAL_REQUEST ALLOW but rule_trace empty');
    fail++;
  } else {
    console.log('INFO: GENERAL_REQUEST returned', res2.status, '(may be expected based on scope)');
    pass++;
  }

  console.log(`\nTrace verification: ${pass} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
}

run().catch(e => { console.error('FATAL:', e.message); process.exit(1); });
