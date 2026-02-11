import handler from '../api/kernel.js';
import { Journal } from '../api/_lib/journal.js';
import fs from 'fs';
import path from 'path';
import { canonicalStringify } from '../api/_lib/canonical.js';
import { sha256Hex, hmacSha256Hex } from '../api/_lib/crypto.js';

// Mock Environment
process.env.KERNEL_SIGNING_SECRET = 'test-secret-123';
process.env.KERNEL_ISSUER_KEY_ID = 'TEST_KEY_01';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const LEDGER_PATH = path.join(DATA_DIR, 'ledger.jsonl');
const HEAD_PATH = path.join(DATA_DIR, 'dag_head.json');

// Mock Request/Response
function createMockReq(body) {
  return {
    method: 'POST',
    body: body
  };
}

function createMockRes() {
  const res = {
    statusCode: 200,
    headers: {},
    body: null,
    status: function(code) {
      this.statusCode = code;
      return this;
    },
    json: function(data) {
      this.body = data;
      return this;
    }
  };
  return res;
}

const mockPrincipal = {
    legal_name: 'Test Setup',
    organizational_role: 'System Admin',
    authority_scope: 'Full_Access',
    delegation_chain_reference: 'ROOT_EXEC_AUTHORITY_V4'
  };
  
const mockSession = {
    token_id: 'tok_123',
    trust_epoch: 2700000000,
    expiration_epoch: 2800000000,
    signature_hash: 'sig_123'
};

const mockPolicy = {
    governing_policy_id: 'POL-001',
    jurisdiction: 'US-CA',
    compliance_class: 'L4'
};


// Function to simulate a valid previous run to generate a receipt we can corrupt later
// Note: We cannot easily just call handler() because handler() does integrity check on load
// and we want to control the state.
// BUT, for this test, let's just create the file manually.

async function runTest() {
  console.log('--- STARTING CORRUPTION TEST ---');
  
  if (fs.existsSync(DATA_DIR)) {
      fs.rmSync(DATA_DIR, { recursive: true, force: true });
  }
  fs.mkdirSync(DATA_DIR);

  // 1. Create a VALID generic receipt
  const validReceipt = {
      status: 'ALLOW',
      session_id: 'TEST_SESS_01',
      receipt_hash: 'aaaabbbbccccddddeeeeffff00001111', 
      parent_receipt_hash: '0000000000000000000000000000000000000000000000000000000000000000', // Genesis
      // ... minimal fields for integrity check to pass "structure" ...
      // Actually Integrity check re-computes hash. So we need a REAL valid receipt structure.
      // This is hard to fake manually without duplicating all logic.
      // So... we run the handler ONCE to generate valid state.
  };

  // We'll run handler safely once to generate valid state
  const req1 = createMockReq({
    principal: mockPrincipal,
    session: mockSession,
    intent: { intent_type: 'EXECUTE', target_system: 'SYS', requested_action: 'ACT', declared_risk_tier: 'LOW' },
    policy_context: mockPolicy,
    tenant_id: 'TENANT_001'
  });
  const res1 = createMockRes();
  
  // Note: handler imports Integrity. Integrity reads FS.
  await handler(req1, res1);
  if (res1.statusCode !== 200) {
      console.error('Setup failed: Could not generate valid initial state');
      process.exit(1);
  }
  
  // Now we have a valid ledger with 1 entry.
  // 2. CORRUPT IT.
  console.log('\n[STEP 1] Corrupting Ledger...');
  // Append a garbage line
  fs.appendFileSync(LEDGER_PATH, '\n{"bad": "json"}\n');
  
  // 3. Restart / New Request
  // Since `handler` runs top-level try/catch for integrity, we can't "re-import" it easily in ESM to re-run top level code.
  // However, `Integrity.checkIntegrity()` is called inside `handler` on every request in our implementation 
  // (check kernel.js: `await Integrity.checkIntegrity()`).
  
  console.log('\n[STEP 2] Sending Request to Corrupted System...');
  const req2 = createMockReq({
    principal: mockPrincipal,
    session: mockSession,
    intent: { intent_type: 'EXECUTE', target_system: 'SYS', requested_action: 'ACT', declared_risk_tier: 'LOW' },
    policy_context: mockPolicy,
    tenant_id: 'TENANT_001'
  });
  const res2 = createMockRes();

  await handler(req2, res2);

  // 4. Verify Refusal / Lockdown
  console.log('Status Code:', res2.statusCode);
  console.log('Response Body:', res2.body);

  if (res2.statusCode === 503 && res2.body.error_code === 'SYSTEM_LOCKDOWN') {
      console.log('SUCCESS: System entered LOCKDOWN mode as expected.');
      console.log('Reason:', res2.body.context.reason);
  } else {
      console.error('FAILED: System did NOT lockdown. Status:', res2.statusCode);
      process.exit(1);
  }

  console.log('\n--- CORRUPTION TEST PASSED ---');
  
  // Cleanup
  fs.rmSync(DATA_DIR, { recursive: true, force: true });
}

runTest().catch(console.error);
