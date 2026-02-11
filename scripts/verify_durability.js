import handler from '../api/kernel.js';
import fs from 'fs';
import path from 'path';

// Mock Environment
process.env.KERNEL_SIGNING_SECRET = 'test-secret-123';
process.env.KERNEL_ISSUER_KEY_ID = 'TEST_KEY_01';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const LEDGER_PATH = path.join(DATA_DIR, 'ledger.jsonl');
const HEAD_PATH = path.join(DATA_DIR, 'dag_head.json');

function cleanup() {
  if (fs.existsSync(LEDGER_PATH)) fs.unlinkSync(LEDGER_PATH);
  if (fs.existsSync(HEAD_PATH)) fs.unlinkSync(HEAD_PATH);
  // Re-ensure directory exists in case it was deleted
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

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

async function runTest() {
  console.log('--- STARTING DURABILITY TEST ---');
  cleanup(); // Start fresh

  // 1. First Request
  console.log('\n[STEP 1] Sending First Request...');
  const req1 = createMockReq({
    principal: mockPrincipal,
    session: mockSession,
    intent: {
      intent_type: 'EXECUTE',
      target_system: 'ERP_CORE',
      requested_action: 'UPDATE_CONFIG',
      declared_risk_tier: 'MEDIUM'
    },
    policy_context: mockPolicy,
    tenant_id: 'TENANT_001'
  });
  const res1 = createMockRes();
  
  await handler(req1, res1);
  
  if (res1.statusCode !== 200) {
    console.error('FAILED: Request 1 failed', res1.body);
    process.exit(1);
  }
  
  const receipt1 = res1.body;
  console.log('SUCCESS: Receipt 1 generated:', receipt1.receipt_hash);

  // 2. Verify Ledger Write
  console.log('\n[STEP 2] Verifying Ledger Persistence...');
  if (!fs.existsSync(LEDGER_PATH)) {
    console.error('FAILED: Ledger file not created');
    process.exit(1);
  }
  const ledgerContent = fs.readFileSync(LEDGER_PATH, 'utf8');
  if (!ledgerContent.includes(receipt1.receipt_hash)) {
    console.error('FAILED: Receipt 1 not found in ledger');
    process.exit(1);
  }
  console.log('SUCCESS: Ledger contains receipt 1');

  // 3. Second Request (Must verify parent hash)
  console.log('\n[STEP 3] Sending Second Request (Testing DAG Link)...');
  const req2 = createMockReq({
    principal: mockPrincipal,
    session: mockSession,
    intent: {
      intent_type: 'EXECUTE',
      target_system: 'ERP_CORE',
      requested_action: 'READ_LOGS',
      declared_risk_tier: 'LOW'
    },
    policy_context: mockPolicy,
    tenant_id: 'TENANT_001'
  });
  const res2 = createMockRes();
  
  await handler(req2, res2);
  
  const receipt2 = res2.body;
  console.log('SUCCESS: Receipt 2 generated:', receipt2.receipt_hash);
  console.log('Parent Receipt Hash:', receipt2.parent_receipt_hash);

  if (receipt2.parent_receipt_hash !== receipt1.receipt_hash) {
    console.error(`FAILED: Chain Broken! Expected parent ${receipt1.receipt_hash}, got ${receipt2.parent_receipt_hash}`);
    process.exit(1);
  }
  console.log('SUCCESS: DAG Chain intact.');

  console.log('\n--- DURABILITY TEST PASSED ---');
  cleanup();
}

runTest().catch(console.error);
