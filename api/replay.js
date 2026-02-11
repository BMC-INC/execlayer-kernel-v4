import { canonicalStringify } from './_lib/canonical.js';
import { sha256Hex, hmacSha256Hex } from './_lib/crypto.js';
import { UnifiedSerializer } from './_lib/serializer.js';

const BASE_EPOCH = 1700000000;

function getPrivilegeTier(ref) {
  if (ref === 'ROOT_EXEC_AUTHORITY_V4') return 'TIER_0';
  if (ref === 'FINANCE_ANALYST_V1') return 'TIER_4';
  return 'TIER_3';
}

function isWriteAction(action) {
  const patterns = ['modify', 'update', 'delete', 'write', 'change', 'transfer', 'execute'];
  const lower = action.toLowerCase();
  return patterns.some(p => lower.includes(p));
}

function isHostile(action) {
  const patterns = ['rm -rf', 'drop database', 'wipe'];
  const lower = action.toLowerCase();
  return patterns.some(p => lower.includes(p));
}

function parseAmount(params) {
  if (!params || params.amount_usd === undefined) return null;
  const a = params.amount_usd;
  if (typeof a === 'number') return a;
  if (typeof a === 'string') {
    const c = a.replace(/[$,]/g, '').toLowerCase();
    let m = 1;
    if (c.endsWith('m')) m = 1000000;
    else if (c.endsWith('k')) m = 1000;
    else if (c.endsWith('b')) m = 1000000000;
    const n = parseFloat(c.replace(/[mkb]/g, ''));
    if (!isNaN(n)) return n * m;
  }
  return null;
}

function runRules(principal, session, intent) {
  const rules = [];
  const codes = [];
  let tier = intent.declared_risk_tier || 'LOW';
  let outcome = 'ALLOW';

  if (session.expiration_epoch && session.trust_epoch && session.expiration_epoch < session.trust_epoch) {
    rules.push({ rule_id: 'TOKEN_EXPIRY', type: 'SESSION_VALIDATION', input_facts: { expiration_epoch: session.expiration_epoch, trust_epoch: session.trust_epoch }, decision: 'REFUSE' });
    codes.push('TOKEN_EXPIRED_EPOCH');
    outcome = 'REFUSE';
  }

  if (isHostile(intent.requested_action)) {
    rules.push({ rule_id: 'HOSTILE_PAYLOAD_BASIC', type: 'SECURITY_SCAN', input_facts: { requested_action: intent.requested_action, pattern_match: 'HOSTILE_DESTRUCTIVE' }, decision: 'REFUSE' });
    codes.push('HOSTILE_DESTRUCTIVE_PATTERN');
    tier = 'CRITICAL';
    outcome = 'REFUSE';
  }

  if (principal.authority_scope === 'Read_Only' && isWriteAction(intent.requested_action)) {
    rules.push({ rule_id: 'SCOPE_MISMATCH', type: 'AUTHORIZATION', input_facts: { authority_scope: principal.authority_scope, requested_action: intent.requested_action, is_write_action: true }, decision: 'REFUSE' });
    codes.push('AUTH_SCOPE_MISMATCH_R401');
    outcome = 'REFUSE';
  }

  if (principal.delegation_chain_reference === 'ROOT_EXEC_AUTHORITY_V4') {
    const levels = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
    if ((levels[tier] || 1) < 2) tier = 'MEDIUM';
    rules.push({ rule_id: 'RISK_OVERRIDE_BY_PRIVILEGE', type: 'PRIVILEGE_ESCALATION', input_facts: { delegation_chain_reference: principal.delegation_chain_reference, original_risk_tier: intent.declared_risk_tier, elevated_risk_tier: tier }, decision: 'ALLOW' });
  }

  const isFin = intent.intent_type === 'FINANCIAL_TRANSFER' || intent.requested_action.toLowerCase().includes('wire') || intent.requested_action.toLowerCase().includes('transfer');
  if (isFin) {
    const amt = parseAmount(intent.parameters);
    if (amt === null && intent.intent_type === 'FINANCIAL_TRANSFER') {
      rules.push({ rule_id: 'HIGH_VALUE_TRANSACTION_PROTOCOL', type: 'FINANCIAL_CONTROL', input_facts: { intent_type: intent.intent_type, amount_usd: null }, decision: 'REFUSE' });
      codes.push('AMOUNT_REQUIRED');
      outcome = 'REFUSE';
    } else if (amt !== null && amt >= 1000000) {
      tier = 'HIGH';
      const sigs = intent.parameters?.multisig_signatures || [];
      const roles = intent.parameters?.multisig_roles || [];
      const req = ['Finance Director', 'Treasury Head', 'Audit Controller'];
      const hasSigs = sigs.length >= 3;
      const hasRoles = req.every(r => roles.includes(r));
      if (!hasSigs || !hasRoles) {
        rules.push({ rule_id: 'MULTISIG_CONSENSUS_GATE', type: 'APPROVAL_GATE', input_facts: { amount_usd: amt, signatures_count: sigs.length, roles_present: roles, required_roles: req }, decision: 'REFUSE' });
        codes.push('L4_CONSENSUS_PENDING');
        outcome = 'REFUSE';
      } else {
        rules.push({ rule_id: 'MULTISIG_CONSENSUS_GATE', type: 'APPROVAL_GATE', input_facts: { amount_usd: amt, signatures_count: sigs.length, roles_present: roles }, decision: 'ALLOW' });
      }
      rules.push({ rule_id: 'HIGH_VALUE_TRANSACTION_PROTOCOL', type: 'FINANCIAL_CONTROL', input_facts: { amount_usd: amt, threshold: 1000000, effective_risk_tier: tier }, decision: outcome === 'REFUSE' ? 'REFUSE' : 'ALLOW' });
    }
  }

  return { rules, codes, tier, outcome };
}

function buildBlueprint(principal, policyCtx, intentHash, gov) {
  const prefix = intentHash.slice(0, 10);
  const offset = parseInt(prefix, 16) % 10000000;
  return {
    blueprint_meta: {
      blueprint_id: 'BP-' + intentHash.slice(0, 12).toUpperCase(),
      version: '4.0',
      risk_tier: gov.tier,
      policy_id: policyCtx.governing_policy_id,
      jurisdiction: policyCtx.jurisdiction,
      compliance_class: policyCtx.compliance_class,
      created_at_epoch: BASE_EPOCH + offset
    },
    authority: {
      principal_role: principal.organizational_role,
      authority_scope: principal.authority_scope,
      delegation_chain_reference: principal.delegation_chain_reference,
      privilege_tier: getPrivilegeTier(principal.delegation_chain_reference)
    },
    decision: { outcome: gov.outcome, reason_codes: gov.codes },
    rule_trace: gov.rules
  };
}

async function genSessionId(tokenId, delRef) {
  const hash = await sha256Hex(tokenId + delRef);
  return 'GOV-SESS-' + hash.slice(0, 16).toUpperCase();
}

export default async function handler(req, res) {
  try {
    if (req.method !== 'POST') {
      res.status(405).json(UnifiedSerializer.serializeError('METHOD_NOT_ALLOWED', 'Only POST allowed'));
      return;
    }

    const signingSecret = process.env.KERNEL_SIGNING_SECRET;
    const issuerKeyId = process.env.KERNEL_ISSUER_KEY_ID || 'KERNEL_V4_ISSUER_01';
    if (!signingSecret) {
      res.status(500).json(UnifiedSerializer.serializeError('CONFIG_ERROR', 'Missing signing secret'));
      return;
    }

    const { principal, session, intent, policy_context, parent_receipt_hash, original_receipt_hash } = req.body || {};

    if (!principal || !session || !intent || !policy_context) {
       res.status(400).json(UnifiedSerializer.serializeError('BAD_REQUEST', 'Missing required fields'));
       return;
    }

    const intentPayload = { principal, session, intent, policy_context, parent_receipt_hash: parent_receipt_hash || null };
    const recomputedIntentHash = await sha256Hex(canonicalStringify(intentPayload));

    const authPayload = {
      principal: { legal_name: principal.legal_name, organizational_role: principal.organizational_role, authority_scope: principal.authority_scope, delegation_chain_reference: principal.delegation_chain_reference },
      session: { token_id: session.token_id, trust_epoch: session.trust_epoch, signature_hash: session.signature_hash, expiration_epoch: session.expiration_epoch }
    };
    const recomputedAuthorityTokenHash = await sha256Hex(canonicalStringify(authPayload));

    const gov = runRules(principal, session, intent);
    const recomputedBlueprint = buildBlueprint(principal, policy_context, recomputedIntentHash, gov);
    const recomputedBlueprintHash = await sha256Hex(canonicalStringify(recomputedBlueprint));

    const sessionId = session.session_id || await genSessionId(session.token_id, principal.delegation_chain_reference);
    const receiptCore = {
      status: recomputedBlueprint.decision.outcome,
      session_id: sessionId,
      intent_hash: recomputedIntentHash,
      authority_token_hash: recomputedAuthorityTokenHash,
      blueprint_hash: recomputedBlueprintHash,
      parent_receipt_hash: parent_receipt_hash || null,
      risk_tier: recomputedBlueprint.blueprint_meta.risk_tier,
      reason_codes: recomputedBlueprint.decision.reason_codes,
      rule_trace: recomputedBlueprint.rule_trace,
      blueprint: recomputedBlueprint,
      issuer_key_id: issuerKeyId
    };

    const recomputedReceiptHash = await sha256Hex(canonicalStringify(receiptCore));
    const recomputedSignature = await hmacSha256Hex(signingSecret, recomputedReceiptHash);

    const replayMatch = original_receipt_hash ? (original_receipt_hash === recomputedReceiptHash) : null;

    const response = {
      final_decision: recomputedBlueprint.decision.outcome,
      intent_hash: recomputedIntentHash,
      blueprint_hash: recomputedBlueprintHash,
      rule_trace: recomputedBlueprint.rule_trace,
      replay_verification: {
         match: replayMatch,
         recomputed_hash: recomputedReceiptHash,
         original_hash: original_receipt_hash || null
      }
    };

    res.status(200).json(response);
  } catch (err) {
     res.status(500).json(UnifiedSerializer.serializeError('REPLAY_RUNTIME_EXCEPTION', err?.message || 'Unknown error'));
  }
}
