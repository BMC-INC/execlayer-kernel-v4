import { canonicalStringify } from './_lib/canonical.js';
import { sha256Hex, hmacSha256Hex } from './_lib/crypto.js';
import { JournalAdapter } from './_lib/journal_adapter.js';
import { UnifiedSerializer } from './_lib/serializer.js';

const BASE_EPOCH = 1700000000;
const GEMINI_MODEL = 'gemini-2.5-flash';

function validatePrincipal(p) {
  const e = [];
  if (!p) return ['principal is required'];
  if (!p.legal_name || typeof p.legal_name !== 'string') e.push('principal.legal_name required');
  if (!p.organizational_role || typeof p.organizational_role !== 'string') e.push('principal.organizational_role required');
  if (!p.authority_scope || typeof p.authority_scope !== 'string') e.push('principal.authority_scope required');
  if (!p.delegation_chain_reference || typeof p.delegation_chain_reference !== 'string') e.push('principal.delegation_chain_reference required');
  return e;
}

function validateSession(s) {
  const e = [];
  if (!s) return ['session is required'];
  if (!s.token_id || typeof s.token_id !== 'string') e.push('session.token_id required');
  return e;
}

function validateIntent(i) {
  const e = [];
  if (!i) return ['intent is required'];
  const valid = ['FINANCIAL_TRANSFER', 'GENERAL_REQUEST', 'SYSTEM_COMMAND', 'DATA_QUERY', 'AUDIT_REQUEST', 'EXECUTE'];
  if (!i.intent_type || !valid.includes(i.intent_type)) e.push('intent.intent_type invalid');
  if (!i.target_system || typeof i.target_system !== 'string') e.push('intent.target_system required');
  if (!i.requested_action || typeof i.requested_action !== 'string') e.push('intent.requested_action required');
  if (!i.declared_risk_tier || typeof i.declared_risk_tier !== 'string') e.push('intent.declared_risk_tier required');
  return e;
}

function validatePolicyContext(p) {
  const e = [];
  if (!p) return ['policy_context is required'];
  if (!p.governing_policy_id || typeof p.governing_policy_id !== 'string') e.push('policy_context.governing_policy_id required');
  if (!p.jurisdiction || typeof p.jurisdiction !== 'string') e.push('policy_context.jurisdiction required');
  if (!p.compliance_class || typeof p.compliance_class !== 'string') e.push('policy_context.compliance_class required');
  return e;
}

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

function normalizeTargetSystem(ts) {
  return typeof ts === 'string' ? ts.trim().toUpperCase() : ts;
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

async function callGemini(apiKey, intent, principal) {
  const sys = `You are ExecLayer Kernel V4.0 Assistant. You MUST output ONLY a valid JSON object with no additional text, markdown, or explanation. The JSON object must have exactly this structure:
{
  "assistant_response": string,
  "suggested_next_intents": array
}
Do not include any text before or after the JSON object. Do not use markdown code blocks. Output only the raw JSON.`;
  const user = `Principal: ${principal.legal_name} (${principal.organizational_role})\nIntent: ${intent.requested_action}\nTarget: ${intent.target_system}`;

  const makeRequest = async () => {
    const resp = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents: [{ parts: [{ text: user }] }], systemInstruction: { parts: [{ text: sys }] } })
    });
    return resp;
  };

  let resp = await makeRequest();

  if (resp.status >= 500 && resp.status < 600) {
    resp = await makeRequest();
  }

  if (!resp.ok) {
    const rawText = await resp.text();
    return { error: 'GEMINI_API_ERROR', raw_output_hash: await sha256Hex(rawText) };
  }

  const data = await resp.json();
  const raw = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
  const m = raw.match(/\{[\s\S]*\}/);
  if (!m) {
    return { error: 'MODEL_OUTPUT_INVALID_JSON', raw_output_hash: await sha256Hex(raw) };
  }
  try {
    const p = JSON.parse(m[0]);
    if (typeof p.assistant_response !== 'string' || !Array.isArray(p.suggested_next_intents)) {
      return { error: 'MODEL_OUTPUT_INVALID_JSON', raw_output_hash: await sha256Hex(raw) };
    }
    return { assistant_response: p.assistant_response, suggested_next_intents: p.suggested_next_intents };
  } catch {
    return { error: 'MODEL_OUTPUT_INVALID_JSON', raw_output_hash: await sha256Hex(raw) };
  }
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

    const apiKey = process.env.GEMINI_API_KEY;
    const { principal, session, intent, policy_context, tenant_id } = req.body || {};

    // Mandatory Tenant ID Check for EXECUTE
    if (intent && intent.intent_type === 'EXECUTE' && !tenant_id) {
      res.status(400).json(UnifiedSerializer.serializeError('MISSING_TENANT_ID', 'Tenant ID is mandatory for EXECUTE intents'));
      return;
    }

    // Authoritative parent hash from durable store
    const authoritativeParentHash = await JournalAdapter.getHead();

    const errors = [...validatePrincipal(principal), ...validateSession(session), ...validateIntent(intent), ...validatePolicyContext(policy_context)];
    if (errors.length > 0) {
      const errHash = await sha256Hex(canonicalStringify({ errors }));
      const errReceipt = {
        status: 'REFUSE',
        session_id: 'GOV-SESS-VALIDATION-ERROR',
        intent_hash: errHash,
        authority_token_hash: null,
        blueprint_hash: null,
        parent_receipt_hash: authoritativeParentHash,
        risk_tier: 'CRITICAL',
        reason_codes: ['VALIDATION_FAILED'],
        rule_trace: [{ rule_id: 'INPUT_VALIDATION', type: 'SCHEMA_CHECK', input_facts: { errors }, decision: 'REFUSE' }],
        blueprint: null,
        issuer_key_id: issuerKeyId,
        validation_errors: errors
      };

      const rh = await sha256Hex(canonicalStringify(errReceipt));
      const fullReceipt = {
        ...errReceipt,
        receipt_hash: rh,
        receipt_signature: await hmacSha256Hex(signingSecret, rh),
        next_parent_receipt_hash: rh
      };

      await JournalAdapter.writeReceipt(fullReceipt);
      res.status(400).json(fullReceipt);
      return;
    }

    // Normalize target_system before canonicalization
    const normalizedIntent = { ...intent, target_system: normalizeTargetSystem(intent.target_system) };

    // Include tenant_id in canonicalized intent payload
    const intentPayload = { principal, session, intent: normalizedIntent, policy_context, parent_receipt_hash: authoritativeParentHash, tenant_id: tenant_id || null };
    const intentHash = await sha256Hex(canonicalStringify(intentPayload));

    const authPayload = {
      principal: { legal_name: principal.legal_name, organizational_role: principal.organizational_role, authority_scope: principal.authority_scope, delegation_chain_reference: principal.delegation_chain_reference },
      session: { token_id: session.token_id, trust_epoch: session.trust_epoch, signature_hash: session.signature_hash, expiration_epoch: session.expiration_epoch }
    };
    const authorityTokenHash = await sha256Hex(canonicalStringify(authPayload));

    const gov = runRules(principal, session, normalizedIntent);
    const blueprint = buildBlueprint(principal, policy_context, intentHash, gov);
    const blueprintHash = await sha256Hex(canonicalStringify(blueprint));

    let modelResult = null;

    if (blueprint.decision.outcome === 'ALLOW' && apiKey) {
      modelResult = await callGemini(apiKey, normalizedIntent, principal);

      if (modelResult?.error) {
        gov.outcome = 'REFUSE';
        gov.codes.push('MODEL_OUTPUT_INVALID_JSON');
        gov.rules.push({
          rule_id: 'MODEL_OUTPUT_VALIDATION',
          type: 'MODEL_OUTPUT_CHECK',
          input_facts: { error: modelResult.error },
          decision: 'REFUSE'
        });

        const updatedBlueprint = buildBlueprint(principal, policy_context, intentHash, gov);
        const updatedBlueprintHash = await sha256Hex(canonicalStringify(updatedBlueprint));

        const refusalCore = {
          status: 'REFUSE',
          session_id: session.session_id || await genSessionId(session.token_id, principal.delegation_chain_reference),
          intent_hash: intentHash,
          authority_token_hash: authorityTokenHash,
          blueprint_hash: updatedBlueprintHash,
          parent_receipt_hash: authoritativeParentHash,
          risk_tier: updatedBlueprint.blueprint_meta.risk_tier,
          reason_codes: updatedBlueprint.decision.reason_codes,
          rule_trace: updatedBlueprint.rule_trace,
          blueprint: updatedBlueprint,
          issuer_key_id: issuerKeyId
        };

        const refusalHash = await sha256Hex(canonicalStringify(refusalCore));
        const refusalSignature = await hmacSha256Hex(signingSecret, refusalHash);

        const refusalReceipt = {
          ...refusalCore,
          receipt_hash: refusalHash,
          receipt_signature: refusalSignature,
          next_parent_receipt_hash: refusalHash
        };

        await JournalAdapter.writeReceipt(refusalReceipt);
        return res.status(403).json(refusalReceipt);
      }
    }

    const sessionId = session.session_id || await genSessionId(session.token_id, principal.delegation_chain_reference);
    const receiptCore = {
      status: blueprint.decision.outcome,
      session_id: sessionId,
      intent_hash: intentHash,
      authority_token_hash: authorityTokenHash,
      blueprint_hash: blueprintHash,
      parent_receipt_hash: authoritativeParentHash,
      risk_tier: blueprint.blueprint_meta.risk_tier,
      reason_codes: blueprint.decision.reason_codes,
      rule_trace: blueprint.rule_trace,
      blueprint,
      issuer_key_id: issuerKeyId
    };

    if (blueprint.decision.outcome === 'ALLOW' && modelResult && !modelResult.error) {
      receiptCore.model_result = { assistant_response: modelResult.assistant_response, suggested_next_intents: modelResult.suggested_next_intents };
    }

    const receiptHash = await sha256Hex(canonicalStringify(receiptCore));
    const receiptSignature = await hmacSha256Hex(signingSecret, receiptHash);

    const receipt = { ...receiptCore, receipt_hash: receiptHash, receipt_signature: receiptSignature, next_parent_receipt_hash: receiptHash };

    await JournalAdapter.writeReceipt(receipt);
    res.status(blueprint.decision.outcome === 'ALLOW' ? 200 : 403).json(receipt);

  } catch (err) {
    try {
      const errorReceipt = UnifiedSerializer.serializeError('KERNEL_RUNTIME_EXCEPTION', err?.message || 'Unknown runtime failure');
      res.status(500).json(errorReceipt);
    } catch (_) {
      res.status(500).json(UnifiedSerializer.serializeError('SERIALIZATION_VIOLATION', 'Fatal serialization failure'));
    }
  }
}
