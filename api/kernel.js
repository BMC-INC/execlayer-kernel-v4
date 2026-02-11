import { canonicalStringify } from './_lib/canonical.js';
import { sha256Hex, hmacSha256Hex } from './_lib/crypto.js';
import { JournalAdapter } from './_lib/journal_adapter.js';
import { UnifiedSerializer } from './_lib/serializer.js';

const BASELINE_VERSION = '1.0';
const BASE_EPOCH = 1700000000;
const GEMINI_MODEL = 'gemini-2.5-flash';

// Scope mapping table — maps authority_scope string to structured profile
const SCOPE_PROFILES = {
  Full_Access: {
    allowed_tenants: ['*'],
    allowed_systems: ['*'],
    max_risk: 'HIGH',
    override_eligible: true,
    required_override_tier: 'TIER_3'
  },
  Read_Only: {
    allowed_tenants: ['*'],
    allowed_systems: ['*'],
    max_risk: 'LOW',
    override_eligible: false
  },
  QueueFlow_Ops: {
    allowed_tenants: ['queueflow-prod'],
    allowed_systems: ['QUEUEFLOW'],
    max_risk: 'MODERATE',
    override_eligible: true,
    required_override_tier: 'TIER_3'
  },
  Restricted: {
    allowed_tenants: [],
    allowed_systems: [],
    max_risk: 'LOW',
    override_eligible: false
  }
};

const RISK_LEVELS = { LOW: 1, MEDIUM: 2, MODERATE: 2, HIGH: 3, CRITICAL: 4 };

function resolveScopeProfile(authorityScope) {
  return SCOPE_PROFILES[authorityScope] || null;
}

function evaluateTenantScope(scopeProfile, tenantId, authorityScope) {
  const entry = {
    rule_id: 'RULE_TENANT_SCOPE_ENFORCEMENT',
    result: 'ALLOW',
    reason_code: '',
    facts: { tenant_id: tenantId, allowed_tenants: scopeProfile.allowed_tenants, authority_scope: authorityScope }
  };
  if (scopeProfile.allowed_tenants.includes('*')) return entry;
  if (!scopeProfile.allowed_tenants.includes(tenantId)) {
    entry.result = 'REFUSE';
    entry.reason_code = 'TENANT_MISMATCH';
  }
  return entry;
}

function evaluateSystemScope(scopeProfile, targetSystem, authorityScope) {
  const entry = {
    rule_id: 'RULE_SYSTEM_SCOPE_ENFORCEMENT',
    result: 'ALLOW',
    reason_code: '',
    facts: { target_system: targetSystem, allowed_systems: scopeProfile.allowed_systems, authority_scope: authorityScope }
  };
  if (scopeProfile.allowed_systems.includes('*')) return entry;
  if (!scopeProfile.allowed_systems.includes(targetSystem)) {
    entry.result = 'REFUSE';
    entry.reason_code = 'SYSTEM_SCOPE_MISMATCH';
  }
  return entry;
}

function evaluateRiskCeiling(scopeProfile, declaredRisk, privilegeTier, authorityScope) {
  const maxLevel = RISK_LEVELS[scopeProfile.max_risk] || 1;
  const declaredLevel = RISK_LEVELS[declaredRisk] || 1;
  const privilegeRank = parseInt(privilegeTier.replace('TIER_', ''), 10);

  const entry = {
    rule_id: 'RULE_RISK_CEILING_ENFORCEMENT',
    result: 'ALLOW',
    reason_code: '',
    facts: {
      declared_risk_tier: declaredRisk,
      max_risk: scopeProfile.max_risk,
      authority_scope: authorityScope,
      privilege_tier: privilegeTier,
      privilege_rank: privilegeRank
    }
  };

  if (declaredLevel <= maxLevel) return entry;

  // Risk exceeds ceiling — check for privilege override
  // Tier ordering: TIER_1 = lowest, TIER_4 = highest
  // Override requires privilege_tier >= required_override_tier
  if (scopeProfile.override_eligible) {
    const requiredRank = parseInt((scopeProfile.required_override_tier || 'TIER_1').replace('TIER_', ''), 10);
    if (privilegeRank >= requiredRank) {
      // Privilege override granted — record it explicitly
      return {
        rule_id: 'RULE_RISK_OVERRIDE_BY_PRIVILEGE',
        result: 'ALLOW',
        reason_code: '',
        facts: {
          declared_risk_tier: declaredRisk,
          max_risk: scopeProfile.max_risk,
          privilege_tier: privilegeTier,
          privilege_rank: privilegeRank,
          required_override_tier: scopeProfile.required_override_tier,
          required_rank: requiredRank,
          override_granted: true
        }
      };
    }
    // Privilege insufficient for override
    return {
      rule_id: 'RULE_RISK_CEILING_ENFORCEMENT',
      result: 'REFUSE',
      reason_code: 'PRIVILEGE_INSUFFICIENT_FOR_OVERRIDE',
      facts: {
        declared_risk_tier: declaredRisk,
        max_risk: scopeProfile.max_risk,
        privilege_tier: privilegeTier,
        privilege_rank: privilegeRank,
        required_override_tier: scopeProfile.required_override_tier,
        required_rank: requiredRank,
        override_eligible: true,
        override_granted: false
      }
    };
  }

  // No override possible
  entry.result = 'REFUSE';
  entry.reason_code = 'RISK_TIER_EXCEEDS_SCOPE';
  return entry;
}

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

// Tier ordering: TIER_1 = lowest, TIER_4 = highest
function getPrivilegeTier(ref) {
  if (ref === 'ROOT_EXEC_AUTHORITY_V4') return 'TIER_4';
  if (ref === 'FINANCE_ANALYST_V1') return 'TIER_2';
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

  // Session expiry check
  if (session.expiration_epoch && session.trust_epoch && session.expiration_epoch < session.trust_epoch) {
    rules.push({ rule_id: 'RULE_TOKEN_EXPIRY', result: 'REFUSE', reason_code: 'TOKEN_EXPIRED_EPOCH', facts: { expiration_epoch: session.expiration_epoch, trust_epoch: session.trust_epoch } });
    codes.push('TOKEN_EXPIRED_EPOCH');
    outcome = 'REFUSE';
  } else if (session.expiration_epoch && session.trust_epoch) {
    rules.push({ rule_id: 'RULE_TOKEN_EXPIRY', result: 'ALLOW', reason_code: '', facts: { expiration_epoch: session.expiration_epoch, trust_epoch: session.trust_epoch } });
  }

  // Hostile payload check
  if (isHostile(intent.requested_action)) {
    rules.push({ rule_id: 'RULE_HOSTILE_PAYLOAD', result: 'REFUSE', reason_code: 'HOSTILE_DESTRUCTIVE_PATTERN', facts: { requested_action: intent.requested_action, pattern_match: 'HOSTILE_DESTRUCTIVE' } });
    codes.push('HOSTILE_DESTRUCTIVE_PATTERN');
    tier = 'CRITICAL';
    outcome = 'REFUSE';
  }

  // Write-action scope check
  if (principal.authority_scope === 'Read_Only' && isWriteAction(intent.requested_action)) {
    rules.push({ rule_id: 'RULE_WRITE_SCOPE_CHECK', result: 'REFUSE', reason_code: 'AUTH_SCOPE_MISMATCH_R401', facts: { authority_scope: principal.authority_scope, requested_action: intent.requested_action, is_write_action: true } });
    codes.push('AUTH_SCOPE_MISMATCH_R401');
    outcome = 'REFUSE';
  }

  // Financial transfer controls
  const isFin = intent.intent_type === 'FINANCIAL_TRANSFER' || intent.requested_action.toLowerCase().includes('wire') || intent.requested_action.toLowerCase().includes('transfer');
  if (isFin) {
    const amt = parseAmount(intent.parameters);
    if (amt === null && intent.intent_type === 'FINANCIAL_TRANSFER') {
      rules.push({ rule_id: 'RULE_FINANCIAL_AMOUNT', result: 'REFUSE', reason_code: 'AMOUNT_REQUIRED', facts: { intent_type: intent.intent_type, amount_usd: null } });
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
        rules.push({ rule_id: 'RULE_MULTISIG_CONSENSUS', result: 'REFUSE', reason_code: 'L4_CONSENSUS_PENDING', facts: { amount_usd: amt, signatures_count: sigs.length, roles_present: roles, required_roles: req } });
        codes.push('L4_CONSENSUS_PENDING');
        outcome = 'REFUSE';
      } else {
        rules.push({ rule_id: 'RULE_MULTISIG_CONSENSUS', result: 'ALLOW', reason_code: '', facts: { amount_usd: amt, signatures_count: sigs.length, roles_present: roles } });
      }
      rules.push({ rule_id: 'RULE_HIGH_VALUE_PROTOCOL', result: outcome === 'REFUSE' ? 'REFUSE' : 'ALLOW', reason_code: outcome === 'REFUSE' ? 'HIGH_VALUE_BLOCKED' : '', facts: { amount_usd: amt, threshold: 1000000, effective_risk_tier: tier } });
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
      privilege_tier: getPrivilegeTier(principal.delegation_chain_reference),
      scope_profile: resolveScopeProfile(principal.authority_scope) ? principal.authority_scope : 'UNMAPPED'
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

    // Baseline version enforcement for EXECUTE intents
    if (intent && intent.intent_type === 'EXECUTE') {
      if (!intent.baseline_version) {
        return res.status(400).json({ status: 'REFUSE', reason_codes: ['BASELINE_VERSION_REQUIRED'], rule_trace: [{ rule_id: 'RULE_BASELINE_VERSION_ENFORCEMENT', result: 'REFUSE', reason_code: 'BASELINE_VERSION_REQUIRED', facts: { expected: BASELINE_VERSION, provided: null } }], baseline_version: BASELINE_VERSION });
      }
      if (intent.baseline_version !== BASELINE_VERSION) {
        return res.status(400).json({ status: 'REFUSE', reason_codes: ['BASELINE_VERSION_MISMATCH'], rule_trace: [{ rule_id: 'RULE_BASELINE_VERSION_ENFORCEMENT', result: 'REFUSE', reason_code: 'BASELINE_VERSION_MISMATCH', facts: { expected: BASELINE_VERSION, provided: intent.baseline_version } }], baseline_version: BASELINE_VERSION });
      }
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
        receipt_signature: await hmacSha256Hex(signingSecret, BASELINE_VERSION + rh + errReceipt.parent_receipt_hash + errReceipt.intent_hash),
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

    // === PRE-MODEL ENFORCEMENT GATES ===
    const privilegeTier = getPrivilegeTier(principal.delegation_chain_reference);
    const scopeProfile = resolveScopeProfile(principal.authority_scope);
    const enforcementTrace = [];
    let enforcementRefused = false;
    const enforcementCodes = [];

    // Gate -1: Baseline version enforcement (must be first rule in trace)
    enforcementTrace.push({ rule_id: 'RULE_BASELINE_VERSION_ENFORCEMENT', result: 'ALLOW', reason_code: '', facts: { baseline_version: BASELINE_VERSION, provided: intent.baseline_version || BASELINE_VERSION } });

    // Gate 0: Scope profile must be mapped
    if (!scopeProfile) {
      enforcementTrace.push({ rule_id: 'RULE_SCOPE_RESOLUTION', result: 'REFUSE', reason_code: 'AUTH_SCOPE_UNMAPPED', facts: { authority_scope: principal.authority_scope, known_scopes: Object.keys(SCOPE_PROFILES) } });
      enforcementCodes.push('AUTH_SCOPE_UNMAPPED');
      enforcementRefused = true;
    } else {
      enforcementTrace.push({ rule_id: 'RULE_SCOPE_RESOLUTION', result: 'ALLOW', reason_code: '', facts: { authority_scope: principal.authority_scope, scope_profile: principal.authority_scope } });

      // Gate 1: Tenant scope enforcement (EXECUTE only)
      if (normalizedIntent.intent_type === 'EXECUTE' && tenant_id) {
        const tenantResult = evaluateTenantScope(scopeProfile, tenant_id, principal.authority_scope);
        enforcementTrace.push(tenantResult);
        if (tenantResult.result === 'REFUSE') {
          enforcementCodes.push(tenantResult.reason_code);
          enforcementRefused = true;
        }
      }

      // Gate 2: System scope enforcement
      const systemResult = evaluateSystemScope(scopeProfile, normalizedIntent.target_system, principal.authority_scope);
      enforcementTrace.push(systemResult);
      if (systemResult.result === 'REFUSE') {
        enforcementCodes.push(systemResult.reason_code);
        enforcementRefused = true;
      }

      // Gate 3: Risk ceiling enforcement
      const riskResult = evaluateRiskCeiling(scopeProfile, normalizedIntent.declared_risk_tier, privilegeTier, principal.authority_scope);
      enforcementTrace.push(riskResult);
      if (riskResult.result === 'REFUSE') {
        enforcementCodes.push(riskResult.reason_code);
        enforcementRefused = true;
      }
    }

    // If any enforcement gate refused, return structured REFUSE — do NOT call model
    if (enforcementRefused) {
      const sessionId = session.session_id || await genSessionId(session.token_id, principal.delegation_chain_reference);
      const refusalCore = {
        baseline_version: BASELINE_VERSION,
        status: 'REFUSE',
        execution_result_code: 'EXECUTION_DENIED',
        session_id: sessionId,
        intent_hash: intentHash,
        authority_token_hash: authorityTokenHash,
        blueprint_hash: null,
        parent_receipt_hash: authoritativeParentHash,
        risk_tier: normalizedIntent.declared_risk_tier || 'LOW',
        reason_codes: enforcementCodes,
        rule_trace: enforcementTrace,
        blueprint: null,
        issuer_key_id: issuerKeyId
      };
      const rh = await sha256Hex(canonicalStringify(refusalCore));
      const refusalReceipt = {
        ...refusalCore,
        receipt_hash: rh,
        receipt_signature: await hmacSha256Hex(signingSecret, BASELINE_VERSION + rh + refusalCore.parent_receipt_hash + refusalCore.intent_hash),
        next_parent_receipt_hash: rh
      };
      await JournalAdapter.writeReceipt(refusalReceipt);
      return res.status(403).json(refusalReceipt);
    }

    // === GOVERNANCE RULES (post-enforcement) ===
    const gov = runRules(principal, session, normalizedIntent);
    // Merge enforcement trace into governance rules
    gov.rules = [...enforcementTrace, ...gov.rules];

    // TRACE_MISSING guardrail: if ALLOW and rule_trace empty, hard fail
    if (gov.outcome === 'ALLOW' && gov.rules.length === 0) {
      gov.outcome = 'REFUSE';
      gov.codes.push('TRACE_MISSING');
      gov.rules.push({ rule_id: 'RULE_TRACE_GUARDRAIL', result: 'REFUSE', reason_code: 'TRACE_MISSING', facts: { message: 'ALLOW without rule trace is forbidden' } });
    }

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
          baseline_version: BASELINE_VERSION,
          status: 'REFUSE',
          execution_result_code: 'EXECUTION_DENIED',
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
        const refusalSignature = await hmacSha256Hex(signingSecret, BASELINE_VERSION + refusalHash + refusalCore.parent_receipt_hash + refusalCore.intent_hash);

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

    // Authority envelope — model_result is EXCLUDED from receipt hash
    const receiptCore = {
      baseline_version: BASELINE_VERSION,
      status: blueprint.decision.outcome,
      execution_result_code: blueprint.decision.outcome === 'ALLOW' ? 'EXECUTION_COMMITTED' : 'EXECUTION_DENIED',
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

    const receiptHash = await sha256Hex(canonicalStringify(receiptCore));
    const receiptSignature = await hmacSha256Hex(signingSecret, BASELINE_VERSION + receiptHash + authoritativeParentHash + intentHash);

    const receipt = { ...receiptCore, receipt_hash: receiptHash, receipt_signature: receiptSignature, next_parent_receipt_hash: receiptHash };

    await JournalAdapter.writeReceipt(receipt);

    // Model narrative returned OUTSIDE authority boundary — not part of receipt hash
    const response = { ...receipt };
    if (blueprint.decision.outcome === 'ALLOW' && modelResult && !modelResult.error) {
      response.model_narrative = { assistant_response: modelResult.assistant_response, suggested_next_intents: modelResult.suggested_next_intents };
    }

    res.status(blueprint.decision.outcome === 'ALLOW' ? 200 : 403).json(response);

  } catch (err) {
    const errMsg = err?.message || 'Unknown runtime failure';

    // Normalize DAG_HEAD_MISMATCH to structured refusal
    if (errMsg.includes('DAG_HEAD_MISMATCH')) {
      const match = errMsg.match(/Expected parent ([a-f0-9]+), got ([a-f0-9]+)/);
      const dagRefusal = {
        status: 'REFUSE',
        reason_codes: ['DAG_HEAD_MISMATCH'],
        expected_parent: match ? match[1] : null,
        provided_parent: match ? match[2] : null,
        message: 'Concurrent write detected. Retry with current head.',
        rule_trace: [{ rule_id: 'RULE_DAG_SERIALIZATION', result: 'REFUSE', reason_code: 'DAG_HEAD_MISMATCH', facts: { expected_parent: match ? match[1] : null, provided_parent: match ? match[2] : null } }]
      };
      return res.status(409).json(dagRefusal);
    }

    try {
      const errorReceipt = UnifiedSerializer.serializeError('KERNEL_RUNTIME_EXCEPTION', errMsg);
      res.status(500).json(errorReceipt);
    } catch (_) {
      res.status(500).json(UnifiedSerializer.serializeError('SERIALIZATION_VIOLATION', 'Fatal serialization failure'));
    }
  }
}
