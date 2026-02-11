# MIGRATIONS.md — ExecLayer Kernel V4

## Schema Version

| Attribute            | Value  |
|----------------------|--------|
| Current Baseline     | 1.0    |
| DB Schema Version    | 1.0    |
| Signature Version    | 1.0    |

## Signature Computation

```
HMAC_SHA256(
  baseline_version +
  receipt_hash +
  parent_receipt_hash +
  intent_hash,
  KERNEL_SIGNING_SECRET
)
```

## Backward Compatibility Statement

- Baseline 1.0 receipts are **immutable**.
- No field removal allowed from the authority envelope.
- Additive fields must NOT change the hash input set without a baseline version bump.
- All receipts signed under Baseline 1.0 must remain verifiable indefinitely.

## Receipt Format Change Policy

Any modification to the following requires a baseline version bump:

| Protected Component         | Example Changes                                  |
|-----------------------------|--------------------------------------------------|
| Authority envelope fields   | Adding/removing fields in `receiptCore`           |
| Rule trace schema           | Changing `rule_id`, `result`, `facts` structure   |
| Signature input set         | Changing HMAC concatenation order or fields       |
| `BASELINE_VERSION` constant | Any value change                                  |
| Scope resolution logic      | Changing `SCOPE_PROFILES` semantics               |
| Risk ceiling semantics      | Changing tier ordering or override predicate      |

### Required Artifacts for Any Version Bump

1. Baseline version bump (`BASELINE_VERSION` constant)
2. Updated hash canonicalization (if envelope fields change)
3. Updated signature computation (if input set changes)
4. Migration SQL script (if DB schema changes)
5. Replay determinism comparison document (1.0 vs N.N)
6. Updated integrity verification logic
7. Entry in this document

## Migration Procedure Template

```
1. Bump BASELINE_VERSION in kernel.js and replay.js
2. Update canonicalized authority envelope if fields changed
3. Update HMAC signature computation if input set changed
4. Write migration SQL:
   ALTER TABLE receipts ADD COLUMN IF NOT EXISTS <new_column> ...
5. Produce replay determinism comparison:
   - Replay 3 receipts from Baseline 1.0
   - Replay same intents under Baseline N.N
   - Document hash divergence (expected) or convergence (unexpected)
6. Update verify_integrity.js for new signature scheme
7. Document in MIGRATIONS.md
8. Deploy and verify with regression suite
```

## Migration Log

| Date       | From | To  | Description                                | Author       |
|------------|------|-----|--------------------------------------------|--------------|
| 2026-02-11 | —    | 1.0 | Initial baseline freeze. Immutability guard | Kernel V4    |
