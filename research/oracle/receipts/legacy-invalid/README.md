# Legacy receipts — schema v1 (invalid)

These receipts were produced by an earlier version of the oracle harness.
They contain known defects:

- `oracle_parity: true` while `oracle_binary` is null
- `corpus_revision` instead of `corpus_digest` (not tied to corpus content)
- No `mode` field
- No `oracle_manifest` field

They are retained only for provenance but should NOT be cited as evidence.
