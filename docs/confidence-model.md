# Confidence model (Phase 9)

Phase 9 keeps technology identification, version identification, package identity, advisory-source
quality, intelligence completeness, independent corroboration, and contradictions as separate
dimensions. Scores are deterministic heuristics in `[0,1]`; they are not calibrated probabilities.
The full breakdown and a plain-language rationale are included in every target, technology, and
per-advisory assessment.

## Calculation

The overall assessment confidence is the weighted sum below multiplied by the contradiction
penalty:

```text
(0.20 × technology + 0.20 × version + 0.15 × package + 0.15 × applicability
 + 0.10 × advisory + 0.10 × intelligence completeness + 0.10 × independent corroboration)
 × contradiction penalty
```

- **Technology** uses the Phase 4 detection confidence. Distinct evidence references are counted
  after deduplicating identical source/type/key/value tuples; repeated evidence does not add weight.
- **Version** uses Phase 5 version confidence only if a parsed upstream version is selected and
  reconciliation is `single` or `corroborated`. Otherwise it is zero.
- **Package** is zero without one explicit mapping. Mapping authority scores are fixed at 0.95 for
  operator-verified, 0.90 for vendor documentation, and 0.85 for upstream documentation.
- **Applicability** keeps Phase 8's result as its own dimension: affected 0.95, not affected 0.90,
  vendor patched 0.95, potential 0.65, conflict 0.35, unknown/insufficient 0. A complete empty
  source result contributes 0.80 for the scoped negative assessment only. Applicability evidence is
  zero if the exact package mapping or required parsed version does not support the correlation;
  exact vendor patch evidence uses the verified package-revision path.
- **Advisory** uses the strongest active record authority rather than adding records: vendor 0.95,
  primary 0.90, aggregator 0.40, and unknown 0.50. A complete, explicit no-record response is 0.80
  for confidence in the scoped assessment only; it is not positive vulnerability evidence.
- **Completeness** is 1.0 for fresh complete responses from the supplied providers, 0.5 for partial,
  0.35 for stale, and 0 for unavailable, unsupported, or unknown coverage.
- **Corroboration** counts distinct caller-verified `sourceGroupId` declarations for primary/vendor
  records, not provider count or record count: fewer than two groups is 0, two is 0.65, and three or
  more is 0.90. Provider IDs and authority labels alone do not prove independent lineage; undeclared
  providers contribute zero. Identical substantive normalized advisory payloads are treated as one
  origin even if provider IDs or declarations differ. Duplicate records and aliases cannot inflate it.
- **Contradiction penalty** is 1.0 with no conflict. Distinct contradictory technology observations
  reduce it by 0.10 each to a 0.35 floor; Phase 8 source conflict applies at least a 0.55 penalty,
  with a 0.20 floor.

The formula and input dimensions are stable and versioned in `AssessmentConfidence`. Confirmation
also has explicit gates: detection confidence at least 0.75, version confidence at least 0.75, a
single strategy-parsed version, exactly matching package mapping, active primary/vendor affected
range evidence, complete fresh requested-provider coverage, and overall score at least 0.75.
Passing the numeric threshold alone never creates a vulnerability claim. `LIKELY_VULNERABLE` covers
Phase 8 potential applicability and affected applicability that does not satisfy every confirmation
gate.

Freshness is evaluated only from caller-supplied provider `retrievedAt` values relative to the
required `assessedAt` input. Default maximum age is 30 days and can be configured. A missing,
malformed, future, or over-age retrieval time is stale. Supplying `assessedAt` makes identical inputs
reproducible and avoids hidden wall-clock dependencies.

Coverage is relative to the providers included in the input, not a global guarantee. Phase 9 does
not authenticate provenance, source authority labels, package mappings, or inventory assertions.
Identical-payload matching is a conservative heuristic over normalized fields; it cannot detect a
copied record that was materially rewritten by another provider. Inconsistent provider status and
record lists make coverage `unknown` and cannot support a no-known state.
See [assessment states](assessment-states.md) for precedence and transition behavior.
