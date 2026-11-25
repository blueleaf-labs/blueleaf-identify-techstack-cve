# Assessment states (Phase 9)

The assessment engine produces a target result, a separate result for every detected technology,
and a result for each Phase 8 advisory correlation. It embeds the original Phase 8 correlation and
its source records so different providers and conflicting ranges remain traceable.

## State transitions and precedence

Per-advisory state uses the first applicable rule:

1. `CONFLICTING_EVIDENCE` when Phase 8 reports source disagreement.
2. `PATCHED_BY_VENDOR` only when Phase 8 has exact authoritative installed-package revision and
   matching official vendor patch evidence.
3. `CONFIRMED_VULNERABLE` only when Phase 8 is `AFFECTED` and every confirmation gate in
   [confidence model](confidence-model.md) is met.
4. `LIKELY_VULNERABLE` for Phase 8 `POTENTIALLY_AFFECTED` when a usable version is established, or
   `AFFECTED` that misses a confirmation gate. Potential CPE configuration matches never become
   confirmed here. Without a usable version, the state remains `VERSION_UNKNOWN`.
5. `PATCHED` only when Phase 8 is `NOT_AFFECTED` and its comparisons show the assessed version at
   or beyond an explicit exclusive fixed boundary.
6. `INSUFFICIENT_EVIDENCE` for unsupported or malformed ranges, ambiguous package identity, or
   other unresolved advisory applicability.
7. `NO_KNOWN_VULNERABILITY` for a scoped complete source set with no matching records, or
   explicit `NOT_AFFECTED` range evidence that does not establish a fixed boundary.
8. `INTELLIGENCE_UNAVAILABLE` when relevant provider coverage is missing, unsupported, partial, or
   stale and no stronger positive applicability state is supported; `VERSION_UNKNOWN` when a
   sufficiently specific version cannot be established and source availability is not the blocking
   condition.

At technology level, weak detection or ambiguous/missing package mapping yields
`INSUFFICIENT_EVIDENCE`; Phase 8 conflict takes precedence over positive and negative conclusions;
then a confirmed or likely advisory finding is retained; then a uniform patched state; then provider
availability, version specificity, and completeness determine whether the result is unknown,
insufficient, unavailable, or scoped `NO_KNOWN_VULNERABILITY`.

At target level the precedence is `CONFIRMED_VULNERABLE`, `LIKELY_VULNERABLE`,
`CONFLICTING_EVIDENCE`, `INTELLIGENCE_UNAVAILABLE`, `INSUFFICIENT_EVIDENCE`, `VERSION_UNKNOWN`, then
uniform patch states, then `NO_KNOWN_VULNERABILITY`. An empty detection set is
`TECHNOLOGY_UNKNOWN`. A vulnerable technology remains visible as the target state even when other
technologies are unknown; the per-technology list and target coverage/limitations expose those
unknowns rather than averaging them away.

`PATCHED` and `PATCHED_BY_VENDOR` apply only to their evaluated advisory/package and never mean the
whole target is secure. `NO_KNOWN_VULNERABILITY` means no applicable vulnerability was identified
for the supplied package/version and requested source set; it never means secure or free from
vulnerabilities. Missing, unavailable, stale, or unsupported intelligence cannot produce that state.
No remediation, exploitability, or whole-system security verdict is generated.
