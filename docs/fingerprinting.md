# Technology fingerprinting

`FingerprintEngine.fingerprint(EvidenceCollection)` maps Phase 3's versioned observations to a
versioned `FingerprintResult`. It is synchronous, network-free, deterministic, and independent of
HTTP transport, CLI output, API controllers, vulnerability intelligence, and remediation.

The result contract is `schemas/fingerprint-result.schema.json`. Each detection includes a stable
technology ID, display name, category, detection confidence, version confidence, matched evidence
references, reasons, and contradictory evidence. A reference contains its input evidence index,
type, source, normalized value, and optional key. The index refers to the exact versioned evidence
array supplied to the engine.

## Initial definitions

The built-in data pack currently includes:

- PHP: `X-Powered-By`, a PHP session cookie name, and generator metadata.
- nginx: `Server`, `Via`, backend/served-by headers, and generator metadata.
- Apache HTTP Server: `Server`, backend/served-by headers, and generator metadata.

These are indicators, not proof of origin infrastructure. Headers can be set or removed by an
application, proxy, or CDN. `Server` and `X-Powered-By` can be spoofed. Generator metadata can be
stale or intentionally misleading. A `Via` or backend header may refer to an intermediary. Reasons
surface these limits; a lone signal is confidence-capped. The engine may report multiple compatible
technologies, and nginx/Apache evidence is treated as contradictory because the same observed server
role cannot be confidently attributed to both from the current rules. Proxies and mixed deployments
can still explain that conflict.

## Confidence and versions

Each signal has a fixed weight in `(0, 1]`. For each technology, the engine counts each rule signal
at most once, so duplicate observations matching one signal do not inflate confidence. Independent
signals combine with noisy-OR:

`support = 1 - product(1 - signalWeight)`

Definitions can cap a lone-signal result. For a declared contradiction, the other technology's
support is combined the same way and reduces the score as `support * (1 - 0.65 * contradiction)`.
Scores are bounded to `[0, 1]` and rounded to three decimal places. They are deterministic heuristics,
not calibrated probabilities or a claim of certainty.

Detection confidence rates technology indicators. Version confidence rates a separate version
candidate, combines its supporting signal weights with noisy-OR, and is capped at 0.65. A candidate
is accepted only from a Phase 3 `versionHint` when the same evidence value
places that version immediately after the matched technology token. This prevents unrelated version
numbers in generic headers or asset names from being assigned to a product. The engine does not
derive hidden versions. It preserves competing candidates, sorts them by confidence then lexical
value, and places the top one in optional `versionCandidate`. A missing version means no candidate
met these conditions; it does not mean the software has no version.

## Extending definitions

Add a versioned definition to `src/fingerprinting/definitions.ts`, then add focused tests for its
positive, weak, duplicate, conflicting, and version-provenance behavior. Definitions are data-only
and use literal `equals`, `contains`, or `prefix` matching, an evidence type, optional source/key
filters, a contribution weight, and a human-readable reason. `validateFingerprintDefinitions` checks
the schema version, unique IDs, supported evidence types/sources, valid weights, and contradiction
references before the engine uses the pack. The Draft 2020-12 shape is documented in
`schemas/fingerprint-definitions.schema.json`.

Do not put regexes, executable code, downloaded rules, AI-generated rules, network calls, or
technology-specific branches in the core engine. Use a new result/definition schema version when a
breaking contract change is needed. The Phase 4 engine does not verify versions or connect detections
to CVEs, vulnerabilities, or remediation.
