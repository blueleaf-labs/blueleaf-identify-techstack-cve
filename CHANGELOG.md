# Changelog

All notable changes are recorded here. The repository has not been published as v0.1.0; this
section describes the intended initial package contents and does not claim a production deployment
or real-world target scan.

## Unreleased

- No changes recorded.

## 0.1.0

### Initial release

- **Phase 1 — Foundation:** established the strict TypeScript ESM project, domain and application
  contracts, provider boundaries, configuration boundary, typed errors, JSON result contract, and
  development tooling.
- **Phases 2–5 — Identification pipeline:** added bounded HTTP/HTTPS probing with DNS/IP
  validation, checked-IP connection pinning, redirect revalidation, TLS checks, time and response
  limits; deterministic passive evidence collection; extensible PHP, nginx, and Apache fingerprint
  definitions; and conservative version parsing, comparison, and range evaluation.
- **Phases 6–7 — Vulnerability intelligence:** added normalized OSV, NVD, Canonical Ubuntu, and
  Red Hat advisory providers with bounded requests, validation, caching, source provenance, and
  multi-source result preservation. Package and ecosystem mappings remain explicit. PHP bulletins
  without a stable documented machine-readable interface remain unsupported/manual.
- **Phase 8 — Correlation:** added package-identity and version-strategy-backed advisory
  applicability results, preserving aliases, source conflicts, and vendor patch evidence.
- **Phase 9 — Assessment:** added explainable per-target, per-technology, and per-advisory
  assessment states, confidence dimensions, and explicit intelligence coverage. Unknown,
  incomplete, or unavailable data is not evidence of safety.
- **Phase 10 — Remediation planning:** added deterministic evidence-backed upgrade and vendor
  update plans that preserve uncertainty and never execute package-manager commands or alter
  assessment verdicts.
- **Phase 11 — CLI and API:** added `blueleaf` help, version, and scan commands, JSON output, and a
  versioned HTTP API. Both use the same application scan service.
- **Phase 12 — Runtime security hardening:** added bearer authentication, protected health and
  readiness routes by default, bounded process-local request and concurrency limits, cancellation,
  trusted-proxy and exact-origin controls, redacted structured security events, and graceful
  shutdown.
- **Phase 13 — Release validation:** added schema and response validation, an ESM package entry
  point, executable wrapper, package file allowlist, bounded cache limits, and built-artifact smoke
  checks.

### Limitations

- Validation uses tests, mocked providers, and local HTTP/TLS fixtures. No real-world target scan,
  production deployment, or infrastructure security review is claimed.
- The project does not provide comprehensive vulnerability coverage, origin verification, a binary
  secure/insecure verdict, remediation execution, crawling, exploitation, fuzzing, brute forcing, or
  port scanning.
- API rate limits and cache are process-local. Internet exposure requires separately reviewed
  ingress, TLS, network, monitoring, quota, and operational controls.
- Assessment and remediation depend on explicit package mappings, supported version semantics,
  configured intelligence sources, and source freshness. Missing information never means safe.
