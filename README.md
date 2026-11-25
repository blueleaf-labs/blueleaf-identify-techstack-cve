# Blueleaf Identify Techstack CVE

Blueleaf Identify runs a bounded passive HTTP/HTTPS probe and passes its observations through the
technology, version, intelligence, correlation, assessment, and remediation pipeline. Results
preserve uncertainty and source conflicts. `NO_KNOWN_VULNERABILITY` is scoped to the available
package/version intelligence and does not mean secure.

Phases 11–12 add a usable CLI and local HTTP API over the same application service, bearer
authentication, bounded process-local limits, request cancellation, and structured security events.
The API binds to loopback by default. Application hardening does not make an internet-facing
deployment production ready; follow [deployment guidance](docs/deployment.md). Scan only systems you
own or are authorized to assess.

## Requirements and development

- Node.js 22 or newer
- pnpm 10

```sh
pnpm install
pnpm typecheck
pnpm lint
pnpm test
pnpm format:check
pnpm build
pnpm release:smoke
```

## CLI

```sh
pnpm start -- --help
pnpm start -- --version
pnpm start -- scan https://your-authorized-host.example/
pnpm start -- scan https://your-authorized-host.example/ --json
```

The command syntax, output behavior, and exit codes are described in [CLI usage](docs/cli.md).
The public package entry point is `blueleaf-identify-techstack-cve`; the installed CLI executable
is `blueleaf`.

## HTTP API

```sh
pnpm start:api
```

The server provides `GET /health`, `GET /ready`, and `POST /v1/scans`. Configure an API key through a
protected secret source before starting. See the [API reference](docs/api.md) and
[configuration](docs/configuration.md) for authentication, limits, and deployment requirements.

## Configuration and architecture

The explicit runtime environment boundary and supported settings are listed in
[configuration](docs/configuration.md). The CLI and API both call the shared
`ScanApplicationService`; the adapters do not duplicate pipeline logic. See
[ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and
[PROJECT_CONTEXT.md](PROJECT_CONTEXT.md).

## Versioned contracts

Phase 1–10 schema contracts remain available with their versioned shapes stable. Phase 11 adds:

- [`schemas/scan-request.schema.json`](schemas/scan-request.schema.json)
- [`schemas/scan-result.schema.json`](schemas/scan-result.schema.json)
- [`schemas/api-error.schema.json`](schemas/api-error.schema.json)

The original [`schemas/identification-result.schema.json`](schemas/identification-result.schema.json)
and the evidence, fingerprint, version, intelligence, correlation, assessment, and remediation
schemas remain stable.

## Limits

There is no user management, persistent history, database, queue, distributed quota, or external
monitoring service. Local rate limits reset on restart. No crawling, form submission, JavaScript
execution, fuzzing, brute forcing, port scanning, exploit behavior, remediation execution, or
authoritative origin verification is performed. Unknown or incomplete assessments do not establish
safety.

## v0.1.0 scope

Initial technology definitions cover PHP, nginx, and Apache. Passive evidence includes response
headers and cookies, HTML metadata and generator tags, script/stylesheet/asset URLs, generic content
markers, redirect behavior, and TLS metadata. Indicators are self-reported and can describe a proxy,
CDN, or spoofed value; detections are not proof of origin infrastructure.

Live advisory retrieval supports OSV, NVD, Ubuntu, and Red Hat through normalized provider
contracts. Package identity mappings must be supplied explicitly; no default mapping assumes that a
detected technology name equals an installed package. PHP security bulletins without a stable
machine-readable interface remain unsupported. Intelligence is limited to configured mappings,
providers, their coverage, and freshness. The project does not claim comprehensive CVE coverage,
binary safety, or authoritative origin/version verification.

Version parsing, applicability, and remediation remain conservative when versions, package
identity, vendor revisions, source records, or fixed versions are uncertain. Remediation plans are
informational and never execute package-manager commands or apply changes. See the [known
limitations](docs/security.md), [fingerprinting](docs/fingerprinting.md),
[intelligence](docs/intelligence.md), [versioning](docs/versioning.md), and
[remediation](docs/remediation.md) guides.
