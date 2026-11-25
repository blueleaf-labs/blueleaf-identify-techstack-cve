# Configuration

`ApplicationConfiguration` is immutable. `loadRuntimeSettings` is the explicit environment
boundary used by executable composition; application/domain services do not read `process.env`.
Invalid values fail startup without printing secret contents.

## Probe and intelligence settings

| Environment variable                      |    Default | Bound / behavior                                                              |
| ----------------------------------------- | ---------: | ----------------------------------------------------------------------------- |
| `BLUELEAF_SCAN_TIMEOUT_MS`                |     10,000 | 100–60,000 ms target probe timeout                                            |
| `BLUELEAF_MAX_RESPONSE_BYTES`             |  2,097,152 | 1 KiB–2 MiB response body cap                                                 |
| `BLUELEAF_REDIRECT_LIMIT`                 |          5 | 0–20 redirects; each is revalidated                                           |
| `BLUELEAF_ALLOWED_HOSTS`                  |      empty | Comma-separated host allowlist                                                |
| `BLUELEAF_ALLOW_PRIVATE_NETWORKS`         |    `false` | Relaxes private/reserved blocking; in production it requires a host allowlist |
| `BLUELEAF_CACHE_TTL_SECONDS`              |        300 | 0–86,400 seconds                                                              |
| `BLUELEAF_CACHE_MAX_ENTRIES`              |      2,000 | 1–100,000 process-local normalized cache entries                              |
| `BLUELEAF_CACHE_MAX_BYTES`                | 33,554,432 | 1 KiB–512 MiB serialized cache key/value bytes                                |
| `BLUELEAF_INTELLIGENCE_TIMEOUT_MS`        |      5,000 | 100–30,000 ms per provider request                                            |
| `BLUELEAF_INTELLIGENCE_CACHE_TTL_SECONDS` |        300 | 0–86,400 seconds                                                              |
| `BLUELEAF_NVD_API_KEY`                    |      unset | Optional NVD API secret, sent only in its provider HTTPS header               |
| `BLUELEAF_PACKAGE_MAPPINGS_JSON`          |       `[]` | Explicit package mappings matching the package mapping schema                 |
| `BLUELEAF_MAX_ADVISORY_LOOKUPS`           |         20 | 0–100 ID enrichment lookups per scan                                          |

## API security and limits

| Environment variable                             |     Default | Bound / behavior                                                                                |
| ------------------------------------------------ | ----------: | ----------------------------------------------------------------------------------------------- |
| `BLUELEAF_API_KEYS_JSON`                         |       unset | Protected JSON list of API identity/token records; API startup requires at least one active key |
| `BLUELEAF_API_PUBLIC_HEALTH`                     |     `false` | Expose only liveness/readiness without a bearer key                                             |
| `BLUELEAF_API_HOST`                              | `127.0.0.1` | Bind host; non-loopback requires external opt-in, TLS termination, keys, and trusted proxy IPs  |
| `BLUELEAF_API_PORT`                              |        8787 | 1–65,535                                                                                        |
| `BLUELEAF_API_ALLOW_EXTERNAL`                    |     `false` | Explicit non-loopback binding opt-in                                                            |
| `BLUELEAF_API_TLS_TERMINATED`                    |     `false` | Assert TLS terminates at the configured trusted ingress; required for external bind             |
| `BLUELEAF_API_TRUSTED_PROXY_ADDRESSES`           |       empty | Up to 32 exact IP addresses; required externally; only these peers may forward client addresses |
| `BLUELEAF_API_ALLOWED_ORIGINS`                   |       empty | Up to 100 exact HTTP(S) origins; no wildcards or paths                                          |
| `BLUELEAF_API_RATE_LIMIT`                        |          60 | 1–10,000 scan requests per identity per window                                                  |
| `BLUELEAF_API_RATE_WINDOW_MS`                    |      60,000 | 1,000–3,600,000 ms fixed window                                                                 |
| `BLUELEAF_API_MAX_RATE_LIMIT_ENTRIES`            |      10,000 | 100–100,000 in-memory buckets; new buckets fail closed if full                                  |
| `BLUELEAF_API_MAX_CONCURRENT_SCANS`              |           2 | 1–32 global in-flight scans                                                                     |
| `BLUELEAF_API_MAX_CONCURRENT_SCANS_PER_IDENTITY` |           2 | 1–32 and cannot exceed the global cap                                                           |
| `BLUELEAF_API_MAX_REQUEST_BYTES`                 |       8,192 | 256 bytes–1 MiB request body                                                                    |
| `BLUELEAF_API_MAX_RESPONSE_BYTES`                |  12,582,912 | 1 KiB–32 MiB serialized response                                                                |
| `BLUELEAF_API_REQUEST_TIMEOUT_MS`                |      15,000 | 1,000–120,000 ms to receive a request                                                           |
| `BLUELEAF_API_SCAN_TIMEOUT_MS`                   |      30,000 | 100–120,000 ms scan deadline                                                                    |
| `BLUELEAF_API_SHUTDOWN_GRACE_MS`                 |      10,000 | 1,000–60,000 ms graceful shutdown period                                                        |

Rate limits and concurrency are process-local and reset on restart. They are not distributed quotas
and do not replace a reverse proxy or gateway limit. Authentication failures have a separate
bounded fallback limiter. A full rate bucket table rejects new tracked identities/addresses until
expired entries are reclaimed.

## Credential format and secret handling

`BLUELEAF_API_KEYS_JSON` is a secret. It accepts up to 64 records with fields `identity`, `token`,
and optional `expiresAt` and `disabled`. Identity labels use 1–64 ASCII letters, digits, dots,
underscores, or hyphens and must be unique. Tokens use 32–512 URL-safe bearer characters and must be
unique. Expired and disabled keys are rejected. Keep this JSON in a protected secret store or
service-manager secret injection; never commit it, print it, place it in command history, or include
it in diagnostics.

For example, construct the JSON from a token already supplied securely to the current PowerShell
process (do not paste a real token into a script or terminal transcript):

```powershell
$credentialList = @(@{ identity = 'scanner-service'; token = $env:BLUELEAF_API_KEY })
$env:BLUELEAF_API_KEYS_JSON = ConvertTo-Json -Compress -InputObject $credentialList
pnpm start:api
```

Use the same protected mechanism for `BLUELEAF_NVD_API_KEY`. Key rotation can temporarily configure
two distinct identities; mark a revoked identity `disabled: true` or remove it after clients have
rotated.

## External deployment checks

External binding fails closed unless `BLUELEAF_API_ALLOW_EXTERNAL=true`,
`BLUELEAF_API_TLS_TERMINATED=true`, active keys exist, and
`BLUELEAF_API_TRUSTED_PROXY_ADDRESSES` contains exact proxy IPs. The runtime also rejects requests
that do not arrive from those peers. Configure the ingress to restrict direct access, terminate
TLS, and overwrite/append `X-Forwarded-For` correctly. Forwarded IP data from any untrusted peer is
ignored. See [deployment guidance](deployment.md).

Never enable private target networking for an untrusted scanner. In `NODE_ENV=production`, enabling
private network probing also requires a non-empty host allowlist. The Phase 2 resolver still blocks
non-public addresses by default and revalidates every redirect.

## Example commands

```sh
BLUELEAF_API_PORT=8787 pnpm start:api
BLUELEAF_SCAN_TIMEOUT_MS=8000 pnpm start -- scan https://your-authorized-host.example/
```

On Windows PowerShell, set non-secret values with `$env:NAME = 'value'` before running the command.
See [CLI usage](cli.md) and the [API reference](api.md).

## Evidence limits

`EvidenceEngine` defaults to 512 KiB body inspection and 512 output items; constructor options can
raise those only to 2 MiB and 4,096. Evidence snippets are bounded and redacted as documented in
[evidence documentation](evidence.md).
