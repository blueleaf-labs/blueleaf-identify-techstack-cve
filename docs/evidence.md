# Evidence model

`EvidenceEngine.collect(HttpResponse)` accepts one normalized Phase 2 probe result and returns a
versioned `EvidenceCollection`. It is synchronous and network-free. The JSON contract is
`schemas/evidence-collection.schema.json`; it is separate from the existing identification result
schema.

Each evidence item contains:

- `type` and `source`: stable category and origin enums.
- `normalizedValue`: deterministic observation string.
- `strength`: `direct` for a field reported by the probe, or `derived` for parsed response content.
- `reason`: short explanation of what was observed.
- Optional `key`, bounded/sanitized `rawValue`, and generic `versionHint`.
- Optional `technologyHint`, reserved for a later classifier and absent in Phase 3.

`versionHint` is the first generic version-like token found in the observation. Its reason says it
is unverified; it is not associated with a product or treated as an authoritative version.
`strength` describes source fidelity, not confidence in a technology identification. Conflicting
observations are emitted independently and in deterministic order.

## Sources

| Type                                                         | Source                    | Observation                                                                       |
| ------------------------------------------------------------ | ------------------------- | --------------------------------------------------------------------------------- |
| `http-status`, `final-url`, `content-type`, `content-length` | `probe.*`                 | Probe response status and normalized response metadata.                           |
| `header`                                                     | `response.headers`        | Lexically ordered header names and bounded values; sensitive values are redacted. |
| `cookie`                                                     | `response.cookies`        | Cookie names only; values and attributes are redacted.                            |
| `html-meta`, `html-generator`, `html-title`                  | `html.*`                  | Passive metadata and title text, in document order.                               |
| `script-url`, `stylesheet-url`, `asset-url`                  | `html.*`                  | External references in script/link and common asset attributes.                   |
| `content-marker`                                             | `response.body.signature` | Generic HTML, XML, or JSON-like structural markers.                               |
| `redirect`, `tls`, `network`, `timing`                       | `probe.*`                 | Redirect chain, TLS, resolved/remote addresses, and timing fields.                |

URLs resolve relative references against `finalUrl`; userinfo, query strings, and fragments are
removed. Only HTTP(S) references are retained. Text uses Unicode NFKC normalization, control
character cleanup, whitespace collapse, and fixed length caps. HTML entities are decoded for
metadata and attributes. Header names, meta keys, and cookie names are case-normalized.

## Bounds and behavior

The body inspection cap defaults to 512 KiB and may be raised to 2 MiB. The evidence count defaults
to 512 and may be raised to 4,096. `EvidenceCollection.processing` reports received/examined body
bytes and whether body or evidence output was truncated. Raw observations are optional, bounded to
512 characters, and sanitized. Cookie values, sensitive header values, and URL credentials/query/
fragment data are not preserved. Token-bearing HTML metadata values are redacted by metadata key.

The HTML tokenizer handles malformed input without executing anything. The engine does not load
URLs, execute JavaScript, submit forms, crawl links, probe additional paths, recognize product
fingerprints, assign technologies, or produce vulnerability/remediation results.
