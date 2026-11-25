import { describe, expect, it } from "vitest";
import {
  EvidenceEngine,
  extractVersionHint,
  normalizeEvidenceText,
  normalizeEvidenceUrl,
} from "../src/application/evidence/evidence-engine.js";
import type { Evidence } from "../src/domain/evidence.js";
import { createProbeResult, loadEvidenceHtmlFixture } from "./helpers/probe-fixture.js";

function evidenceByType(
  evidence: readonly Evidence[],
  type: Evidence["type"],
): readonly Evidence[] {
  return evidence.filter((item) => item.type === type);
}

describe("EvidenceEngine", () => {
  it("normalizes direct headers, retains duplicate values, and redacts sensitive headers", () => {
    const result = new EvidenceEngine().collect(
      createProbeResult({
        headers: {
          "X-Zed": " last ",
          "X-Duplicate": "first,  second",
          "X-Powered-By": "Example/2.4.58",
          Authorization: "Bearer do-not-expose",
        },
      }),
    );
    const headers = evidenceByType(result.evidence, "header");

    expect(headers.map((item) => item.key)).toEqual([
      "authorization",
      "x-duplicate",
      "x-powered-by",
      "x-zed",
    ]);
    expect(headers.find((item) => item.key === "x-duplicate")?.normalizedValue).toBe(
      "first, second",
    );
    expect(headers.find((item) => item.key === "x-duplicate")?.rawValue).toBe(
      "first,  second",
    );
    expect(headers.find((item) => item.key === "x-powered-by")?.versionHint).toBe(
      "2.4.58",
    );
    const authorization = headers.find((item) => item.key === "authorization");
    expect(authorization?.normalizedValue).toBe("<redacted>");
    expect(authorization?.rawValue).toBeUndefined();
    expect(JSON.stringify(result)).not.toContain("do-not-expose");
    expect(result.evidence.every((item) => item.technologyHint === undefined)).toBe(true);
  });

  it("redacts cookie values and sensitive cookie names", () => {
    const result = new EvidenceEngine().collect(
      createProbeResult({
        cookies: [
          "session_id=private-session; HttpOnly; Path=/",
          "theme=dark; SameSite=Lax",
          "Bearer private-token-without-name",
        ],
      }),
    );
    const cookies = evidenceByType(result.evidence, "cookie");

    expect(cookies.map((item) => item.normalizedValue)).toEqual([
      "<redacted-name>=<redacted>",
      "theme=<redacted>",
      "<redacted-name>=<redacted>",
    ]);
    expect(JSON.stringify(result)).not.toContain("private-session");
    expect(JSON.stringify(result)).not.toContain("private-token-without-name");
    expect(cookies[1]?.rawValue).toBe("theme=<redacted>");
  });

  it("redacts token-bearing HTML metadata", () => {
    const result = new EvidenceEngine().collect(
      createProbeResult({
        contentType: "text/html",
        body: Buffer.from(
          '<html><head><meta name="csrf-token" content="must-not-appear"></head></html>',
        ),
      }),
    );
    const csrf = evidenceByType(result.evidence, "html-meta")[0];
    expect(csrf?.normalizedValue).toBe("<redacted>");
    expect(csrf?.rawValue).toBeUndefined();
    expect(JSON.stringify(result)).not.toContain("must-not-appear");
  });

  it("normalizes URL headers and handles legacy Set-Cookie headers safely", () => {
    const result = new EvidenceEngine().collect(
      createProbeResult({
        headers: {
          Location: "https://example.test/next?token=do-not-expose#fragment",
          "Set-Cookie": "session_id=private-value; HttpOnly",
          "Content-Type": "text/html; charset=utf-8",
        },
        body: Buffer.from('<meta name="generator" content="Generic Publisher 1.2.3">'),
      }),
    );

    expect(evidenceByType(result.evidence, "header")).toContainEqual(
      expect.objectContaining({
        key: "location",
        normalizedValue: "https://example.test/next",
        rawValue: "https://example.test/next",
      }),
    );
    expect(evidenceByType(result.evidence, "cookie")[0]?.normalizedValue).toBe(
      "<redacted-name>=<redacted>",
    );
    expect(evidenceByType(result.evidence, "html-generator")[0]?.normalizedValue).toBe(
      "Generic Publisher 1.2.3",
    );
    expect(JSON.stringify(result)).not.toContain("do-not-expose");
    expect(JSON.stringify(result)).not.toContain("private-value");
  });

  it("collects HTML metadata, generator values, title text, and entity normalization", async () => {
    const body = await loadEvidenceHtmlFixture();
    const result = new EvidenceEngine().collect(
      createProbeResult({
        headers: { "content-type": "text/html; charset=utf-8" },
        contentType: "text/html; charset=utf-8",
        body,
      }),
    );

    expect(evidenceByType(result.evidence, "content-marker")[0]?.normalizedValue).toBe(
      "html-doctype",
    );
    const description = evidenceByType(result.evidence, "html-meta").find(
      (item) => item.key === "description",
    );
    expect(description?.normalizedValue).toBe("A & B release 3.4");
    expect(description?.rawValue).toBe("  A &amp; B   release 3.4 ");
    const generator = evidenceByType(result.evidence, "html-generator")[0];
    expect(generator).toMatchObject({
      key: "generator",
      normalizedValue: "Example Publisher 5.6.7",
      versionHint: "5.6.7",
      strength: "derived",
    });
    expect(generator?.reason).toContain("unverified as a technology version");
    expect(evidenceByType(result.evidence, "html-title")[0]?.normalizedValue).toBe(
      "Demo & Sample",
    );
  });

  it("collects script, stylesheet, and asset URLs after safe URL normalization", async () => {
    const result = new EvidenceEngine().collect(
      createProbeResult({ body: await loadEvidenceHtmlFixture() }),
    );
    const scripts = evidenceByType(result.evidence, "script-url");
    const stylesheets = evidenceByType(result.evidence, "stylesheet-url");
    const assets = evidenceByType(result.evidence, "asset-url");

    expect(scripts).toContainEqual(
      expect.objectContaining({
        normalizedValue: "https://example.test/assets/app.v1.2.3.js",
        versionHint: "1.2.3",
      }),
    );
    expect(stylesheets).toContainEqual(
      expect.objectContaining({
        normalizedValue: "https://cdn.example.test/css/site.2.0.css",
        versionHint: "2.0",
      }),
    );
    expect(assets.map((item) => item.normalizedValue)).toEqual(
      expect.arrayContaining([
        "https://example.test/favicon.ico",
        "https://example.test/images/logo.svg",
        "https://example.test/images/a.jpg",
        "https://example.test/images/b.jpg",
      ]),
    );
    expect(JSON.stringify(result)).not.toContain("private");
    expect(JSON.stringify(result)).not.toContain("hidden");
    expect(JSON.stringify(result)).not.toContain("must-not-be-read.js");
  });

  it("preserves conflicting observations without merging them into a verdict", () => {
    const html = Buffer.from(
      '<html><head><meta name="generator" content="Publisher A 1.0"><meta name="generator" content="Publisher B 2.0"></head></html>',
    );
    const result = new EvidenceEngine().collect(
      createProbeResult({
        headers: { server: "Unrelated Service/9.1" },
        contentType: "text/html",
        body: html,
      }),
    );

    expect(
      evidenceByType(result.evidence, "html-generator").map(
        (item) => item.normalizedValue,
      ),
    ).toEqual(["Publisher A 1.0", "Publisher B 2.0"]);
    expect(
      result.evidence.some((item) => item.type === "header" && item.key === "server"),
    ).toBe(true);
    expect(result.evidence.every((item) => item.technologyHint === undefined)).toBe(true);
  });

  it("handles missing optional fields and empty responses", () => {
    const result = new EvidenceEngine().collect(createProbeResult());
    expect(result.schemaVersion).toBe("1.0");
    expect(result.evidence.map((item) => item.type)).toEqual([
      "http-status",
      "final-url",
    ]);
    expect(result.processing).toEqual({
      bodyBytesReceived: 0,
      bodyBytesExamined: 0,
      bodyTruncated: false,
      evidenceTruncated: false,
    });
  });

  it("handles malformed HTML without throwing and retains parseable observations", () => {
    const body = Buffer.from(
      '<html><head><meta name="generator" content="Loose Publisher 1.2.3"><title>Unclosed title',
    );
    const result = new EvidenceEngine().collect(
      createProbeResult({ contentType: "text/html", body }),
    );

    expect(evidenceByType(result.evidence, "html-generator")[0]?.normalizedValue).toBe(
      "Loose Publisher 1.2.3",
    );
    expect(evidenceByType(result.evidence, "html-title")[0]?.normalizedValue).toBe(
      "Unclosed title",
    );

    const unquoted = new EvidenceEngine().collect(
      createProbeResult({
        contentType: "text/html",
        body: Buffer.from(
          "<html><meta name=generator content=Publisher/2.3.4><script src=/assets/entry.js></script>",
        ),
      }),
    );
    expect(evidenceByType(unquoted.evidence, "html-generator")[0]?.normalizedValue).toBe(
      "Publisher/2.3.4",
    );
    expect(evidenceByType(unquoted.evidence, "script-url")[0]?.normalizedValue).toBe(
      "https://example.test/assets/entry.js",
    );
  });

  it("enforces the body inspection byte limit and reports truncation", () => {
    const body = Buffer.from(
      "<!doctype html><title>This content is beyond the cap</title>",
    );
    const result = new EvidenceEngine({ maxBodyBytes: 15 }).collect(
      createProbeResult({ contentType: "text/html", body }),
    );

    expect(result.processing).toMatchObject({
      bodyBytesReceived: body.byteLength,
      bodyBytesExamined: 15,
      bodyTruncated: true,
    });
    expect(evidenceByType(result.evidence, "content-marker")[0]?.normalizedValue).toBe(
      "html-doctype",
    );
    expect(evidenceByType(result.evidence, "html-title")).toHaveLength(0);
  });

  it("bounds the number of evidence items and reports omitted items", () => {
    const result = new EvidenceEngine({ maxEvidenceItems: 2 }).collect(
      createProbeResult({
        headers: { server: "service" },
        body: Buffer.from("<!doctype html>"),
      }),
    );
    expect(result.evidence).toHaveLength(2);
    expect(result.processing.evidenceTruncated).toBe(true);
  });

  it("normalizes text, URLs, and generic version-like strings deterministically", () => {
    expect(normalizeEvidenceText("  A\t B\nＣ  ")).toBe("A B C");
    expect(
      normalizeEvidenceUrl(
        "//CDN.Example.test/a.js?token=secret#section",
        "https://Example.test/base/",
      ),
    ).toBe("https://cdn.example.test/a.js");
    expect(
      normalizeEvidenceUrl("https://CDN.Example.test./a.js", "https://example.test/"),
    ).toBe("https://cdn.example.test/a.js");
    expect(
      normalizeEvidenceUrl("javascript:alert(1)", "https://example.test/"),
    ).toBeUndefined();
    expect(extractVersionHint("release v2.4.1-RC.1+Build.3")).toBe("2.4.1-rc.1+build.3");
    expect(extractVersionHint("127.0.0.1")).toBeUndefined();
  });

  it("returns the same evidence order regardless of header object insertion order", () => {
    const engine = new EvidenceEngine();
    const first = engine.collect(
      createProbeResult({
        headers: {
          "x-zebra": "z",
          "x-alpha": "a",
          server: "Service/1.2",
          "X-Case": "uppercase key",
          "x-case": "lowercase key",
        },
      }),
    );
    const second = engine.collect(
      createProbeResult({
        headers: {
          "x-case": "lowercase key",
          server: "Service/1.2",
          "x-zebra": "z",
          "X-Case": "uppercase key",
          "x-alpha": "a",
        },
      }),
    );
    expect(first).toEqual(second);
  });

  it("emits passive redirect, TLS, network, timing, and content-type observations", () => {
    const result = new EvidenceEngine().collect(
      createProbeResult({
        contentType: "Text/Html; Charset=UTF-8",
        redirectChain: [
          {
            from: "http://example.test/?token=hidden",
            status: 301,
            to: "https://example.test/final#part",
          },
        ],
        tls: {
          authorized: true,
          protocol: "TLSv1.3",
          cipher: "TLS_AES_128_GCM_SHA256",
          peerCertificate: { fingerprint256: "AB:CD" },
        },
        resolvedAddresses: ["2001:4860:4860::8888", "8.8.8.8", "8.8.8.8"],
        remoteAddress: "8.8.8.8",
        timing: {
          requestStartedAt: "2026-01-01T00:00:00.000Z",
          responseReceivedAt: "2026-01-01T00:00:00.100Z",
          completedAt: "2026-01-01T00:00:00.120Z",
          durationMs: 120.1234,
        },
      }),
    );

    expect(evidenceByType(result.evidence, "content-type")[0]?.normalizedValue).toBe(
      "text/html; charset=utf-8",
    );
    expect(evidenceByType(result.evidence, "redirect")[0]?.normalizedValue).toContain(
      "301 http://example.test/ -> https://example.test/final",
    );
    expect(evidenceByType(result.evidence, "tls").map((item) => item.key)).toEqual([
      "authorized",
      "protocol",
      "cipher",
      "fingerprint256",
    ]);
    expect(
      evidenceByType(result.evidence, "network").map((item) => item.normalizedValue),
    ).toEqual(["2001:4860:4860::8888", "8.8.8.8", "8.8.8.8"]);
    expect(evidenceByType(result.evidence, "timing")[0]?.normalizedValue).toBe(
      "duration-ms=120.123",
    );
  });

  it("does not infer evidence from unknown non-HTML body text", () => {
    const result = new EvidenceEngine().collect(
      createProbeResult({
        body: Buffer.from("an unknown response with no known structural marker"),
      }),
    );
    expect(evidenceByType(result.evidence, "content-marker")).toHaveLength(0);
    expect(evidenceByType(result.evidence, "html-meta")).toHaveLength(0);
  });
});
