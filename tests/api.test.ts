import { afterEach, describe, expect, it, vi } from "vitest";
import type { Server } from "node:http";
import {
  createApiServer,
  listenApiServer,
  shutdownApiServer,
} from "../src/api/server.js";
import { createTestScanService } from "./helpers/scan-fixture.js";
import { runCli } from "../src/cli/main.js";
import { HttpProbeProvider } from "../src/infrastructure/http/http-probe-provider.js";
import { DEFAULT_APPLICATION_CONFIGURATION } from "../src/config/configuration.js";
import { ApplicationError } from "../src/domain/errors.js";
import type { SecurityEvent } from "../src/config/api-security.js";
import { validateApiError, validateScanResult } from "./helpers/schema-validator.js";

const servers: Server[] = [];
const TEST_TOKEN = "blueleaf-test-api-key-0123456789abcdef";
const SECOND_TOKEN = "blueleaf-other-api-key-0123456789abcdef";
const QUIET_LOGGER = {
  write: (event: SecurityEvent): void => {
    void event;
  },
};

async function apiFetch(
  input: string,
  init: RequestInit = {},
  token: string | null = TEST_TOKEN,
): Promise<Response> {
  const headers = new Headers(init.headers);
  if (token !== null) headers.set("authorization", `Bearer ${token}`);
  return fetch(input, { ...init, headers });
}

async function start(
  service: Parameters<typeof createApiServer>[0]["service"],
  overrides: Partial<Parameters<typeof createApiServer>[0]> = {},
): Promise<{ readonly url: string; readonly server: Server }> {
  const server = createApiServer({
    ...overrides,
    service,
    credentials: overrides.credentials ?? [
      { identity: "test-client", token: TEST_TOKEN },
    ],
    logger: overrides.logger ?? QUIET_LOGGER,
  });
  await listenApiServer(server, "127.0.0.1", 0);
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("Expected a TCP listener.");
  servers.push(server);
  return { url: `http://127.0.0.1:${address.port}`, server };
}

afterEach(async () => {
  for (const server of servers.splice(0)) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

describe("Blueleaf HTTP API", () => {
  it("serves authenticated health and readiness without invoking a scan", async () => {
    const service = { scan: vi.fn() };
    const { url } = await start(service);
    const health = await apiFetch(`${url}/health`);
    const readiness = await apiFetch(`${url}/ready`);
    expect(health.status).toBe(200);
    expect(await health.json()).toMatchObject({ schemaVersion: "1.0", status: "ok" });
    expect(await readiness.json()).toMatchObject({
      schemaVersion: "1.0",
      status: "ready",
    });
    expect(service.scan).not.toHaveBeenCalled();
  });

  it("requires bearer authentication and accepts only enabled credentials", async () => {
    const { url } = await start(createTestScanService(), {
      credentials: [
        { identity: "test-client", token: TEST_TOKEN },
        {
          identity: "expired-client",
          token: "expired-api-key-0123456789abcdef",
          expiresAt: "2020-01-01T00:00:00.000Z",
        },
        {
          identity: "disabled-client",
          token: "disabled-api-key-0123456789abcdef",
          disabled: true,
        },
      ],
    });
    const request = {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        schemaVersion: "1.0",
        target: { url: "https://example.test" },
      }),
    };
    const missing = await apiFetch(`${url}/v1/scans`, request, null);
    expect(missing.status).toBe(401);
    expect(missing.headers.get("www-authenticate")).toContain("Bearer");
    const invalid = await apiFetch(
      `${url}/v1/scans`,
      request,
      "invalid-api-key-0123456789abcdef",
    );
    expect(invalid.status).toBe(401);
    const expired = await apiFetch(
      `${url}/v1/scans`,
      request,
      "expired-api-key-0123456789abcdef",
    );
    expect(expired.status).toBe(401);
    const disabled = await apiFetch(
      `${url}/v1/scans`,
      request,
      "disabled-api-key-0123456789abcdef",
    );
    expect(disabled.status).toBe(401);
    let finalUnauthorized: Response | undefined;
    for (let attempt = 0; attempt < 7; attempt += 1)
      finalUnauthorized = await apiFetch(
        `${url}/v1/scans`,
        request,
        "invalid-api-key-0123456789abcdef",
      );
    expect(finalUnauthorized?.status).toBe(429);
    expect(finalUnauthorized?.headers.get("retry-after")).toBeTruthy();
    const valid = await apiFetch(`${url}/v1/scans`, request);
    expect(valid.status).toBe(200);
  });

  it("rate limits authenticated identities and returns Retry-After", async () => {
    const { url } = await start(createTestScanService(), {
      rateLimit: 1,
      rateWindowMs: 60_000,
    });
    const request = {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        schemaVersion: "1.0",
        target: { url: "https://example.test" },
      }),
    };
    expect((await apiFetch(`${url}/v1/scans`, request)).status).toBe(200);
    const limited = await apiFetch(`${url}/v1/scans`, request);
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toBeTruthy();
    expect(await limited.json()).toMatchObject({ error: { code: "RATE_LIMITED" } });
  });

  it("adds request IDs and security headers, enforces exact CORS origins, and redacts audit events", async () => {
    const events: SecurityEvent[] = [];
    const logger = {
      write: (event: SecurityEvent): void => {
        events.push(event);
      },
    };
    const { url } = await start(createTestScanService(), {
      logger,
      allowedOrigins: ["https://ui.example.test"],
    });
    const blocked = await apiFetch(`${url}/health`, {
      headers: { origin: "https://evil.example.test" },
    });
    expect(blocked.status).toBe(403);
    const response = await apiFetch(`${url}/health`, {
      headers: { origin: "https://ui.example.test", "x-request-id": "trace_123" },
    });
    expect(response.headers.get("x-request-id")).toBe("trace_123");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("x-frame-options")).toBe("DENY");
    expect(response.headers.get("access-control-allow-origin")).toBe(
      "https://ui.example.test",
    );
    const preflight = await apiFetch(`${url}/v1/scans`, {
      method: "OPTIONS",
      headers: {
        origin: "https://ui.example.test",
        "access-control-request-method": "POST",
        "access-control-request-headers": "authorization,content-type",
      },
    });
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("access-control-allow-credentials")).toBeNull();
    const authFailure = await apiFetch(
      `${url}/health`,
      { headers: { cookie: "session-secret-never-log" } },
      null,
    );
    expect(authFailure.status).toBe(401);
    expect(JSON.stringify(events)).not.toContain(TEST_TOKEN);
    expect(JSON.stringify(events)).not.toContain("session-secret-never-log");
    expect(JSON.stringify(events)).toContain("origin_rejected");
    expect(JSON.stringify(events)).toContain("authentication_failed");
  });

  it("cancels work when the client disconnects and aborts active work at shutdown", async () => {
    let observedSignal: AbortSignal | undefined;
    const service = {
      scan: (_request: unknown, signal?: AbortSignal): Promise<never> =>
        new Promise((_resolve, reject) => {
          observedSignal = signal;
          signal?.addEventListener("abort", () => reject(new Error("cancelled")), {
            once: true,
          });
        }),
    };
    const { url, server } = await start(service);
    const client = new AbortController();
    const pending = apiFetch(`${url}/v1/scans`, {
      method: "POST",
      signal: client.signal,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        schemaVersion: "1.0",
        target: { url: "https://example.test" },
      }),
    }).catch(() => undefined);
    await vi.waitFor(() => expect(observedSignal).toBeDefined());
    client.abort();
    await vi.waitFor(() => expect(observedSignal?.aborted).toBe(true));
    await pending;
    await shutdownApiServer(server, 1000, { write: () => undefined });
  });

  it("runs a valid scan request and returns the versioned assessment and remediation result", async () => {
    const { url } = await start(createTestScanService());
    const response = await apiFetch(`${url}/v1/scans`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        schemaVersion: "1.0",
        target: { url: "https://example.test/" },
      }),
    });
    const result = (await response.json()) as Record<string, unknown>;
    expect(response.status).toBe(200);
    expect(validateScanResult(result), JSON.stringify(validateScanResult.errors)).toBe(
      true,
    );
    expect(result["schemaVersion"]).toBe("1.0");
    expect(result["assessment"]).toBeDefined();
    expect(result["remediation"]).toBeDefined();
    expect(result["probe"]).toBeDefined();
    expect(Object.keys(result).sort()).toEqual(
      [
        "schemaVersion",
        "target",
        "generatedAt",
        "probe",
        "evidence",
        "fingerprint",
        "versions",
        "intelligence",
        "correlation",
        "assessment",
        "remediation",
      ].sort(),
    );
    for (const key of [
      "evidence",
      "fingerprint",
      "versions",
      "intelligence",
      "correlation",
      "assessment",
      "remediation",
    ]) {
      expect(result[key]).toMatchObject({ schemaVersion: "1.0" });
    }
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("returns structured errors for invalid requests and unsupported content types", async () => {
    const { url } = await start(createTestScanService());
    const wrongType = await apiFetch(`${url}/v1/scans`, {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "{}",
    });
    expect(wrongType.status).toBe(415);
    expect(await wrongType.json()).toMatchObject({
      schemaVersion: "1.0",
      error: { code: "UNSUPPORTED_MEDIA_TYPE" },
    });
    const invalid = await apiFetch(`${url}/v1/scans`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        schemaVersion: "7.0",
        target: { url: "https://example.test" },
      }),
    });
    expect(invalid.status).toBe(400);
    const invalidPayload: unknown = await invalid.json();
    expect(invalidPayload).toMatchObject({ error: { code: "INVALID_REQUEST" } });
    expect(
      validateApiError(invalidPayload),
      JSON.stringify(validateApiError.errors),
    ).toBe(true);
    const extraField = await apiFetch(`${url}/v1/scans`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        schemaVersion: "1.0",
        target: { url: "https://example.test", headers: { authorization: "secret" } },
      }),
    });
    expect(extraField.status).toBe(400);
    const malformed = await apiFetch(`${url}/v1/scans`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{",
    });
    expect(malformed.status).toBe(400);
    expect(await malformed.json()).toMatchObject({ error: { code: "INVALID_JSON" } });

    const wrongMethod = await apiFetch(`${url}/v1/scans`, { method: "GET" });
    expect(wrongMethod.status).toBe(405);
    expect(wrongMethod.headers.get("allow")).toBe("POST, OPTIONS");
    expect(await wrongMethod.json()).toMatchObject({
      error: { code: "METHOD_NOT_ALLOWED" },
    });
  });

  it("bounds request bodies and scan duration", async () => {
    const bodyLimited = await start(createTestScanService(), { maxRequestBytes: 256 });
    const tooLarge = await apiFetch(`${bodyLimited.url}/v1/scans`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        schemaVersion: "1.0",
        target: { url: `https://example.test/${"a".repeat(400)}` },
      }),
    });
    expect(tooLarge.status).toBe(413);
    expect(await tooLarge.json()).toMatchObject({ error: { code: "REQUEST_TOO_LARGE" } });

    let finish!: () => void;
    const slowService = {
      scan: vi.fn(() =>
        new Promise<void>((resolve) => {
          finish = resolve;
        }).then(() => {
          throw new Error("released fixture");
        }),
      ),
    };
    const deadline = await start(slowService, { scanTimeoutMs: 100 });
    const timed = await apiFetch(`${deadline.url}/v1/scans`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        schemaVersion: "1.0",
        target: { url: "https://example.test" },
      }),
    });
    expect(timed.status).toBe(504);
    expect(await timed.json()).toMatchObject({ error: { code: "SCAN_TIMEOUT" } });
    finish();
  });

  it("bounds concurrent scans and returns capacity errors", async () => {
    let complete!: () => void;
    const service = {
      scan: vi.fn(() =>
        new Promise<void>((resolve) => {
          complete = resolve;
        }).then(() => {
          throw new Error("released fixture");
        }),
      ),
    };
    const { url } = await start(service, {
      maxConcurrentScans: 1,
      credentials: [
        { identity: "test-client", token: TEST_TOKEN },
        { identity: "other-client", token: SECOND_TOKEN },
      ],
    });
    const body = JSON.stringify({
      schemaVersion: "1.0",
      target: { url: "https://example.test" },
    });
    const first = apiFetch(`${url}/v1/scans`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    await vi.waitFor(() => expect(service.scan).toHaveBeenCalledTimes(1));
    const second = await apiFetch(
      `${url}/v1/scans`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      },
      SECOND_TOKEN,
    );
    expect(second.status).toBe(503);
    expect(await second.json()).toMatchObject({ error: { code: "CONCURRENCY_LIMIT" } });
    complete();
    expect((await first).status).toBe(500);
  });

  it("enforces a separate concurrency quota for each API identity", async () => {
    let finish!: () => void;
    const service = {
      scan: vi.fn(() =>
        new Promise<void>((resolve) => {
          finish = resolve;
        }).then(() => {
          throw new Error("released fixture");
        }),
      ),
    };
    const { url } = await start(service, {
      maxConcurrentScans: 2,
      maxConcurrentScansPerIdentity: 1,
    });
    const request = {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        schemaVersion: "1.0",
        target: { url: "https://example.test" },
      }),
    };
    const first = apiFetch(`${url}/v1/scans`, request);
    await vi.waitFor(() => expect(service.scan).toHaveBeenCalledTimes(1));
    const second = await apiFetch(`${url}/v1/scans`, request);
    expect(second.status).toBe(429);
    expect(second.headers.get("retry-after")).toBe("1");
    finish();
    expect((await first).status).toBe(500);
  });

  it("does not expose stack traces, request headers, secrets, or internal paths in errors/results", async () => {
    const secretService = {
      scan: async (): Promise<never> => {
        throw new Error("C:\\private\\path Authorization: Bearer secret-value");
      },
    };
    const { url } = await start(secretService);
    const response = await apiFetch(`${url}/v1/scans`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer request-secret",
      },
      body: JSON.stringify({
        schemaVersion: "1.0",
        target: { url: "https://example.test" },
      }),
    });
    const body = await response.text();
    expect(response.status).toBe(500);
    expect(body).toBe(
      JSON.stringify({
        schemaVersion: "1.0",
        error: {
          code: "INTERNAL_ERROR",
          message: "Request failed due to an internal error.",
        },
      }),
    );
    expect(body).not.toContain("private");
    expect(body).not.toContain("request-secret");
  });

  it("preserves SSRF rejection when accessed through the API", async () => {
    const service = createTestScanService({
      http: new HttpProbeProvider(DEFAULT_APPLICATION_CONFIGURATION),
    });
    const { url } = await start(service);
    for (const target of [
      "http://127.0.0.1:9/",
      "http://[::1]:9/",
      "http://localhost:9/",
    ]) {
      const response = await apiFetch(`${url}/v1/scans`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ schemaVersion: "1.0", target: { url: target } }),
      });
      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({ error: { code: "TARGET_REJECTED" } });
    }
  });

  it("uses the same application service as the CLI and returns equivalent assessment/remediation", async () => {
    const service = createTestScanService();
    const stdout: string[] = [];
    const cliCode = await runCli(["scan", "https://example.test/", "--json"], {
      service,
      io: { stdout: (value) => stdout.push(value), stderr: () => undefined },
    });
    const { url } = await start(service);
    const response = await apiFetch(`${url}/v1/scans`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        schemaVersion: "1.0",
        target: { url: "https://example.test/" },
      }),
    });
    const cliResult = JSON.parse(stdout[0]!) as {
      assessment: unknown;
      remediation: unknown;
    };
    const apiResult = (await response.json()) as {
      assessment: unknown;
      remediation: unknown;
    };
    expect(cliCode).toBe(1);
    expect(apiResult.assessment).toEqual(cliResult.assessment);
    expect(apiResult.remediation).toEqual(cliResult.remediation);
  });

  it("requires explicit opt-in for non-loopback binding", () => {
    expect(() =>
      createApiServer({
        service: createTestScanService(),
        credentials: [{ identity: "test-client", token: TEST_TOKEN }],
        host: "0.0.0.0",
      }),
    ).toThrow(ApplicationError);
    expect(() =>
      createApiServer({
        service: createTestScanService(),
        credentials: [{ identity: "test-client", token: TEST_TOKEN }],
        host: "0.0.0.0",
        allowExternal: true,
        tlsTerminated: true,
        trustedProxyAddresses: ["127.0.0.1"],
      }),
    ).not.toThrow();
  });
});
