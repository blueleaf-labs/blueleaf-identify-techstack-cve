import { readFile } from "node:fs/promises";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import https from "node:https";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import type { ApplicationConfiguration } from "../src/config/configuration.js";
import { DEFAULT_APPLICATION_CONFIGURATION } from "../src/config/configuration.js";
import { ApplicationError } from "../src/domain/errors.js";
import type {
  HostResolver,
  ResolvedAddress,
} from "../src/infrastructure/http/target-resolver.js";
import {
  isGloballyRoutableAddress,
  normalizeTarget,
  SecureTargetResolver,
} from "../src/infrastructure/http/target-resolver.js";
import { HttpProbeProvider } from "../src/infrastructure/http/http-probe-provider.js";

type TestServer = http.Server | https.Server | net.Server;
const servers: TestServer[] = [];

function configuration(
  overrides: Partial<ApplicationConfiguration["http"]> = {},
  allowPrivateNetworks = true,
): ApplicationConfiguration {
  return {
    ...DEFAULT_APPLICATION_CONFIGURATION,
    http: { ...DEFAULT_APPLICATION_CONFIGURATION.http, ...overrides },
    network: {
      ...DEFAULT_APPLICATION_CONFIGURATION.network,
      allowedHosts: ["127.0.0.1", "localhost", "probe.test"],
      allowPrivateNetworks,
    },
  };
}

async function startServer(
  handler: (request: IncomingMessage, response: ServerResponse) => void,
  secure = false,
): Promise<string> {
  const server = secure
    ? https.createServer(
        {
          key: await readFile(new URL("./fixtures/probe-leaf-key.pem", import.meta.url)),
          cert: await readFile(
            new URL("./fixtures/probe-leaf-cert.pem", import.meta.url),
          ),
        },
        handler,
      )
    : http.createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address() as AddressInfo;
  return `${secure ? "https" : "http"}://127.0.0.1:${address.port}`;
}

async function closeServers(): Promise<void> {
  for (const server of servers.splice(0)) {
    if (!server.listening) continue;
    if (
      "closeAllConnections" in server &&
      typeof server.closeAllConnections === "function"
    ) {
      server.closeAllConnections();
    }
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

afterEach(async () => closeServers());

describe("target normalization and resolution", () => {
  it("normalizes HTTP(S) targets and removes fragments", () => {
    expect(normalizeTarget("HTTP://Example.COM:80/a#frag").href).toBe(
      "http://example.com/a",
    );
    expect(normalizeTarget("https://[2001:4860:4860::8888]/").hostname).toBe(
      "[2001:4860:4860::8888]",
    );
  });

  it.each([
    "example.com",
    "ftp://example.com",
    "http://user:pass@example.com",
    "http://",
    "http://[not-ipv6]/",
  ])("rejects invalid target %s", (url) => {
    expect(() => normalizeTarget(url)).toThrow(ApplicationError);
  });

  it("classifies IPv4, IPv6, and IPv4-mapped IPv6 addresses", () => {
    expect(isGloballyRoutableAddress("8.8.8.8")).toBe(true);
    expect(isGloballyRoutableAddress("127.0.0.1")).toBe(false);
    expect(isGloballyRoutableAddress("2001:4860:4860::8888")).toBe(true);
    expect(isGloballyRoutableAddress("::1")).toBe(false);
    expect(isGloballyRoutableAddress("::ffff:7f00:1")).toBe(false);
    expect(isGloballyRoutableAddress("2001:2f:ffff::1")).toBe(false);
  });

  it.each([
    "0.1.2.3",
    "10.0.0.1",
    "100.64.0.1",
    "172.31.255.254",
    "169.254.169.254",
    "192.168.1.1",
    "192.0.2.10",
    "198.18.0.1",
    "224.0.0.1",
    "240.0.0.1",
    "fc00::1",
    "fe80::1",
    "ff02::1",
    "2001:db8::1",
    "2002:0808:0808::1",
  ])("blocks non-global address %s", (address) => {
    expect(isGloballyRoutableAddress(address)).toBe(false);
  });

  it("resolves IPv6 literals when private-network access is explicitly enabled", async () => {
    const resolver = new SecureTargetResolver();
    const result = await resolver.resolve("https://[::1]/", {
      ...configuration(),
      network: { allowedHosts: ["::1"], allowPrivateNetworks: true },
    });
    expect(result.hostname).toBe("::1");
    expect(result.addresses).toEqual([{ address: "::1", family: 6 }]);
  });

  it("blocks private literal addresses by default", async () => {
    const resolver = new SecureTargetResolver();
    await expect(
      resolver.resolve("http://127.0.0.1", configuration({}, false)),
    ).rejects.toMatchObject({ code: "TARGET_REJECTED" });
    await expect(
      resolver.resolve("http://[::1]", configuration({}, false)),
    ).rejects.toMatchObject({
      code: "TARGET_REJECTED",
    });
  });

  it("rejects DNS answers containing any private address before connecting", async () => {
    const resolver = new SecureTargetResolver({
      async resolve(): Promise<readonly ResolvedAddress[]> {
        return [
          { address: "93.184.216.34", family: 4 },
          { address: "10.1.2.3", family: 4 },
        ];
      },
    });
    await expect(
      resolver.resolve("https://probe.test", configuration({}, false)),
    ).rejects.toMatchObject({ code: "TARGET_REJECTED" });
  });

  it("reports hostname resolution failures as provider errors", async () => {
    const resolver = new SecureTargetResolver({
      async resolve(): Promise<readonly ResolvedAddress[]> {
        throw new Error("DNS fixture failure");
      },
    });
    await expect(
      resolver.resolve("https://probe.test", configuration()),
    ).rejects.toMatchObject({ code: "PROVIDER_FAILURE" });
  });

  it("re-resolves names at each validation boundary instead of trusting an earlier DNS answer", async () => {
    let resolution = 0;
    const resolver = new SecureTargetResolver({
      async resolve(): Promise<readonly ResolvedAddress[]> {
        resolution += 1;
        return resolution === 1
          ? [{ address: "93.184.216.34", family: 4 }]
          : [{ address: "10.0.0.7", family: 4 }];
      },
    });
    await resolver.resolve("https://rebind.test/", {
      ...configuration(),
      network: { allowedHosts: ["rebind.test"], allowPrivateNetworks: false },
    });
    await expect(
      resolver.resolve("https://rebind.test/", {
        ...configuration(),
        network: { allowedHosts: ["rebind.test"], allowPrivateNetworks: false },
      }),
    ).rejects.toMatchObject({ code: "TARGET_REJECTED" });
  });

  it("supports an explicitly injected resolver and pins the connection to its answer", async () => {
    const base = await startServer((_request, response) => response.end("pinned"));
    const resolver: HostResolver = {
      async resolve(): Promise<readonly ResolvedAddress[]> {
        return [{ address: "127.0.0.1", family: 4 }];
      },
    };
    const url = new URL(base);
    url.hostname = "probe.test";
    const result = await new HttpProbeProvider(
      configuration(),
      new SecureTargetResolver(resolver),
    ).request({
      url: url.href,
      timeoutMs: 1_000,
    });
    expect(Buffer.from(result.body).toString()).toBe("pinned");
    expect(result.remoteAddress).toBe("127.0.0.1");
    expect(result.resolvedAddresses).toEqual(["127.0.0.1"]);
  });
});

describe("HTTP probe provider", () => {
  it("collects normalized headers, cookies, status, content metadata, and timing", async () => {
    const base = await startServer((_request, response) => {
      response.writeHead(201, {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Length": "5",
        "X-Probe-Header": "normalized",
        "Set-Cookie": ["session=a; HttpOnly", "preference=b; SameSite=Lax"],
      });
      response.end("hello");
    });
    const result = await new HttpProbeProvider(configuration()).request({
      url: `${base}/path#ignored`,
      timeoutMs: 1_000,
    });

    expect(result.status).toBe(201);
    expect(result.finalUrl).toBe(`${base}/path`);
    expect(result.headers["content-type"]).toBe("text/plain; charset=utf-8");
    expect(result.headers["x-probe-header"]).toBe("normalized");
    expect(result.cookies).toEqual(["session=a; HttpOnly", "preference=b; SameSite=Lax"]);
    expect(result.contentType).toBe("text/plain; charset=utf-8");
    expect(result.contentLength).toBe(5);
    expect(Buffer.from(result.body).toString()).toBe("hello");
    expect(result.timing?.durationMs).toBeGreaterThanOrEqual(0);
    expect(Number.isNaN(Date.parse(result.timing?.requestStartedAt ?? ""))).toBe(false);
  });

  it("follows redirects, records the chain, and strips credentials across origins", async () => {
    let receivedAuthorization: string | undefined;
    let receivedCookie: string | undefined;
    let receivedCustom: string | undefined;
    const destination = await startServer((request, response) => {
      receivedAuthorization = request.headers.authorization;
      receivedCookie = request.headers.cookie;
      receivedCustom = request.headers["x-request-label"] as string | undefined;
      response.end("destination");
    });
    const source = await startServer((_request, response) => {
      response.writeHead(302, { Location: destination });
      response.end();
    });
    const result = await new HttpProbeProvider(configuration()).request({
      url: source,
      timeoutMs: 1_000,
      headers: {
        Authorization: "Bearer secret",
        Cookie: "session=secret",
        "X-Request-Label": "keep",
      },
    });

    expect(result.status).toBe(200);
    expect(result.finalUrl).toBe(`${destination}/`);
    expect(result.redirectChain).toEqual([
      { from: source + "/", status: 302, to: destination + "/" },
    ]);
    expect(receivedAuthorization).toBeUndefined();
    expect(receivedCookie).toBeUndefined();
    expect(receivedCustom).toBe("keep");
  });

  it("revalidates redirect targets and enforces the redirect limit", async () => {
    const base = await startServer((_request, response) => {
      response.writeHead(302, { Location: "/again" });
      response.end();
    });
    await expect(
      new HttpProbeProvider(configuration({ redirectLimit: 1 })).request({
        url: base,
        timeoutMs: 1_000,
      }),
    ).rejects.toMatchObject({ code: "REDIRECT_LIMIT" });

    const maliciousRedirect = await startServer((_request, response) => {
      response.writeHead(302, { Location: "http://evil.test/admin" });
      response.end();
    });
    await expect(
      new HttpProbeProvider({
        ...configuration(),
        network: { ...configuration().network, allowedHosts: ["127.0.0.1"] },
      }).request({
        url: maliciousRedirect,
        timeoutMs: 1_000,
      }),
    ).rejects.toMatchObject({ code: "TARGET_REJECTED" });
  });

  it("rejects HTTPS downgrade redirects", async () => {
    const destination = await startServer((_request, response) =>
      response.end("downgraded"),
    );
    const secure = await startServer((_request, response) => {
      response.writeHead(302, { Location: destination });
      response.end();
    }, true);
    const cert = await readFile(
      new URL("./fixtures/probe-ca-cert.pem", import.meta.url),
      "utf8",
    );
    const downgradeError = await new HttpProbeProvider(configuration(), undefined, [cert])
      .request({ url: secure, timeoutMs: 1_000 })
      .catch((error: unknown) => error);
    expect(downgradeError).toMatchObject({ code: "TARGET_REJECTED" });
  });

  it("enforces timeout and response byte limits", async () => {
    const slow = await startServer((_request, response) => {
      setTimeout(() => response.end("late"), 150);
    });
    await expect(
      new HttpProbeProvider(configuration({ timeoutMs: 40 })).request({
        url: slow,
        timeoutMs: 1_000,
      }),
    ).rejects.toMatchObject({ code: "TIMEOUT" });

    const stalledResolver = new SecureTargetResolver({
      async resolve(): Promise<readonly ResolvedAddress[]> {
        await new Promise((resolve) => setTimeout(resolve, 150));
        return [{ address: "127.0.0.1", family: 4 }];
      },
    });
    await expect(
      new HttpProbeProvider(configuration({ timeoutMs: 40 }), stalledResolver).request({
        url: "http://probe.test/",
        timeoutMs: 1_000,
      }),
    ).rejects.toMatchObject({ code: "TIMEOUT" });

    const large = await startServer((_request, response) => response.end("123456"));
    await expect(
      new HttpProbeProvider(configuration({ maxResponseBytes: 5 })).request({
        url: large,
        timeoutMs: 1_000,
      }),
    ).rejects.toMatchObject({ code: "RESPONSE_TOO_LARGE" });

    const atLimit = await startServer((_request, response) => response.end("12345"));
    const accepted = await new HttpProbeProvider(
      configuration({ maxResponseBytes: 5 }),
    ).request({ url: atLimit, timeoutMs: 1_000 });
    expect(Buffer.from(accepted.body).toString()).toBe("12345");
    expect(accepted.body.byteLength).toBe(5);

    const oneMiB = Buffer.alloc(1024 * 1024, 0x61);
    const permittedLarge = await startServer((_request, response) =>
      response.end(oneMiB),
    );
    const boundedLarge = await new HttpProbeProvider(
      configuration({ maxResponseBytes: oneMiB.byteLength }),
    ).request({ url: permittedLarge, timeoutMs: 2_000 });
    expect(boundedLarge.body.byteLength).toBe(oneMiB.byteLength);
  });

  it("cancels an active pinned HTTP request when its caller aborts", async () => {
    const slow = await startServer((_request, response) => {
      setTimeout(() => response.end("late"), 1000);
    });
    const controller = new AbortController();
    const pending = new HttpProbeProvider(configuration()).request({
      url: slow,
      timeoutMs: 3000,
      signal: controller.signal,
    });
    setTimeout(() => controller.abort(), 20);
    await expect(pending).rejects.toMatchObject({ code: "CANCELLED" });
  });

  it("reports malformed HTTP and network failures as provider errors", async () => {
    const malformed = net.createServer((socket) => {
      socket.write("not an HTTP response\r\n\r\n");
      socket.destroy();
    });
    servers.push(malformed);
    await new Promise<void>((resolve) => malformed.listen(0, "127.0.0.1", resolve));
    const port = (malformed.address() as AddressInfo).port;
    await expect(
      new HttpProbeProvider(configuration()).request({
        url: `http://127.0.0.1:${port}`,
        timeoutMs: 1_000,
      }),
    ).rejects.toMatchObject({ code: "PROVIDER_FAILURE" });

    const unusedPortServer = net.createServer();
    servers.push(unusedPortServer);
    await new Promise<void>((resolve) =>
      unusedPortServer.listen(0, "127.0.0.1", resolve),
    );
    const unusedPort = (unusedPortServer.address() as AddressInfo).port;
    await new Promise<void>((resolve) => unusedPortServer.close(() => resolve()));
    await expect(
      new HttpProbeProvider(configuration()).request({
        url: `http://127.0.0.1:${unusedPort}/`,
        timeoutMs: 1_000,
      }),
    ).rejects.toMatchObject({ code: "PROVIDER_FAILURE" });
  });

  it("collects TLS certificate metadata and rejects untrusted certificates", async () => {
    const secure = await startServer(
      (_request, response) => response.end("secure"),
      true,
    );
    const tlsError = await new HttpProbeProvider(configuration())
      .request({ url: secure, timeoutMs: 1_000 })
      .catch((error: unknown) => error);
    expect(tlsError).toMatchObject({ code: "TLS_FAILURE" });

    const cert = await readFile(
      new URL("./fixtures/probe-ca-cert.pem", import.meta.url),
      "utf8",
    );
    const result = await new HttpProbeProvider(configuration(), undefined, [
      cert,
    ]).request({
      url: secure,
      timeoutMs: 1_000,
    });
    expect(Buffer.from(result.body).toString()).toBe("secure");
    expect(result.tls?.authorized).toBe(true);
    expect(result.tls?.protocol).toMatch(/^TLS/);
    expect(result.tls?.peerCertificate?.fingerprint256).toBeTruthy();
  });

  it("validates host allowlists before connecting", async () => {
    const base = await startServer((_request, response) => response.end("not reached"));
    await expect(
      new HttpProbeProvider({
        ...configuration(),
        network: { ...configuration().network, allowedHosts: ["example.com"] },
      }).request({ url: base, timeoutMs: 1_000 }),
    ).rejects.toMatchObject({ code: "TARGET_REJECTED" });
  });
});
