import { describe, expect, it } from "vitest";
import type { ConfigurationSource } from "../src/config/configuration.js";
import { loadRuntimeSettings } from "../src/config/environment.js";
import { mapping } from "./helpers/scan-fixture.js";

function source(values: Record<string, string>): ConfigurationSource {
  return { get: (name: string): string | undefined => values[name] };
}

describe("runtime environment boundary", () => {
  it("uses safe loopback and private-network defaults", () => {
    const settings = loadRuntimeSettings(source({}));
    expect(settings.api).toMatchObject({
      host: "127.0.0.1",
      port: 8787,
      allowExternal: false,
    });
    expect(settings.configuration.network.allowPrivateNetworks).toBe(false);
    expect(settings.configuration.cache).toMatchObject({
      maxEntries: 2_000,
      maxBytes: 32 * 1024 * 1024,
    });
    expect(settings.packageMappings).toEqual([]);
  });

  it("requires explicit opt-in for non-loopback API binding", () => {
    expect(() => loadRuntimeSettings(source({ BLUELEAF_API_HOST: "0.0.0.0" }))).toThrow(
      "Non-loopback API binding requires BLUELEAF_API_ALLOW_EXTERNAL=true.",
    );
    expect(
      loadRuntimeSettings(
        source({
          BLUELEAF_API_HOST: "0.0.0.0",
          BLUELEAF_API_ALLOW_EXTERNAL: "true",
          BLUELEAF_API_TLS_TERMINATED: "true",
          BLUELEAF_API_TRUSTED_PROXY_ADDRESSES: "10.0.0.2",
          BLUELEAF_API_KEYS_JSON: JSON.stringify([
            { identity: "external-client", token: "A".repeat(40) },
          ]),
        }),
      ).api.host,
    ).toBe("0.0.0.0");
  });

  it("validates bounded values, package mappings, and secret configuration", () => {
    expect(() => loadRuntimeSettings(source({ BLUELEAF_SCAN_TIMEOUT_MS: "0" }))).toThrow(
      "BLUELEAF_SCAN_TIMEOUT_MS must be an integer between 100 and 60000.",
    );
    expect(() =>
      loadRuntimeSettings(source({ BLUELEAF_PACKAGE_MAPPINGS_JSON: "{}" })),
    ).toThrow("BLUELEAF_PACKAGE_MAPPINGS_JSON must contain a JSON array.");
    expect(() =>
      loadRuntimeSettings(
        source({
          BLUELEAF_PACKAGE_MAPPINGS_JSON: JSON.stringify([
            { ...mapping, cpe: { vendor: "", product: "p", rangeType: "SEMVER" } },
          ]),
        }),
      ),
    ).toThrow("BLUELEAF_PACKAGE_MAPPINGS_JSON contains an invalid package mapping.");
    const settings = loadRuntimeSettings(
      source({
        BLUELEAF_NVD_API_KEY: "test-secret",
        BLUELEAF_PACKAGE_MAPPINGS_JSON: JSON.stringify([mapping]),
      }),
    );
    expect(settings.configuration.intelligence?.nvdApiKey).toBe("test-secret");
    expect(settings.packageMappings).toEqual([mapping]);
    expect(() =>
      loadRuntimeSettings(source({ BLUELEAF_CACHE_MAX_ENTRIES: "0" })),
    ).toThrow("BLUELEAF_CACHE_MAX_ENTRIES must be an integer between 1 and 100000.");
  });

  it("validates authentication credentials, exact CORS origins, and trusted proxy IPs", () => {
    expect(() =>
      loadRuntimeSettings(
        source({
          BLUELEAF_API_KEYS_JSON: JSON.stringify([
            { identity: "client", token: "short" },
          ]),
        }),
      ),
    ).toThrow("BLUELEAF_API_KEYS_JSON credentials are invalid or inactive.");
    expect(() =>
      loadRuntimeSettings(source({ BLUELEAF_API_ALLOWED_ORIGINS: "*" })),
    ).toThrow("API CORS origins must be exact HTTP(S) origins.");
    expect(() =>
      loadRuntimeSettings(
        source({ BLUELEAF_API_TRUSTED_PROXY_ADDRESSES: "proxy.local" }),
      ),
    ).toThrow("Trusted proxy addresses must be at most 32 exact IP addresses.");
    const valid = loadRuntimeSettings(
      source({
        BLUELEAF_API_KEYS_JSON: JSON.stringify([
          { identity: "scanner", token: "A".repeat(40) },
        ]),
        BLUELEAF_API_ALLOWED_ORIGINS: "https://ui.example.test",
        BLUELEAF_API_TRUSTED_PROXY_ADDRESSES: "10.0.0.2",
      }),
    );
    expect(valid.apiCredentials).toHaveLength(1);
    expect(valid.api.allowedOrigins).toEqual(["https://ui.example.test"]);
    expect(valid.api.trustedProxyAddresses).toEqual(["10.0.0.2"]);
  });
});
