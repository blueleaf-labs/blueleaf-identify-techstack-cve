import { ApplicationError } from "../domain/errors.js";
import { isIP } from "node:net";
import type { ApiCredential } from "./api-security.js";
import { validateApiCredentials } from "./api-security.js";
import type { TechnologyPackageIdentityMapping } from "../domain/correlation.js";
import {
  DEFAULT_APPLICATION_CONFIGURATION,
  type ApplicationConfiguration,
  type ConfigurationSource,
} from "./configuration.js";

export interface RuntimeSettings {
  readonly configuration: ApplicationConfiguration;
  readonly packageMappings: readonly TechnologyPackageIdentityMapping[];
  readonly apiCredentials: readonly ApiCredential[];
  readonly api: {
    readonly host: string;
    readonly port: number;
    readonly allowExternal: boolean;
    readonly maxRequestBytes: number;
    readonly maxResponseBytes: number;
    readonly scanTimeoutMs: number;
    readonly requestTimeoutMs: number;
    readonly maxConcurrentScans: number;
    readonly maxConcurrentScansPerIdentity: number;
    readonly publicHealth: boolean;
    readonly allowedOrigins: readonly string[];
    readonly trustedProxyAddresses: readonly string[];
    readonly tlsTerminated: boolean;
    readonly rateLimit: number;
    readonly rateWindowMs: number;
    readonly maxRateLimitEntries: number;
    readonly shutdownGraceMs: number;
  };
  readonly maxAdvisoryLookups: number;
}

function apiCredentials(source: ConfigurationSource): ApiCredential[] {
  const raw = source.get("BLUELEAF_API_KEYS_JSON");
  if (raw === undefined || raw.trim() === "") return [];
  if (raw.length > 65_536)
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "BLUELEAF_API_KEYS_JSON exceeds 64 KiB.",
    );
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "BLUELEAF_API_KEYS_JSON must contain a JSON array.",
    );
  }
  if (!Array.isArray(parsed))
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "BLUELEAF_API_KEYS_JSON must contain a JSON array.",
    );
  const validShape = parsed.every((item: unknown) => {
    if (typeof item !== "object" || item === null || Array.isArray(item)) return false;
    const row = item as Record<string, unknown>;
    return (
      typeof row["identity"] === "string" &&
      typeof row["token"] === "string" &&
      (row["expiresAt"] === undefined || typeof row["expiresAt"] === "string") &&
      (row["disabled"] === undefined || typeof row["disabled"] === "boolean") &&
      Object.keys(row).every((key) =>
        ["identity", "token", "expiresAt", "disabled"].includes(key),
      )
    );
  });
  if (!validShape)
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "BLUELEAF_API_KEYS_JSON contains an invalid credential record.",
    );
  try {
    validateApiCredentials(parsed as ApiCredential[]);
  } catch (cause) {
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "BLUELEAF_API_KEYS_JSON credentials are invalid or inactive.",
      { cause },
    );
  }
  return parsed as ApiCredential[];
}

function origins(source: ConfigurationSource): string[] {
  const values = (source.get("BLUELEAF_API_ALLOWED_ORIGINS") ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (values.length > 100)
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "At most 100 API CORS origins may be configured.",
    );
  for (const value of values) {
    let origin: URL;
    try {
      origin = new URL(value);
    } catch {
      throw new ApplicationError(
        "INVALID_CONFIGURATION",
        "API CORS origins must be exact HTTP(S) origins.",
      );
    }
    if (
      !["http:", "https:"].includes(origin.protocol) ||
      origin.origin !== value ||
      value === "*"
    )
      throw new ApplicationError(
        "INVALID_CONFIGURATION",
        "API CORS origins must be exact HTTP(S) origins without paths or wildcards.",
      );
  }
  return [...new Set(values)];
}

function trustedProxies(source: ConfigurationSource): string[] {
  const values = (source.get("BLUELEAF_API_TRUSTED_PROXY_ADDRESSES") ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (values.some((item) => isIP(item) === 0) || values.length > 32)
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "Trusted proxy addresses must be at most 32 exact IP addresses.",
    );
  return [...new Set(values.map((item) => item.toLowerCase()))];
}

function integer(
  source: ConfigurationSource,
  name: string,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const raw = source.get(name);
  if (raw === undefined || raw.trim() === "") return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum)
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      `${name} must be an integer between ${minimum} and ${maximum}.`,
    );
  return value;
}

function boolean(source: ConfigurationSource, name: string, fallback: boolean): boolean {
  const raw = source.get(name);
  if (raw === undefined || raw.trim() === "") return fallback;
  if (raw.trim().toLowerCase() === "true") return true;
  if (raw.trim().toLowerCase() === "false") return false;
  throw new ApplicationError("INVALID_CONFIGURATION", `${name} must be true or false.`);
}

function packageMappings(
  source: ConfigurationSource,
): TechnologyPackageIdentityMapping[] {
  const raw = source.get("BLUELEAF_PACKAGE_MAPPINGS_JSON");
  if (raw === undefined || raw.trim() === "") return [];
  if (raw.length > 65_536)
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "BLUELEAF_PACKAGE_MAPPINGS_JSON exceeds 64 KiB.",
    );
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "BLUELEAF_PACKAGE_MAPPINGS_JSON must contain a JSON array.",
    );
  }
  if (!Array.isArray(parsed))
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "BLUELEAF_PACKAGE_MAPPINGS_JSON must contain a JSON array.",
    );
  const valid = parsed.every((item: unknown) => {
    if (typeof item !== "object" || item === null || Array.isArray(item)) return false;
    const mapping = item as Record<string, unknown>;
    const pkg = mapping["package"];
    const cpe = mapping["cpe"];
    const rangeTypes = mapping["supportedRangeTypes"];
    const pkgRecord =
      typeof pkg === "object" && pkg !== null && !Array.isArray(pkg)
        ? (pkg as Record<string, unknown>)
        : undefined;
    const cpeRecord =
      typeof cpe === "object" && cpe !== null && !Array.isArray(cpe)
        ? (cpe as Record<string, unknown>)
        : undefined;
    const ecosystem = pkgRecord?.["ecosystem"];
    const packageName = pkgRecord?.["name"];
    const cpeVendor = cpeRecord?.["vendor"];
    const cpeProduct = cpeRecord?.["product"];
    const packageValid =
      pkgRecord !== undefined &&
      typeof ecosystem === "string" &&
      ecosystem.trim().length > 0 &&
      typeof packageName === "string" &&
      packageName.trim().length > 0 &&
      Object.keys(pkgRecord).every((key) => ["ecosystem", "name"].includes(key));
    const cpeValid =
      cpe === undefined ||
      (cpeRecord !== undefined &&
        typeof cpeVendor === "string" &&
        cpeVendor.trim().length > 0 &&
        typeof cpeProduct === "string" &&
        cpeProduct.trim().length > 0 &&
        ["SEMVER", "ECOSYSTEM"].includes(String(cpeRecord["rangeType"])) &&
        Object.keys(cpeRecord).every((key) =>
          ["vendor", "product", "rangeType"].includes(key),
        ));
    const requiredStrings = ["mappingId", "technologyId", "versionStrategyId"] as const;
    return (
      requiredStrings.every(
        (key) => typeof mapping[key] === "string" && mapping[key].trim().length > 0,
      ) &&
      typeof mapping["mappingId"] === "string" &&
      /^[a-z0-9][a-z0-9._-]{0,127}$/.test(mapping["mappingId"]) &&
      typeof mapping["technologyId"] === "string" &&
      /^[a-z0-9][a-z0-9._-]{0,127}$/.test(mapping["technologyId"]) &&
      packageValid &&
      ["operator-verified", "upstream-documentation", "vendor-documentation"].includes(
        String(mapping["authority"]),
      ) &&
      Array.isArray(rangeTypes) &&
      rangeTypes.length > 0 &&
      new Set(rangeTypes).size === rangeTypes.length &&
      rangeTypes.every((value) => value === "SEMVER" || value === "ECOSYSTEM") &&
      cpeValid &&
      Object.keys(mapping).every((key) =>
        [
          "mappingId",
          "technologyId",
          "package",
          "authority",
          "versionStrategyId",
          "supportedRangeTypes",
          "vendor",
          "distribution",
          "cpe",
        ].includes(key),
      ) &&
      (mapping["vendor"] === undefined ||
        (typeof mapping["vendor"] === "string" && mapping["vendor"].trim().length > 0)) &&
      (mapping["distribution"] === undefined ||
        (typeof mapping["distribution"] === "string" &&
          mapping["distribution"].trim().length > 0))
    );
  });
  if (!valid)
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "BLUELEAF_PACKAGE_MAPPINGS_JSON contains an invalid package mapping.",
    );
  return parsed as TechnologyPackageIdentityMapping[];
}

export function loadRuntimeSettings(source: ConfigurationSource): RuntimeSettings {
  const timeoutMs = integer(source, "BLUELEAF_SCAN_TIMEOUT_MS", 10_000, 100, 60_000);
  const maxResponseBytes = integer(
    source,
    "BLUELEAF_MAX_RESPONSE_BYTES",
    2 * 1024 * 1024,
    1024,
    2 * 1024 * 1024,
  );
  const redirectLimit = integer(source, "BLUELEAF_REDIRECT_LIMIT", 5, 0, 20);
  const allowedHosts = (source.get("BLUELEAF_ALLOWED_HOSTS") ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const nvdApiKey = source.get("BLUELEAF_NVD_API_KEY");
  const base = DEFAULT_APPLICATION_CONFIGURATION;
  const configuration: ApplicationConfiguration = {
    ...base,
    http: { timeoutMs, maxResponseBytes, redirectLimit },
    network: {
      allowedHosts,
      allowPrivateNetworks: boolean(source, "BLUELEAF_ALLOW_PRIVATE_NETWORKS", false),
    },
    cache: {
      defaultTtlSeconds: integer(source, "BLUELEAF_CACHE_TTL_SECONDS", 300, 0, 86_400),
      maxEntries: integer(source, "BLUELEAF_CACHE_MAX_ENTRIES", 2_000, 1, 100_000),
      maxBytes: integer(
        source,
        "BLUELEAF_CACHE_MAX_BYTES",
        32 * 1024 * 1024,
        1024,
        512 * 1024 * 1024,
      ),
    },
    intelligence: {
      ...base.intelligence!,
      timeoutMs: integer(source, "BLUELEAF_INTELLIGENCE_TIMEOUT_MS", 5_000, 100, 30_000),
      cacheTtlSeconds: integer(
        source,
        "BLUELEAF_INTELLIGENCE_CACHE_TTL_SECONDS",
        300,
        0,
        86_400,
      ),
      ...(nvdApiKey ? { nvdApiKey } : {}),
    },
  };
  const host = source.get("BLUELEAF_API_HOST")?.trim() || "127.0.0.1";
  const allowExternal = boolean(source, "BLUELEAF_API_ALLOW_EXTERNAL", false);
  const tlsTerminated = boolean(source, "BLUELEAF_API_TLS_TERMINATED", false);
  const proxies = trustedProxies(source);
  const credentials = apiCredentials(source);
  const normalizedHost = host.replace(/^\[|\]$/g, "").toLowerCase();
  const loopback = ["localhost", "127.0.0.1", "::1"].includes(normalizedHost);
  if (!loopback && !allowExternal)
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "Non-loopback API binding requires BLUELEAF_API_ALLOW_EXTERNAL=true.",
    );
  if (!loopback && !tlsTerminated)
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "Non-loopback API binding requires TLS termination at a trusted ingress.",
    );
  if (!loopback && proxies.length === 0)
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "Non-loopback API binding requires BLUELEAF_API_TRUSTED_PROXY_ADDRESSES.",
    );
  if (!loopback && credentials.length === 0)
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "Non-loopback API binding requires configured API credentials.",
    );
  if (
    (source.get("NODE_ENV") ?? "").toLowerCase() === "production" &&
    configuration.network.allowPrivateNetworks &&
    allowedHosts.length === 0
  )
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "Production private-network probing requires an explicit host allowlist.",
    );
  const maxConcurrentScans = integer(
    source,
    "BLUELEAF_API_MAX_CONCURRENT_SCANS",
    2,
    1,
    32,
  );
  const maxConcurrentScansPerIdentity = integer(
    source,
    "BLUELEAF_API_MAX_CONCURRENT_SCANS_PER_IDENTITY",
    2,
    1,
    32,
  );
  if (maxConcurrentScansPerIdentity > maxConcurrentScans)
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "Per-identity concurrency cannot exceed global concurrency.",
    );
  return {
    configuration,
    packageMappings: packageMappings(source),
    apiCredentials: credentials,
    api: {
      host,
      port: integer(source, "BLUELEAF_API_PORT", 8787, 1, 65_535),
      allowExternal,
      publicHealth: boolean(source, "BLUELEAF_API_PUBLIC_HEALTH", false),
      allowedOrigins: origins(source),
      trustedProxyAddresses: proxies,
      tlsTerminated,
      rateLimit: integer(source, "BLUELEAF_API_RATE_LIMIT", 60, 1, 10_000),
      rateWindowMs: integer(
        source,
        "BLUELEAF_API_RATE_WINDOW_MS",
        60_000,
        1_000,
        3_600_000,
      ),
      maxRateLimitEntries: integer(
        source,
        "BLUELEAF_API_MAX_RATE_LIMIT_ENTRIES",
        10_000,
        100,
        100_000,
      ),
      shutdownGraceMs: integer(
        source,
        "BLUELEAF_API_SHUTDOWN_GRACE_MS",
        10_000,
        1_000,
        60_000,
      ),
      maxRequestBytes: integer(
        source,
        "BLUELEAF_API_MAX_REQUEST_BYTES",
        8 * 1024,
        256,
        1024 * 1024,
      ),
      maxResponseBytes: integer(
        source,
        "BLUELEAF_API_MAX_RESPONSE_BYTES",
        12 * 1024 * 1024,
        1024,
        32 * 1024 * 1024,
      ),
      scanTimeoutMs: integer(
        source,
        "BLUELEAF_API_SCAN_TIMEOUT_MS",
        30_000,
        100,
        120_000,
      ),
      requestTimeoutMs: integer(
        source,
        "BLUELEAF_API_REQUEST_TIMEOUT_MS",
        15_000,
        1_000,
        120_000,
      ),
      maxConcurrentScans,
      maxConcurrentScansPerIdentity,
    },
    maxAdvisoryLookups: integer(source, "BLUELEAF_MAX_ADVISORY_LOOKUPS", 20, 0, 100),
  };
}

export const processEnvironmentSource: ConfigurationSource = {
  get(name: string): string | undefined {
    return process.env[name];
  },
};
