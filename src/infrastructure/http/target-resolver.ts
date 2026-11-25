import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { ApplicationError } from "../../domain/errors.js";
import type { ApplicationConfiguration } from "../../config/configuration.js";

export interface ResolvedAddress {
  readonly address: string;
  readonly family: 4 | 6;
}

export interface ResolvedTarget {
  readonly url: URL;
  readonly hostname: string;
  readonly addresses: readonly ResolvedAddress[];
}

export interface HostResolver {
  resolve(hostname: string): Promise<readonly ResolvedAddress[]>;
}

const systemHostResolver: HostResolver = {
  async resolve(hostname) {
    const records = await lookup(hostname, { all: true, verbatim: true });
    return records.map((record) => ({
      address: record.address,
      family: record.family as 4 | 6,
    }));
  },
};

/** Parse and canonicalize an absolute HTTP or HTTPS URL. */
export function normalizeTarget(input: string): URL {
  if (!/^https?:\/\//i.test(input)) {
    throw new ApplicationError(
      "INVALID_INPUT",
      "Target must be an absolute HTTP or HTTPS URL.",
    );
  }

  let url: URL;
  try {
    url = new URL(input);
  } catch (cause) {
    throw new ApplicationError("INVALID_INPUT", "Target URL is malformed.", { cause });
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ApplicationError(
      "INVALID_INPUT",
      "Only HTTP and HTTPS targets are supported.",
    );
  }
  if (!url.hostname || url.username || url.password) {
    throw new ApplicationError(
      "INVALID_INPUT",
      "Target URL must include a hostname and no credentials.",
    );
  }

  url.hash = "";
  return url;
}

function normalizedHostname(hostname: string): string {
  return hostname
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "")
    .toLowerCase();
}

function isHostAllowed(hostname: string, allowedHosts: readonly string[]): boolean {
  if (allowedHosts.length === 0) return true;
  const candidate = normalizedHostname(hostname);
  return allowedHosts.some((entry) => {
    const allowed = normalizedHostname(entry.trim().replace(/^\*\./, ""));
    return (
      candidate === allowed ||
      (isIP(candidate) === 0 && candidate.endsWith(`.${allowed}`))
    );
  });
}

function ipv4Number(address: string): number {
  return address
    .split(".")
    .reduce((value, octet) => ((value << 8) | Number(octet)) >>> 0, 0);
}

function inIpv4Range(address: string, base: string, prefix: number): boolean {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipv4Number(address) & mask) === (ipv4Number(base) & mask);
}

function ipv4IsGloballyRoutable(address: string): boolean {
  const denied: readonly [string, number][] = [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.88.99.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
  ];
  return !denied.some(([base, prefix]) => inIpv4Range(address, base, prefix));
}

function ipv6Words(address: string): readonly number[] | undefined {
  if (address.includes("%")) return undefined;
  let value = address.toLowerCase();
  if (value.includes(".")) {
    const lastColon = value.lastIndexOf(":");
    const ipv4 = value.slice(lastColon + 1);
    if (isIP(ipv4) !== 4) return undefined;
    const [a, b, c, d] = ipv4.split(".").map(Number);
    value = `${value.slice(0, lastColon)}:${(((a ?? 0) << 8) | (b ?? 0)).toString(16)}:${(((c ?? 0) << 8) | (d ?? 0)).toString(16)}`;
  }
  const halves = value.split("::");
  if (halves.length > 2) return undefined;
  const left = halves[0] === "" ? [] : (halves[0] ?? "").split(":");
  const right =
    halves.length === 1 || halves[1] === "" ? [] : (halves[1] ?? "").split(":");
  const fillCount = 8 - left.length - right.length;
  if ((halves.length === 1 && fillCount !== 0) || (halves.length === 2 && fillCount < 1))
    return undefined;
  const parts = [...left, ...Array.from({ length: fillCount }, () => "0"), ...right];
  if (parts.length !== 8 || parts.some((part) => !/^[\da-f]{1,4}$/i.test(part)))
    return undefined;
  return parts.map((part) => Number.parseInt(part, 16));
}

function ipv6IsGloballyRoutable(address: string): boolean {
  const words = ipv6Words(address);
  if (!words) return false;

  const mapped = words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff;
  if (mapped) {
    const [w6, w7] = words.slice(6);
    const ipv4 = `${(w6 ?? 0) >> 8}.${(w6 ?? 0) & 255}.${(w7 ?? 0) >> 8}.${(w7 ?? 0) & 255}`;
    return ipv4IsGloballyRoutable(ipv4);
  }

  // Global unicast is 2000::/3. Exclude protocol, documentation, and transition ranges.
  const first = words[0] ?? 0;
  const globalUnicast = (first & 0xe000) === 0x2000;
  const second = words[1] ?? 0;
  const protocolAssignment = first === 0x2001 && second <= 0x01ff;
  const documentation =
    (first === 0x2001 && second === 0x0db8) ||
    (first === 0x3fff && (second & 0xfff0) === 0);
  const orchid = first === 0x2001 && (second & 0xfff0) === 0x0020;
  const sixToFour = first === 0x2002;
  return globalUnicast && !protocolAssignment && !documentation && !orchid && !sixToFour;
}

export function isGloballyRoutableAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return ipv4IsGloballyRoutable(address);
  if (family === 6) return ipv6IsGloballyRoutable(address);
  return false;
}

function validateConfiguration(configuration: ApplicationConfiguration): void {
  if (
    typeof configuration.network.allowPrivateNetworks !== "boolean" ||
    !Array.isArray(configuration.network.allowedHosts) ||
    configuration.network.allowedHosts.some((host) => typeof host !== "string")
  ) {
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "Network policy configuration is invalid.",
    );
  }
  const { timeoutMs, maxResponseBytes } = configuration.http;
  const redirectLimit = configuration.http.redirectLimit ?? 5;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new ApplicationError("INVALID_CONFIGURATION", "HTTP timeout must be positive.");
  }
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes <= 0) {
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "Response byte limit must be a positive integer.",
    );
  }
  if (!Number.isSafeInteger(redirectLimit) || redirectLimit < 0 || redirectLimit > 20) {
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "Redirect limit must be an integer from 0 to 20.",
    );
  }
  for (const host of configuration.network.allowedHosts) {
    const normalized = normalizedHostname(host.trim());
    if (
      !normalized ||
      (isIP(normalized) === 0 &&
        (/[/:\s]/.test(normalized) ||
          (normalized.includes("*") && !normalized.startsWith("*."))))
    ) {
      throw new ApplicationError(
        "INVALID_CONFIGURATION",
        "Allowed hosts must contain hostnames only.",
      );
    }
  }
}

export class SecureTargetResolver {
  public constructor(private readonly hostResolver: HostResolver = systemHostResolver) {}

  public async resolve(
    input: string | URL,
    configuration: ApplicationConfiguration,
  ): Promise<ResolvedTarget> {
    validateConfiguration(configuration);
    const url =
      input instanceof URL ? normalizeTarget(input.href) : normalizeTarget(input);
    const hostname = normalizedHostname(url.hostname);

    if (!isHostAllowed(hostname, configuration.network.allowedHosts)) {
      throw new ApplicationError(
        "TARGET_REJECTED",
        "Target host is not allowed by network policy.",
      );
    }
    if (
      !configuration.network.allowPrivateNetworks &&
      (hostname === "localhost" ||
        hostname.endsWith(".localhost") ||
        hostname.endsWith(".local") ||
        hostname.endsWith(".internal"))
    ) {
      throw new ApplicationError(
        "TARGET_REJECTED",
        "Target host is reserved by network policy.",
      );
    }

    const literalFamily = isIP(hostname);
    let addresses: readonly ResolvedAddress[];
    try {
      addresses =
        literalFamily === 4 || literalFamily === 6
          ? [{ address: hostname, family: literalFamily }]
          : await this.hostResolver.resolve(hostname);
    } catch (cause) {
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "Target hostname could not be resolved.",
        { cause },
      );
    }

    if (addresses.length === 0) {
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "Target hostname did not resolve to an address.",
      );
    }
    if (addresses.some(({ address, family }) => isIP(address) !== family)) {
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "Target resolver returned an invalid address record.",
      );
    }
    if (
      !configuration.network.allowPrivateNetworks &&
      addresses.some(({ address }) => !isGloballyRoutableAddress(address))
    ) {
      throw new ApplicationError(
        "TARGET_REJECTED",
        "Target resolves to a non-public network address.",
      );
    }

    return { url, hostname, addresses };
  }
}
