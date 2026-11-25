import { ApplicationError } from "../../domain/errors.js";
import type {
  NormalizedAdvisory,
  VendorPackageInformation,
} from "../../domain/intelligence.js";
import type {
  AdvisoryIntelligenceProvider,
  AdvisoryProviderResult,
} from "../../application/intelligence/contracts.js";
import { adaptOsvAdvisory } from "./osv-adapter.js";

export interface OfficialVendorProviderOptions {
  readonly timeoutMs?: number;
  readonly maxRetries?: number;
  readonly maxResponseBytes?: number;
  readonly fetch?: typeof fetch;
  readonly now?: () => Date;
  readonly sleep?: (milliseconds: number) => Promise<void>;
}
type JsonRecord = Record<string, unknown>;
function record(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function string(value: unknown): string | undefined {
  return typeof value === "string" && value.length ? value : undefined;
}
function list(value: unknown, field: string): unknown[] {
  if (value === undefined) return [];
  if (!Array.isArray(value))
    throw new ApplicationError(
      "PROVIDER_FAILURE",
      `Vendor advisory has malformed ${field}.`,
    );
  return value;
}
function advisoryId(id: string): string {
  if (
    !/^(?:CVE-\d{4}-\d{4,}|UBUNTU-CVE-\d{4}-\d{4,}|USN-\d{1,6}-\d{1,4}|LSN-\d{1,6}-\d{1,4})$/i.test(
      id,
    )
  )
    throw new ApplicationError(
      "INVALID_INPUT",
      "Vendor advisory identifier is malformed or unsupported.",
    );
  return id.toUpperCase();
}

abstract class OfficialVendorProvider implements AdvisoryIntelligenceProvider {
  public abstract readonly providerId: string;
  public readonly supportsPackageQueries = false;
  public readonly supportsIdLookups = true;
  public abstract supportsAdvisoryId(id: string): boolean;
  public abstract getAdvisory(
    id: string,
    signal?: AbortSignal,
  ): Promise<NormalizedAdvisory>;
  protected readonly fetcher: typeof fetch;
  protected readonly now: () => Date;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly timeout: number;
  private readonly retries: number;
  private readonly maxBytes: number;
  protected constructor(options: OfficialVendorProviderOptions = {}) {
    this.fetcher = options.fetch ?? fetch;
    this.now = options.now ?? ((): Date => new Date());
    this.sleep =
      options.sleep ??
      ((ms: number): Promise<void> =>
        new Promise<void>((resolve) => setTimeout(resolve, ms)));
    this.timeout = options.timeoutMs ?? 5000;
    this.retries = options.maxRetries ?? 2;
    this.maxBytes = options.maxResponseBytes ?? 4 * 1024 * 1024;
    if (
      ![this.timeout, this.retries, this.maxBytes].every(Number.isSafeInteger) ||
      this.timeout < 1 ||
      this.retries < 0 ||
      this.retries > 4 ||
      this.maxBytes < 1
    )
      throw new ApplicationError(
        "INVALID_CONFIGURATION",
        "Vendor provider bounds are invalid.",
      );
  }
  public queryPackage(): Promise<AdvisoryProviderResult> {
    return Promise.reject(
      new ApplicationError(
        "UNSUPPORTED_OPERATION",
        `${this.providerId} does not support generic package queries.`,
      ),
    );
  }
  public queryBatch(): Promise<AdvisoryProviderResult> {
    return Promise.reject(
      new ApplicationError(
        "UNSUPPORTED_OPERATION",
        `${this.providerId} does not support generic package queries.`,
      ),
    );
  }
  protected async json(url: string, parentSignal?: AbortSignal): Promise<unknown> {
    for (let attempt = 0; attempt <= this.retries; attempt += 1) {
      if (parentSignal?.aborted)
        throw new ApplicationError("CANCELLED", "Vendor request was cancelled.");
      const controller = new AbortController();
      const abortParent = (): void => controller.abort();
      parentSignal?.addEventListener("abort", abortParent, { once: true });
      const timer = setTimeout(() => controller.abort(), this.timeout);
      try {
        const response = await this.fetcher(url, {
          headers: { accept: "application/json" },
          signal: controller.signal,
        });
        if (
          (response.status === 429 || response.status === 503) &&
          attempt < this.retries
        ) {
          const retry = Number(response.headers.get("retry-after"));
          await this.sleep(
            Number.isFinite(retry) && retry > 0
              ? Math.min(30_000, retry * 1000)
              : 250 * 2 ** attempt,
          );
          continue;
        }
        if (response.status === 404)
          throw new ApplicationError(
            "NOT_FOUND",
            `${this.providerId} has no advisory for the requested identifier.`,
          );
        if (response.status === 429)
          throw new ApplicationError(
            "RATE_LIMITED",
            `${this.providerId} rate limit was reached.`,
          );
        if (!response.ok)
          throw new ApplicationError(
            "PROVIDER_FAILURE",
            `${this.providerId} returned HTTP ${response.status}.`,
          );
        const length = Number(response.headers.get("content-length"));
        if (Number.isFinite(length) && length > this.maxBytes)
          throw new ApplicationError(
            "PROVIDER_FAILURE",
            `${this.providerId} response exceeded the size limit.`,
          );
        const text = await this.readBody(response, controller.signal);
        try {
          return JSON.parse(text) as unknown;
        } catch (error) {
          throw new ApplicationError(
            "PROVIDER_FAILURE",
            `${this.providerId} returned malformed JSON.`,
            { cause: error },
          );
        }
      } catch (error) {
        if (error instanceof ApplicationError) throw error;
        if (parentSignal?.aborted)
          throw new ApplicationError("CANCELLED", "Vendor request was cancelled.", {
            cause: error,
          });
        if (error instanceof Error && error.name === "AbortError")
          throw new ApplicationError("TIMEOUT", `${this.providerId} request timed out.`, {
            cause: error,
          });
        if (attempt < this.retries) {
          await this.sleep(250 * 2 ** attempt);
          continue;
        }
        throw new ApplicationError(
          "PROVIDER_FAILURE",
          `${this.providerId} network request failed.`,
          { cause: error },
        );
      } finally {
        clearTimeout(timer);
        parentSignal?.removeEventListener("abort", abortParent);
      }
    }
    throw new ApplicationError(
      "PROVIDER_FAILURE",
      `${this.providerId} request did not complete.`,
    );
  }

  private async readBody(response: Response, signal: AbortSignal): Promise<string> {
    if (!response.body) return "";
    const reader = response.body.getReader();
    const cancel = (): void => {
      void reader.cancel();
    };
    signal.addEventListener("abort", cancel, { once: true });
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) {
        if (signal.aborted)
          throw new DOMException("Vendor response timed out", "AbortError");
        const { done, value } = await reader.read();
        if (signal.aborted)
          throw new DOMException("Vendor response timed out", "AbortError");
        if (done) break;
        size += value.byteLength;
        if (size > this.maxBytes) {
          await reader.cancel();
          throw new ApplicationError(
            "PROVIDER_FAILURE",
            `${this.providerId} response exceeded the size limit.`,
          );
        }
        chunks.push(value);
      }
    } finally {
      signal.removeEventListener("abort", cancel);
      reader.releaseLock();
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return new TextDecoder().decode(bytes);
  }
}

/** Canonical Ubuntu security notices published as individual OSV JSON records. */
export class UbuntuSecurityAdvisoryProvider extends OfficialVendorProvider {
  public readonly providerId = "ubuntu";
  public constructor(options: OfficialVendorProviderOptions = {}) {
    super(options);
  }
  public supportsAdvisoryId(id: string): boolean {
    return /^(?:CVE-\d{4}-\d{4,}|UBUNTU-CVE-\d{4}-\d{4,}|USN-\d{1,6}-\d{1,4}|LSN-\d{1,6}-\d{1,4})$/i.test(
      id,
    );
  }
  public async getAdvisory(
    id: string,
    signal?: AbortSignal,
  ): Promise<NormalizedAdvisory> {
    const normalized = advisoryId(id);
    let path: string;
    if (/^CVE-/i.test(normalized) || /^UBUNTU-CVE-/i.test(normalized)) {
      const match = normalized.match(/(?:UBUNTU-)?CVE-(\d{4})-(\d{4,})/i)!;
      path = `cve/${match[1]}/UBUNTU-CVE-${match[1]}-${match[2]}.json`;
    } else if (normalized.startsWith("USN-")) path = `usn/${normalized}.json`;
    else path = `lsn/${normalized}.json`;
    const url = `https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main/osv/${path}`;
    const raw = await this.json(url, signal);
    const retrievedAt = this.now().toISOString();
    const advisory = adaptOsvAdvisory(raw, retrievedAt);
    const rawRecord = record(raw) ? raw : {};
    const upstream = list(rawRecord["upstream"], "upstream identifiers").filter(
      (item): item is string => typeof item === "string",
    );
    return {
      ...advisory,
      relatedIdentifiers: [
        ...new Set([...(advisory.relatedIdentifiers ?? []), ...upstream]),
      ].sort(),
      provenance: {
        providerId: this.providerId,
        authority: "vendor",
        originalIdentifier: advisory.id,
        recordUrl: url,
        retrievedAt,
        ...(advisory.modifiedAt ? { sourceModifiedAt: advisory.modifiedAt } : {}),
      },
    };
  }
}

/** Official Red Hat Security Data API CVE endpoint. */
export class RedHatSecurityAdvisoryProvider extends OfficialVendorProvider {
  public readonly providerId = "redhat";
  public constructor(options: OfficialVendorProviderOptions = {}) {
    super(options);
  }
  public supportsAdvisoryId(id: string): boolean {
    return /^CVE-\d{4}-\d{4,}$/i.test(id);
  }
  public async getAdvisory(
    id: string,
    signal?: AbortSignal,
  ): Promise<NormalizedAdvisory> {
    const normalized = advisoryId(id);
    if (!normalized.startsWith("CVE-"))
      throw new ApplicationError(
        "INVALID_INPUT",
        "Red Hat lookup requires a CVE identifier.",
      );
    const url = `https://access.redhat.com/hydra/rest/securitydata/cve/${encodeURIComponent(normalized)}.json`;
    const raw = await this.json(url, signal);
    if (
      !record(raw) ||
      typeof raw["name"] !== "string" ||
      raw["name"].toUpperCase() !== normalized
    )
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "Red Hat returned an invalid CVE record.",
      );
    const details = list(raw["details"], "details").filter(
      (item): item is string => typeof item === "string",
    );
    const releases = list(raw["affected_release"], "affected releases");
    const states = list(raw["package_state"], "package states");
    const infos: VendorPackageInformation[] = [];
    for (const [value, recordType] of [
      ...releases.map((item) => [item, "affected-release"] as const),
      ...states.map((item) => [item, "package-state"] as const),
    ]) {
      if (!record(value))
        throw new ApplicationError(
          "PROVIDER_FAILURE",
          "Red Hat returned an invalid package record.",
        );
      const productName = string(value["product_name"]);
      const packageName = string(value["package_name"]);
      const packageVersion = string(value["package"]);
      const cpe = string(value["cpe"]);
      const relatedAdvisory = string(value["advisory"]);
      const releaseDate = string(value["release_date"]);
      const fixState = string(value["fix_state"]);
      const upstreamFix = string(value["upstream_fix"]);
      infos.push({
        providerId: this.providerId,
        recordType,
        ...(productName ? { productName } : {}),
        ...(packageName ? { packageName } : {}),
        ...(packageVersion ? { packageVersion } : {}),
        ...(cpe ? { cpe } : {}),
        ...(relatedAdvisory ? { advisoryId: relatedAdvisory } : {}),
        ...(releaseDate ? { releaseDate } : {}),
        ...(fixState ? { fixState } : {}),
        ...(upstreamFix ? { upstreamFix } : {}),
      });
    }
    const refs =
      typeof raw["references"] === "string"
        ? raw["references"].split(/\r?\n/).filter((item) => /^https?:\/\//i.test(item))
        : [];
    const cvss: NormalizedAdvisory["severity"][number][] = [];
    if (record(raw["cvss3"])) {
      const value = raw["cvss3"];
      const vector = string(value["cvss3_scoring_vector"]);
      if (
        typeof value["cvss3_base_score"] === "number" ||
        typeof value["cvss3_base_score"] === "string"
      )
        cvss.push({
          type: "CVSS_V3",
          score: String(value["cvss3_base_score"]),
          ...(vector ? { vector } : {}),
        });
    }
    const published = string(raw["public_date"]);
    const modified = string(raw["modified_date"]);
    if (
      (published && Number.isNaN(Date.parse(published))) ||
      (modified && Number.isNaN(Date.parse(modified)))
    )
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "Red Hat returned an invalid advisory timestamp.",
      );
    const originalIdentifier = string(raw["name"]);
    const now = this.now().toISOString();
    return {
      id: normalized,
      aliases: [],
      ...(details[0] ? { summary: details[0] } : {}),
      ...(details.length ? { details: details.join("\n\n") } : {}),
      affectedPackages: [],
      severity: [
        ...(string(raw["threat_severity"])
          ? [{ type: "RED_HAT_THREAT_SEVERITY", score: string(raw["threat_severity"])! }]
          : []),
        ...cvss,
      ],
      references: refs.map((ref) => ({ url: ref, type: "REFERENCE" })),
      ...(published ? { publishedAt: published } : {}),
      ...(modified ? { modifiedAt: modified } : {}),
      recordStatus: "active",
      vendorPackageInformation: infos,
      cpeConfigurations: infos
        .filter((item) => item.cpe)
        .map((item) => ({
          nodes: [{ matches: [{ criteria: item.cpe!, vulnerable: true }], nodes: [] }],
        })),
      provenance: {
        providerId: this.providerId,
        authority: "vendor",
        ...(originalIdentifier ? { originalIdentifier } : {}),
        recordUrl: url,
        retrievedAt: now,
        ...(modified ? { sourceModifiedAt: modified } : {}),
      },
    };
  }
}
