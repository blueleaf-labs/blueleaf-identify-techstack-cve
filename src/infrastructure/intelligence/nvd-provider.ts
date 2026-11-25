import { ApplicationError } from "../../domain/errors.js";
import type { NormalizedAdvisory } from "../../domain/intelligence.js";
import type {
  AdvisoryIntelligenceProvider,
  AdvisoryProviderResult,
} from "../../application/intelligence/contracts.js";
import { adaptNvdPage } from "./nvd-adapter.js";

export interface NvdProviderOptions {
  readonly apiKey?: string;
  readonly timeoutMs?: number;
  readonly maxRetries?: number;
  readonly maxPages?: number;
  readonly pageSize?: number;
  readonly maxResponseBytes?: number;
  readonly throttleIntervalMs?: number;
  readonly fetch?: typeof fetch;
  readonly now?: () => Date;
  readonly sleep?: (milliseconds: number) => Promise<void>;
}
export interface NvdSyncResult extends AdvisoryProviderResult {
  readonly retrievedAt: string;
  readonly complete: boolean;
}

const CVE_ID = /^CVE-\d{4}-\d{4,}$/i;
const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
function retryAfter(response: Response): number {
  const raw = response.headers.get("retry-after");
  if (!raw) return 0;
  const seconds = Number(raw);
  if (Number.isFinite(seconds)) return Math.max(0, Math.min(30_000, seconds * 1000));
  const date = Date.parse(raw);
  return Number.isNaN(date) ? 0 : Math.max(0, Math.min(30_000, date - Date.now()));
}
function cveId(id: string): string {
  if (!CVE_ID.test(id))
    throw new ApplicationError("INVALID_INPUT", "CVE identifier is malformed.");
  return id.toUpperCase();
}

/** NVD CVE API 2.0 client. It intentionally exposes ID lookup and bounded date sync only. */
export class NvdIntelligenceProvider implements AdvisoryIntelligenceProvider {
  public readonly providerId = "nvd";
  public readonly supportsPackageQueries = false;
  public readonly supportsIdLookups = true;
  public supportsAdvisoryId(id: string): boolean {
    return CVE_ID.test(id);
  }
  private readonly fetcher: typeof fetch;
  private readonly now: () => Date;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly timeout: number;
  private readonly retries: number;
  private readonly pages: number;
  private readonly pageSize: number;
  private readonly maxBytes: number;
  private readonly interval: number;
  private nextRequestAt = 0;
  private queue: Promise<void> = Promise.resolve();

  public constructor(private readonly options: NvdProviderOptions = {}) {
    this.fetcher = options.fetch ?? fetch;
    this.now = options.now ?? ((): Date => new Date());
    this.sleep =
      options.sleep ??
      ((ms: number): Promise<void> =>
        new Promise<void>((resolve) => setTimeout(resolve, ms)));
    this.timeout = options.timeoutMs ?? 5000;
    this.retries = options.maxRetries ?? 2;
    this.pages = options.maxPages ?? 5;
    this.pageSize = options.pageSize ?? 200;
    this.maxBytes = options.maxResponseBytes ?? 8 * 1024 * 1024;
    this.interval = options.throttleIntervalMs ?? (options.apiKey ? 600 : 6000);
    if (
      ![
        this.timeout,
        this.retries,
        this.pages,
        this.pageSize,
        this.maxBytes,
        this.interval,
      ].every(Number.isSafeInteger) ||
      this.timeout < 1 ||
      this.retries < 0 ||
      this.retries > 4 ||
      this.pages < 1 ||
      this.pages > 20 ||
      this.pageSize < 1 ||
      this.pageSize > 2000 ||
      this.maxBytes < 1 ||
      this.interval < 0 ||
      (options.apiKey !== undefined &&
        (options.apiKey.length < 1 || options.apiKey.length > 512))
    )
      throw new ApplicationError(
        "INVALID_CONFIGURATION",
        "NVD provider bounds are invalid.",
      );
  }

  public queryPackage(): Promise<AdvisoryProviderResult> {
    return Promise.reject(
      new ApplicationError(
        "UNSUPPORTED_OPERATION",
        "NVD does not map arbitrary technology packages to CPEs.",
      ),
    );
  }
  public queryBatch(): Promise<AdvisoryProviderResult> {
    return Promise.reject(
      new ApplicationError(
        "UNSUPPORTED_OPERATION",
        "NVD does not map arbitrary technology packages to CPEs.",
      ),
    );
  }

  public async getAdvisory(
    id: string,
    signal?: AbortSignal,
  ): Promise<NormalizedAdvisory> {
    const normalized = cveId(id);
    const url = new URL(NVD_URL);
    url.searchParams.set("cveId", normalized);
    const page = adaptNvdPage(
      await this.requestJson(url, signal),
      this.now().toISOString(),
    );
    const match = page.advisories.find((item) => item.id.toUpperCase() === normalized);
    if (!match)
      throw new ApplicationError("NOT_FOUND", "NVD has no record for the requested CVE.");
    return match;
  }

  /** Synchronize at most maxPages * pageSize records from an inclusive window of <=120 days. */
  public async queryModifiedDateRange(
    start: string,
    end: string,
    signal?: AbortSignal,
  ): Promise<NvdSyncResult> {
    const startMs = Date.parse(start);
    const endMs = Date.parse(end);
    if (
      !Number.isFinite(startMs) ||
      !Number.isFinite(endMs) ||
      endMs < startMs ||
      endMs - startMs > 120 * 86400_000 ||
      !/[zZ]|[+-]\d\d:\d\d$/.test(start) ||
      !/[zZ]|[+-]\d\d:\d\d$/.test(end)
    )
      throw new ApplicationError(
        "INVALID_INPUT",
        "NVD modified-date window must be timezone-qualified and no longer than 120 days.",
      );
    const advisories: NormalizedAdvisory[] = [];
    const diagnostics: string[] = [];
    let total = 0;
    let complete = true;
    const retrievedAt = this.now().toISOString();
    for (let pageNo = 0; pageNo < this.pages; pageNo += 1) {
      const url = new URL(NVD_URL);
      url.searchParams.set("lastModStartDate", new Date(startMs).toISOString());
      url.searchParams.set("lastModEndDate", new Date(endMs).toISOString());
      url.searchParams.set("resultsPerPage", String(this.pageSize));
      url.searchParams.set("startIndex", String(pageNo * this.pageSize));
      const page = adaptNvdPage(await this.requestJson(url, signal), retrievedAt);
      total = page.totalResults;
      advisories.push(...page.advisories);
      if (page.startIndex + page.advisories.length >= total) break;
      if (pageNo === this.pages - 1) {
        complete = false;
        diagnostics.push(
          "NVD modified-date synchronization reached the configured page limit.",
        );
      }
    }
    if (advisories.length < total && advisories.length >= this.pages * this.pageSize)
      complete = false;
    return { advisories, diagnostics, complete, retrievedAt };
  }

  private async throttle(): Promise<void> {
    const previous = this.queue;
    let release!: () => void;
    this.queue = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      const delay = Math.max(0, this.nextRequestAt - Date.now());
      if (delay) await this.sleep(delay);
      this.nextRequestAt = Date.now() + this.interval;
    } finally {
      release();
    }
  }

  private async requestJson(url: URL, parentSignal?: AbortSignal): Promise<unknown> {
    for (let attempt = 0; attempt <= this.retries; attempt += 1) {
      if (parentSignal?.aborted)
        throw new ApplicationError("CANCELLED", "NVD request was cancelled.");
      await this.throttle();
      if (parentSignal?.aborted)
        throw new ApplicationError("CANCELLED", "NVD request was cancelled.");
      const controller = new AbortController();
      const abortParent = (): void => controller.abort();
      parentSignal?.addEventListener("abort", abortParent, { once: true });
      const timer = setTimeout(() => controller.abort(), this.timeout);
      try {
        const headers = new Headers({ accept: "application/json" });
        if (this.options.apiKey) headers.set("apiKey", this.options.apiKey);
        const response = await this.fetcher(url, {
          method: "GET",
          headers,
          signal: controller.signal,
        });
        if (
          (response.status === 429 || response.status === 503) &&
          attempt < this.retries
        ) {
          const delay = retryAfter(response) || Math.min(5000, 250 * 2 ** attempt);
          clearTimeout(timer);
          await this.sleep(delay);
          continue;
        }
        if (response.status === 429)
          throw new ApplicationError("RATE_LIMITED", "NVD rate limit was reached.");
        if (response.status === 404)
          throw new ApplicationError("NOT_FOUND", "NVD record was not found.");
        if (!response.ok)
          throw new ApplicationError(
            "PROVIDER_FAILURE",
            `NVD returned HTTP ${response.status}.`,
          );
        const length = Number(response.headers.get("content-length"));
        if (Number.isFinite(length) && length > this.maxBytes)
          throw new ApplicationError(
            "PROVIDER_FAILURE",
            "NVD response exceeded the configured size limit.",
          );
        const reader = response.body?.getReader();
        let body = "";
        if (reader) {
          const cancel = (): void => {
            void reader.cancel();
          };
          controller.signal.addEventListener("abort", cancel, { once: true });
          const chunks: Uint8Array[] = [];
          let size = 0;
          try {
            while (true) {
              if (controller.signal.aborted)
                throw new DOMException("NVD request timed out", "AbortError");
              const { done, value } = await reader.read();
              if (controller.signal.aborted)
                throw new DOMException("NVD request timed out", "AbortError");
              if (done) break;
              size += value.byteLength;
              if (size > this.maxBytes) {
                await reader.cancel();
                throw new ApplicationError(
                  "PROVIDER_FAILURE",
                  "NVD response exceeded the configured size limit.",
                );
              }
              chunks.push(value);
            }
          } finally {
            controller.signal.removeEventListener("abort", cancel);
            reader.releaseLock();
          }
          const bytes = new Uint8Array(size);
          let offset = 0;
          for (const chunk of chunks) {
            bytes.set(chunk, offset);
            offset += chunk.byteLength;
          }
          body = new TextDecoder().decode(bytes);
        }
        try {
          return JSON.parse(body) as unknown;
        } catch (error) {
          throw new ApplicationError("PROVIDER_FAILURE", "NVD returned malformed JSON.", {
            cause: error,
          });
        }
      } catch (error) {
        if (error instanceof ApplicationError) throw error;
        if (parentSignal?.aborted)
          throw new ApplicationError("CANCELLED", "NVD request was cancelled.", {
            cause: error,
          });
        if (error instanceof Error && error.name === "AbortError")
          throw new ApplicationError("TIMEOUT", "NVD request timed out.", {
            cause: error,
          });
        if (attempt < this.retries) {
          await this.sleep(Math.min(5000, 250 * 2 ** attempt));
          continue;
        }
        throw new ApplicationError("PROVIDER_FAILURE", "NVD network request failed.", {
          cause: error,
        });
      } finally {
        clearTimeout(timer);
        parentSignal?.removeEventListener("abort", abortParent);
      }
    }
    throw new ApplicationError("PROVIDER_FAILURE", "NVD request did not complete.");
  }
}
