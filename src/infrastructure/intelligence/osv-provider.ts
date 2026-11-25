import { ApplicationError } from "../../domain/errors.js";
import type {
  AdvisoryPackageQuery,
  NormalizedAdvisory,
} from "../../domain/intelligence.js";
import type {
  AdvisoryIntelligenceProvider,
  AdvisoryProviderResult,
} from "../../application/intelligence/contracts.js";
import { adaptOsvAdvisory, adaptOsvBatchPage, adaptOsvQueryPage } from "./osv-adapter.js";

export interface OsvProviderOptions {
  readonly timeoutMs?: number;
  readonly maxRetries?: number;
  readonly maxBatchSize?: number;
  readonly maxPages?: number;
  readonly maxAdvisoriesPerBatch?: number;
  readonly maxResponseBytes?: number;
  readonly fetch?: typeof fetch;
  readonly now?: () => Date;
  readonly sleep?: (milliseconds: number) => Promise<void>;
}

type OsvQuery = {
  package: { ecosystem: string; name: string };
  version: string;
  page_token?: string;
};
function retryDelay(response: Response): number {
  const value = response.headers.get("retry-after");
  if (!value) return 0;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return Math.max(0, Math.min(1_000, seconds * 1_000));
  const timestamp = Date.parse(value);
  return Number.isNaN(timestamp)
    ? 0
    : Math.max(0, Math.min(1_000, timestamp - Date.now()));
}

/** Official public OSV API client. No credentials are required or accepted. */
export class OsvIntelligenceProvider implements AdvisoryIntelligenceProvider {
  public readonly providerId = "osv";
  public supportsAdvisoryId(id: string): boolean {
    return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id);
  }
  public readonly maxBatchSize: number;
  private readonly fetcher: typeof fetch;
  private readonly now: () => Date;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly timeout: number;
  private readonly retries: number;
  private readonly batchSize: number;
  private readonly pages: number;
  private readonly maxAdvisories: number;
  private readonly maxResponseBytes: number;

  public constructor(options: OsvProviderOptions = {}) {
    this.fetcher = options.fetch ?? fetch;
    this.now = options.now ?? ((): Date => new Date());
    this.sleep =
      options.sleep ??
      ((ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms)));
    this.timeout = options.timeoutMs ?? 5_000;
    this.retries = options.maxRetries ?? 2;
    this.batchSize = options.maxBatchSize ?? 100;
    this.maxBatchSize = this.batchSize;
    this.pages = options.maxPages ?? 5;
    this.maxAdvisories = options.maxAdvisoriesPerBatch ?? 500;
    this.maxResponseBytes = options.maxResponseBytes ?? 8 * 1024 * 1024;
    if (
      ![
        this.timeout,
        this.retries,
        this.batchSize,
        this.pages,
        this.maxAdvisories,
        this.maxResponseBytes,
      ].every(Number.isSafeInteger) ||
      this.timeout < 1 ||
      this.batchSize < 1 ||
      this.batchSize > 100 ||
      this.pages < 1 ||
      this.pages > 10 ||
      this.maxAdvisories < 1 ||
      this.maxResponseBytes < 1 ||
      this.retries < 0 ||
      this.retries > 4
    )
      throw new ApplicationError(
        "INVALID_CONFIGURATION",
        "OSV provider bounds are invalid.",
      );
  }

  public async queryPackage(
    query: AdvisoryPackageQuery,
    signal?: AbortSignal,
  ): Promise<AdvisoryProviderResult> {
    this.validateQuery(query);
    const advisoryRecords: NormalizedAdvisory[] = [];
    const diagnostics: string[] = [];
    let token: string | undefined;
    let complete = true;
    for (let page = 0; page < this.pages; page += 1) {
      if (signal?.aborted)
        throw new ApplicationError("CANCELLED", "OSV query was cancelled.");
      const body: OsvQuery = {
        package: { ecosystem: query.ecosystem, name: query.name },
        version: query.version,
        ...(token ? { page_token: token } : {}),
      };
      const response = await this.requestJson(
        "https://api.osv.dev/v1/query",
        {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify(body),
        },
        signal,
      );
      const pageResult = adaptOsvQueryPage(response, this.now().toISOString());
      advisoryRecords.push(...pageResult.advisories);
      token = pageResult.nextPageToken;
      if (!token) break;
      if (page === this.pages - 1) {
        complete = false;
        diagnostics.push("OSV query pagination reached the configured page limit.");
      }
    }
    return { advisories: this.dedupe(advisoryRecords), complete, diagnostics };
  }

  public async queryBatch(
    queries: readonly AdvisoryPackageQuery[],
    signal?: AbortSignal,
  ): Promise<AdvisoryProviderResult> {
    if (
      !Array.isArray(queries) ||
      queries.length === 0 ||
      queries.length > this.batchSize
    )
      throw new ApplicationError(
        "INVALID_INPUT",
        `OSV batch must contain between 1 and ${this.batchSize} queries.`,
      );
    queries.forEach((query) => this.validateQuery(query));
    const ids = new Set<string>();
    const diagnostics: string[] = [];
    let complete = true;
    let pending: { query: OsvQuery; index: number }[] = queries.map((query, index) => ({
      query: {
        package: { ecosystem: query.ecosystem, name: query.name },
        version: query.version,
      },
      index,
    }));
    for (let page = 0; pending.length > 0 && page < this.pages; page += 1) {
      if (signal?.aborted)
        throw new ApplicationError("CANCELLED", "OSV batch was cancelled.");
      const response = await this.requestJson(
        "https://api.osv.dev/v1/querybatch",
        {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify({ queries: pending.map((item) => item.query) }),
        },
        signal,
      );
      const pageResult = adaptOsvBatchPage(response, pending.length);
      const next: typeof pending = [];
      for (let resultIndex = 0; resultIndex < pending.length; resultIndex += 1) {
        const item = pageResult.results[resultIndex]!;
        if (!item.complete) {
          complete = false;
          diagnostics.push(
            `OSV batch item ${pending[resultIndex]!.index} was malformed.`,
          );
        }
        for (const id of item.advisoryIds) {
          if (ids.size < this.maxAdvisories) ids.add(id);
          else complete = false;
        }
        if (item.nextPageToken)
          next.push({
            ...pending[resultIndex]!,
            query: {
              ...pending[resultIndex]!.query,
              page_token: item.nextPageToken,
            },
          });
      }
      pending = next;
      if (pending.length && page === this.pages - 1) {
        complete = false;
        diagnostics.push("OSV batch pagination reached the configured page limit.");
      }
    }
    if (ids.size >= this.maxAdvisories)
      diagnostics.push("OSV batch advisory result cap was reached.");
    const hydrated: (NormalizedAdvisory | undefined)[] = [];
    const advisoryIds = [...ids];
    for (let offset = 0; offset < advisoryIds.length; offset += 8) {
      if (signal?.aborted)
        throw new ApplicationError("CANCELLED", "OSV batch was cancelled.");
      const page = await Promise.all(
        advisoryIds.slice(offset, offset + 8).map(async (id) => {
          try {
            return await this.getAdvisory(id, signal);
          } catch (error) {
            if (signal?.aborted)
              throw new ApplicationError("CANCELLED", "OSV batch was cancelled.", {
                cause: error,
              });
            complete = false;
            diagnostics.push(`OSV advisory ${id} could not be retrieved.`);
            return undefined;
          }
        }),
      );
      hydrated.push(...page);
    }
    return {
      advisories: this.dedupe(
        hydrated.filter((item): item is NormalizedAdvisory => item !== undefined),
      ),
      complete,
      diagnostics: [...new Set(diagnostics)],
    };
  }

  public async getAdvisory(
    id: string,
    signal?: AbortSignal,
  ): Promise<NormalizedAdvisory> {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id))
      throw new ApplicationError("INVALID_INPUT", "Advisory ID is malformed.");
    const response = await this.requestJson(
      `https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`,
      { method: "GET", headers: { accept: "application/json" } },
      signal,
    );
    return adaptOsvAdvisory(response, this.now().toISOString());
  }

  private validateQuery(query: AdvisoryPackageQuery): void {
    if (
      !query ||
      !query.ecosystem.trim() ||
      !query.name.trim() ||
      !query.version.trim() ||
      query.version.length > 128
    )
      throw new ApplicationError(
        "INVALID_INPUT",
        "OSV query requires package, ecosystem, and bounded version values.",
      );
  }

  private async requestJson(
    url: string,
    init: RequestInit,
    parentSignal?: AbortSignal,
  ): Promise<unknown> {
    for (let attempt = 0; attempt <= this.retries; attempt += 1) {
      if (parentSignal?.aborted)
        throw new ApplicationError("CANCELLED", "OSV request was cancelled.");
      const controller = new AbortController();
      const abortParent = (): void => controller.abort();
      parentSignal?.addEventListener("abort", abortParent, { once: true });
      const timer = setTimeout(() => controller.abort(), this.timeout);
      try {
        const response = await this.fetcher(url, { ...init, signal: controller.signal });
        if (response.status === 429 || response.status === 503) {
          if (attempt < this.retries) {
            const delay = retryDelay(response);
            clearTimeout(timer);
            await this.sleep(delay);
            continue;
          }
          throw new ApplicationError(
            "RATE_LIMITED",
            "OSV rate limited the request or is temporarily unavailable.",
          );
        }
        if (!response.ok)
          throw new ApplicationError(
            "PROVIDER_FAILURE",
            `OSV returned HTTP ${response.status}.`,
          );
        const contentLength = Number(response.headers.get("content-length"));
        if (Number.isFinite(contentLength) && contentLength > this.maxResponseBytes)
          throw new ApplicationError(
            "PROVIDER_FAILURE",
            "OSV response exceeded the configured size boundary.",
          );
        const text = await this.readBoundedBody(response, controller.signal);
        try {
          return JSON.parse(text) as unknown;
        } catch (error) {
          throw new ApplicationError("PROVIDER_FAILURE", "OSV returned malformed JSON.", {
            cause: error,
          });
        }
      } catch (error) {
        if (error instanceof ApplicationError) throw error;
        if (parentSignal?.aborted)
          throw new ApplicationError("CANCELLED", "OSV request was cancelled.", {
            cause: error,
          });
        if (
          attempt < this.retries &&
          !(error instanceof Error && error.name === "AbortError")
        )
          continue;
        if (error instanceof Error && error.name === "AbortError")
          throw new ApplicationError("TIMEOUT", "OSV request timed out.", {
            cause: error,
          });
        throw new ApplicationError("PROVIDER_FAILURE", "OSV network request failed.", {
          cause: error,
        });
      } finally {
        clearTimeout(timer);
        parentSignal?.removeEventListener("abort", abortParent);
      }
    }
    throw new ApplicationError("PROVIDER_FAILURE", "OSV request did not complete.");
  }

  private async readBoundedBody(
    response: Response,
    signal: AbortSignal,
  ): Promise<string> {
    if (!response.body) return "";
    const reader = response.body.getReader();
    const abortReader = (): void => {
      void reader.cancel();
    };
    signal.addEventListener("abort", abortReader, { once: true });
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    try {
      while (true) {
        if (signal.aborted)
          throw new DOMException("OSV response timed out", "AbortError");
        const { done, value } = await reader.read();
        if (signal.aborted)
          throw new DOMException("OSV response timed out", "AbortError");
        if (done) break;
        totalBytes += value.byteLength;
        if (totalBytes > this.maxResponseBytes) {
          await reader.cancel();
          throw new ApplicationError(
            "PROVIDER_FAILURE",
            "OSV response exceeded the configured size boundary.",
          );
        }
        chunks.push(value);
      }
    } catch (error) {
      if (signal.aborted) throw new DOMException("OSV response timed out", "AbortError");
      throw error;
    } finally {
      signal.removeEventListener("abort", abortReader);
      reader.releaseLock();
    }
    const bytes = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return new TextDecoder().decode(bytes);
  }

  private dedupe(records: readonly NormalizedAdvisory[]): readonly NormalizedAdvisory[] {
    const map = new Map<string, NormalizedAdvisory>();
    for (const item of records) map.set(item.id, item);
    return [...map.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  }
}
