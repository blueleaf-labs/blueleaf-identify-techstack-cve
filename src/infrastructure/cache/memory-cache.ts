import type { CacheProvider } from "../../application/ports.js";

export interface MemoryCacheOptions {
  readonly maxEntries?: number;
  readonly maxBytes?: number;
}

interface CacheEntry {
  readonly value: string;
  readonly expiresAt: number;
  readonly byteLength: number;
}

/** Process-local TTL/LRU cache with hard entry and serialized-byte bounds. */
export class MemoryCacheProvider implements CacheProvider {
  private readonly values = new Map<string, CacheEntry>();
  private readonly maxEntries: number;
  private readonly maxBytes: number;
  private byteLength = 0;

  public constructor(
    private readonly now: () => number = Date.now,
    options: MemoryCacheOptions = {},
  ) {
    this.maxEntries = options.maxEntries ?? 2_000;
    this.maxBytes = options.maxBytes ?? 32 * 1024 * 1024;
    if (
      !Number.isSafeInteger(this.maxEntries) ||
      this.maxEntries < 1 ||
      !Number.isSafeInteger(this.maxBytes) ||
      this.maxBytes < 1
    )
      throw new Error("Memory cache bounds must be positive safe integers.");
  }

  public async get(key: string): Promise<string | undefined> {
    const entry = this.values.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= this.now()) {
      this.remove(key, entry);
      return undefined;
    }
    // Map insertion order is the least-recently-used eviction order.
    this.values.delete(key);
    this.values.set(key, entry);
    return entry.value;
  }

  public async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    const previous = this.values.get(key);
    if (previous) this.remove(key, previous);
    if (ttlSeconds <= 0) return;
    if (!Number.isFinite(ttlSeconds)) throw new Error("Cache TTL must be finite.");

    const length = Buffer.byteLength(key, "utf8") + Buffer.byteLength(value, "utf8");
    // Oversized cache values remain available to the current caller, but are not retained.
    if (length > this.maxBytes) return;
    this.pruneExpired();
    while (
      this.values.size >= this.maxEntries ||
      this.byteLength + length > this.maxBytes
    ) {
      const oldest = this.values.entries().next().value as
        [string, CacheEntry] | undefined;
      if (!oldest) break;
      this.remove(oldest[0], oldest[1]);
    }
    const entry: CacheEntry = {
      value,
      expiresAt: this.now() + ttlSeconds * 1000,
      byteLength: length,
    };
    this.values.set(key, entry);
    this.byteLength += length;
  }

  public async delete(key: string): Promise<void> {
    const entry = this.values.get(key);
    if (entry) this.remove(key, entry);
  }

  public get size(): number {
    return this.values.size;
  }

  public get sizeBytes(): number {
    return this.byteLength;
  }

  private pruneExpired(): void {
    const now = this.now();
    for (const [key, entry] of this.values) {
      if (entry.expiresAt <= now) this.remove(key, entry);
    }
  }

  private remove(key: string, entry: CacheEntry): void {
    if (this.values.delete(key))
      this.byteLength = Math.max(0, this.byteLength - entry.byteLength);
  }
}
