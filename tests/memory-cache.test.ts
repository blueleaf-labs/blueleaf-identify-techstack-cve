import { describe, expect, it } from "vitest";
import { MemoryCacheProvider } from "../src/infrastructure/cache/memory-cache.js";

describe("MemoryCacheProvider", () => {
  it("bounds entry count and evicts the least recently used key", async () => {
    const cache = new MemoryCacheProvider(Date.now, { maxEntries: 2, maxBytes: 1024 });
    await cache.set("a", "one", 60);
    await cache.set("b", "two", 60);
    await cache.get("a");
    await cache.set("c", "three", 60);

    expect(await cache.get("a")).toBe("one");
    expect(await cache.get("b")).toBeUndefined();
    expect(await cache.get("c")).toBe("three");
    expect(cache.size).toBe(2);
  });

  it("bounds serialized cache bytes and skips a single oversized value", async () => {
    const cache = new MemoryCacheProvider(Date.now, { maxEntries: 10, maxBytes: 12 });
    await cache.set("one", "12345", 60);
    await cache.set("two", "67890", 60);
    await cache.set("too-large", "x".repeat(20), 60);

    expect(cache.sizeBytes).toBeLessThanOrEqual(12);
    expect(cache.size).toBeLessThanOrEqual(10);
    expect(await cache.get("too-large")).toBeUndefined();
  });

  it("expires stale records and removes their accounted bytes", async () => {
    let now = 0;
    const cache = new MemoryCacheProvider(() => now, { maxEntries: 2, maxBytes: 1024 });
    await cache.set("a", "value", 1);
    expect(cache.sizeBytes).toBeGreaterThan(0);
    now = 1_001;

    expect(await cache.get("a")).toBeUndefined();
    expect(cache.size).toBe(0);
    expect(cache.sizeBytes).toBe(0);
  });
});
