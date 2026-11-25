import { describe, expect, it } from "vitest";
import {
  BoundedFixedWindowLimiter,
  clientAddress,
  safeLogText,
  timingSafeCredentialMatch,
} from "../src/api/security.js";

describe("API security primitives", () => {
  it("uses a fixed-length timing-safe credential comparison", () => {
    expect(timingSafeCredentialMatch("same-key", "same-key")).toBe(true);
    expect(timingSafeCredentialMatch("same-key", "different-key")).toBe(false);
    expect(timingSafeCredentialMatch("short", "a-much-longer-secret")).toBe(false);
  });

  it("bounds fixed-window buckets and returns retry timing", () => {
    let now = 0;
    const limiter = new BoundedFixedWindowLimiter(1, 1000, 2, () => now);
    expect(limiter.consume("identity:a").allowed).toBe(true);
    expect(limiter.consume("identity:a")).toEqual({
      allowed: false,
      retryAfterSeconds: 1,
      shouldLogRejection: true,
    });
    expect(limiter.consume("identity:b").allowed).toBe(true);
    expect(limiter.consume("identity:c")).toEqual({
      allowed: false,
      retryAfterSeconds: 1,
      shouldLogRejection: false,
    });
    now = 1000;
    expect(limiter.consume("identity:c").allowed).toBe(true);
    expect(limiter.size).toBe(1);
  });

  it("trusts forwarded addresses only from configured proxies and rejects malformed chains", () => {
    expect(clientAddress("203.0.113.10", "198.51.100.20", [])).toBe("203.0.113.10");
    expect(
      clientAddress("10.0.0.2", "198.51.100.20, 10.0.0.1", ["10.0.0.2", "10.0.0.1"]),
    ).toBe("198.51.100.20");
    expect(
      clientAddress("10.0.0.2", "attacker, 10.0.0.1", ["10.0.0.2", "10.0.0.1"]),
    ).toBe("10.0.0.2");
  });

  it("removes control characters from security log fields", () => {
    expect(safeLogText("safe\r\nforged", 30)).toBe("safeforged");
    expect(safeLogText("a".repeat(100), 8)).toBe("a".repeat(8));
  });
});
