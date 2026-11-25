import { createHash, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import type {
  ApiCredential,
  SecurityEvent,
  SecurityEventLogger,
} from "../config/api-security.js";

const TOKEN_PREFIX = /^Bearer ([A-Za-z0-9._~+/-]+=*)$/;

export const stderrSecurityLogger: SecurityEventLogger = {
  write(event: SecurityEvent): void {
    process.stderr.write(`${JSON.stringify(event)}\n`);
  },
};

export function safeLogText(value: string, maximum = 64): string {
  // This range intentionally strips ASCII and C1 control characters from audit fields.
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u001f\u007f-\u009f]/g, "").slice(0, maximum);
}

/** Hashes both values to a fixed-length digest before constant-time comparison. */
export function timingSafeCredentialMatch(
  candidate: string,
  configured: string,
): boolean {
  const left = createHash("sha256").update(candidate, "utf8").digest();
  const right = createHash("sha256").update(configured, "utf8").digest();
  return timingSafeEqual(left, right);
}

export function authenticateBearer(
  header: string | undefined,
  credentials: readonly ApiCredential[],
  now: Date,
): ApiCredential | undefined {
  const match = header === undefined ? undefined : TOKEN_PREFIX.exec(header);
  const candidate = match?.[1] ?? "";
  let selected: ApiCredential | undefined;
  for (const credential of credentials) {
    const equal = timingSafeCredentialMatch(candidate, credential.token);
    const active =
      credential.disabled !== true &&
      (credential.expiresAt === undefined ||
        Date.parse(credential.expiresAt) > now.getTime());
    if (equal && active) selected = credential;
  }
  return selected;
}

export interface LimitDecision {
  readonly allowed: boolean;
  readonly retryAfterSeconds: number;
  readonly shouldLogRejection: boolean;
}

/** Fixed-window limiter with bounded buckets and fail-closed behavior when full. */
export class BoundedFixedWindowLimiter {
  private readonly buckets = new Map<
    string,
    { start: number; count: number; blockedLogged: boolean }
  >();

  public constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly maximumEntries: number,
    private readonly now: () => number = Date.now,
  ) {
    if (
      ![limit, windowMs, maximumEntries].every(Number.isSafeInteger) ||
      limit < 1 ||
      windowMs < 1000 ||
      maximumEntries < 1
    )
      throw new Error("Rate limiter bounds are invalid.");
  }

  public consume(key: string): LimitDecision {
    const now = this.now();
    for (const [existingKey, bucket] of this.buckets) {
      if (now - bucket.start >= this.windowMs) this.buckets.delete(existingKey);
    }
    let bucket = this.buckets.get(key);
    if (!bucket) {
      if (this.buckets.size >= this.maximumEntries)
        return {
          allowed: false,
          retryAfterSeconds: Math.ceil(this.windowMs / 1000),
          shouldLogRejection: false,
        };
      bucket = { start: now, count: 0, blockedLogged: false };
      this.buckets.set(key, bucket);
    }
    if (bucket.count >= this.limit) {
      const shouldLogRejection = !bucket.blockedLogged;
      bucket.blockedLogged = true;
      return {
        allowed: false,
        retryAfterSeconds: Math.max(
          1,
          Math.ceil((bucket.start + this.windowMs - now) / 1000),
        ),
        shouldLogRejection,
      };
    }
    bucket.count += 1;
    return { allowed: true, retryAfterSeconds: 0, shouldLogRejection: false };
  }

  public get size(): number {
    return this.buckets.size;
  }
}

function validIp(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.length > 64 || isIP(trimmed) === 0) return undefined;
  return trimmed.toLowerCase();
}

/** Uses X-Forwarded-For only when the direct peer is explicitly trusted. */
export function clientAddress(
  remoteAddress: string | undefined,
  forwardedFor: string | undefined,
  trustedProxyAddresses: readonly string[],
): string {
  const remote = validIp(remoteAddress ?? "") ?? "unknown";
  if (!trustedProxyAddresses.includes(remote) || forwardedFor === undefined)
    return remote;
  if (forwardedFor.length > 256) return remote;
  const chain = forwardedFor.split(",").map(validIp);
  if (chain.length === 0 || chain.some((item) => item === undefined) || chain.length > 10)
    return remote;
  let candidate = remote;
  for (let index = chain.length - 1; index >= 0; index -= 1) {
    if (!trustedProxyAddresses.includes(candidate)) break;
    candidate = chain[index]!;
  }
  return candidate;
}
