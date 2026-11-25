import { randomUUID } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { isIP } from "node:net";
import { ApplicationError } from "../domain/errors.js";
import { validateApiCredentials } from "../config/api-security.js";
import type { ApiCredential, SecurityEventLogger } from "../config/api-security.js";
import type { ApiErrorEnvelope, ScanRequest } from "../domain/scan.js";
import type { ScanService } from "../application/scan/contracts.js";
import {
  authenticateBearer,
  BoundedFixedWindowLimiter,
  clientAddress,
  safeLogText,
  stderrSecurityLogger,
} from "./security.js";

export interface ApiServerOptions {
  readonly service: ScanService;
  readonly credentials: readonly ApiCredential[];
  readonly host?: string;
  readonly allowExternal?: boolean;
  readonly publicHealth?: boolean;
  readonly allowedOrigins?: readonly string[];
  readonly trustedProxyAddresses?: readonly string[];
  readonly tlsTerminated?: boolean;
  readonly maxRequestBytes?: number;
  readonly maxResponseBytes?: number;
  readonly scanTimeoutMs?: number;
  readonly maxConcurrentScans?: number;
  readonly maxConcurrentScansPerIdentity?: number;
  readonly requestTimeoutMs?: number;
  readonly rateLimit?: number;
  readonly rateWindowMs?: number;
  readonly maxRateLimitEntries?: number;
  readonly logger?: SecurityEventLogger;
  readonly now?: () => Date;
}

interface ApiLimits {
  readonly host: string;
  readonly allowExternal: boolean;
  readonly publicHealth: boolean;
  readonly allowedOrigins: readonly string[];
  readonly trustedProxyAddresses: readonly string[];
  readonly tlsTerminated: boolean;
  readonly credentials: readonly ApiCredential[];
  readonly maxRequestBytes: number;
  readonly maxResponseBytes: number;
  readonly scanTimeoutMs: number;
  readonly maxConcurrentScans: number;
  readonly maxConcurrentScansPerIdentity: number;
  readonly requestTimeoutMs: number;
  readonly rateLimit: number;
  readonly rateWindowMs: number;
  readonly maxRateLimitEntries: number;
  readonly logger: SecurityEventLogger;
  readonly now: () => Date;
}

class ApiFault extends Error {
  public constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly retryAfterSeconds?: number,
  ) {
    super(message);
  }
}

const lifecycle = new WeakMap<
  Server,
  { stop: () => void; active: Set<AbortController> }
>();

function checkOptions(options: ApiServerOptions): ApiLimits {
  const host = options.host ?? "127.0.0.1";
  const allowExternal = options.allowExternal ?? false;
  const loopback = ["localhost", "127.0.0.1", "::1"].includes(
    host.replace(/^\[|\]$/g, "").toLowerCase(),
  );
  if (!loopback && !allowExternal)
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "Non-loopback API binding requires explicit external binding permission.",
    );
  if (!loopback && options.tlsTerminated !== true)
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "Non-loopback API binding requires confirmed TLS termination at a trusted ingress.",
    );
  if (!loopback && (options.trustedProxyAddresses?.length ?? 0) === 0)
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "Non-loopback API binding requires an explicit trusted proxy address allowlist.",
    );
  const credentials = options.credentials ?? [];
  try {
    validateApiCredentials(credentials);
  } catch {
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "At least one valid enabled API credential is required.",
    );
  }
  const allowedOrigins = options.allowedOrigins ?? [];
  if (
    allowedOrigins.some((origin) => {
      try {
        const parsed = new URL(origin);
        return (
          !["http:", "https:"].includes(parsed.protocol) ||
          parsed.origin !== origin ||
          origin === "*"
        );
      } catch {
        return true;
      }
    })
  )
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "CORS origins must be exact HTTP(S) origins.",
    );
  const trustedProxyAddresses = options.trustedProxyAddresses ?? [];
  if (
    trustedProxyAddresses.length > 32 ||
    trustedProxyAddresses.some((address) => !isExactIp(address))
  )
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "Trusted proxy addresses must be exact IP addresses.",
    );
  const resolved = {
    host,
    allowExternal,
    publicHealth: options.publicHealth ?? false,
    allowedOrigins: [...new Set(allowedOrigins)],
    trustedProxyAddresses: [
      ...new Set(trustedProxyAddresses.map((item) => item.toLowerCase())),
    ],
    tlsTerminated: options.tlsTerminated ?? false,
    credentials,
    maxRequestBytes: options.maxRequestBytes ?? 8 * 1024,
    maxResponseBytes: options.maxResponseBytes ?? 12 * 1024 * 1024,
    scanTimeoutMs: options.scanTimeoutMs ?? 30_000,
    maxConcurrentScans: options.maxConcurrentScans ?? 2,
    maxConcurrentScansPerIdentity:
      options.maxConcurrentScansPerIdentity ??
      Math.min(2, options.maxConcurrentScans ?? 2),
    requestTimeoutMs: options.requestTimeoutMs ?? 15_000,
    rateLimit: options.rateLimit ?? 60,
    rateWindowMs: options.rateWindowMs ?? 60_000,
    maxRateLimitEntries: options.maxRateLimitEntries ?? 10_000,
    logger: options.logger ?? stderrSecurityLogger,
    now: options.now ?? ((): Date => new Date()),
  };
  if (
    !Number.isSafeInteger(resolved.maxRequestBytes) ||
    resolved.maxRequestBytes < 256 ||
    resolved.maxRequestBytes > 1024 * 1024 ||
    !Number.isSafeInteger(resolved.maxResponseBytes) ||
    resolved.maxResponseBytes < 1024 ||
    resolved.maxResponseBytes > 32 * 1024 * 1024 ||
    !Number.isSafeInteger(resolved.scanTimeoutMs) ||
    resolved.scanTimeoutMs < 100 ||
    resolved.scanTimeoutMs > 120_000 ||
    !Number.isSafeInteger(resolved.maxConcurrentScans) ||
    resolved.maxConcurrentScans < 1 ||
    resolved.maxConcurrentScans > 32 ||
    !Number.isSafeInteger(resolved.maxConcurrentScansPerIdentity) ||
    resolved.maxConcurrentScansPerIdentity < 1 ||
    resolved.maxConcurrentScansPerIdentity > resolved.maxConcurrentScans ||
    !Number.isSafeInteger(resolved.requestTimeoutMs) ||
    resolved.requestTimeoutMs < 1_000 ||
    resolved.requestTimeoutMs > 120_000 ||
    !Number.isSafeInteger(resolved.rateLimit) ||
    resolved.rateLimit < 1 ||
    resolved.rateLimit > 10_000 ||
    !Number.isSafeInteger(resolved.rateWindowMs) ||
    resolved.rateWindowMs < 1_000 ||
    resolved.rateWindowMs > 3_600_000 ||
    !Number.isSafeInteger(resolved.maxRateLimitEntries) ||
    resolved.maxRateLimitEntries < 100 ||
    resolved.maxRateLimitEntries > 100_000
  )
    throw new ApplicationError(
      "INVALID_CONFIGURATION",
      "API request, rate, response, or concurrency limits are invalid.",
    );
  return resolved;
}

// Kept local to avoid accepting malformed textual IP addresses in the proxy allowlist.
function isExactIp(value: string): boolean {
  return value.length <= 64 && isIP(value) !== 0;
}

function envelope(code: string, message: string): ApiErrorEnvelope {
  return { schemaVersion: "1.0", error: { code, message } };
}

function setHeaders(
  response: ServerResponse,
  requestId: string,
  limits: ApiLimits,
  origin?: string,
): void {
  response.setHeader("X-Request-ID", requestId);
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  );
  response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Vary", "Origin");
  if (limits.tlsTerminated && limits.allowExternal)
    response.setHeader("Strict-Transport-Security", "max-age=31536000");
  if (origin && limits.allowedOrigins.includes(origin)) {
    response.setHeader("Access-Control-Allow-Origin", origin);
  }
}

function sendJson(
  response: ServerResponse,
  status: number,
  value: unknown,
  requestId: string,
  limits: ApiLimits,
  extra: Readonly<Record<string, string>> = {},
): void {
  let body: string;
  try {
    body = JSON.stringify(value);
  } catch {
    body = JSON.stringify(
      envelope("INTERNAL_ERROR", "Request failed due to an internal error."),
    );
    status = 500;
  }
  if (Buffer.byteLength(body) > limits.maxResponseBytes) {
    body = JSON.stringify(
      envelope("RESPONSE_TOO_LARGE", "Response exceeds the configured size limit."),
    );
    status = 500;
  }
  setHeaders(
    response,
    requestId,
    limits,
    typeof extra["origin"] === "string" ? extra["origin"] : undefined,
  );
  for (const [name, value] of Object.entries(extra))
    if (name !== "origin") response.setHeader(name, value);
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Content-Length", Buffer.byteLength(body));
  if (!response.destroyed && !response.writableEnded) response.end(body);
}

function log(
  limits: ApiLimits,
  event: string,
  requestId: string,
  code?: string,
  identity?: string,
): void {
  try {
    limits.logger.write({
      event,
      timestamp: limits.now().toISOString(),
      requestId: safeLogText(requestId),
      ...(code ? { code: safeLogText(code) } : {}),
      ...(identity ? { identity: safeLogText(identity) } : {}),
    });
  } catch {
    /* logging failures must not fail requests */
  }
}

async function readBody(request: IncomingMessage, maximum: number): Promise<unknown> {
  const chunks: Buffer[] = [];
  let length = 0;
  let oversized = false;
  for await (const chunk of request) {
    const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    length += data.byteLength;
    if (length > maximum) oversized = true;
    else if (!oversized) chunks.push(data);
  }
  if (oversized)
    throw new ApiFault(
      413,
      "REQUEST_TOO_LARGE",
      "Request body exceeds the configured byte limit.",
    );
  if (length === 0)
    throw new ApiFault(
      400,
      "INVALID_REQUEST",
      "Request body must contain a JSON scan request.",
    );
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw new ApiFault(400, "INVALID_JSON", "Request body is not valid JSON.");
  }
}

function validateScanBody(value: unknown): ScanRequest {
  const record = (item: unknown): item is Record<string, unknown> =>
    typeof item === "object" && item !== null && !Array.isArray(item);
  if (
    !record(value) ||
    Object.keys(value).some((key) => !["schemaVersion", "target"].includes(key)) ||
    value["schemaVersion"] !== "1.0" ||
    !record(value["target"]) ||
    Object.keys(value["target"]).some((key) => key !== "url") ||
    typeof value["target"]["url"] !== "string"
  )
    throw new ApiFault(
      400,
      "INVALID_REQUEST",
      "Request must match ScanRequest schema 1.0.",
    );
  return value as unknown as ScanRequest;
}

function requestId(request: IncomingMessage): string {
  const provided = request.headers["x-request-id"];
  return typeof provided === "string" && /^[A-Za-z0-9._-]{1,64}$/.test(provided)
    ? provided
    : randomUUID();
}

function publicError(error: unknown): {
  status: number;
  code: string;
  message: string;
  retryAfter?: number;
} {
  if (error instanceof ApiFault)
    return {
      status: error.status,
      code: error.code,
      message: error.message,
      ...(error.retryAfterSeconds ? { retryAfter: error.retryAfterSeconds } : {}),
    };
  if (error instanceof ApplicationError) {
    if (error.code === "INVALID_INPUT")
      return {
        status: 400,
        code: "INVALID_REQUEST",
        message: "Scan request is invalid.",
      };
    if (error.code === "TARGET_REJECTED")
      return {
        status: 403,
        code: "TARGET_REJECTED",
        message: "Target was rejected by network policy.",
      };
    if (error.code === "TIMEOUT")
      return {
        status: 504,
        code: "SCAN_TIMEOUT",
        message: "Scan exceeded the configured duration limit.",
      };
    if (error.code === "CANCELLED")
      return { status: 499, code: "SCAN_CANCELLED", message: "Scan was cancelled." };
    if (
      [
        "REDIRECT_LIMIT",
        "RESPONSE_TOO_LARGE",
        "TLS_FAILURE",
        "PROVIDER_FAILURE",
        "RATE_LIMITED",
      ].includes(error.code)
    )
      return {
        status: 502,
        code: "SCAN_FAILED",
        message: "Scan could not be completed by a required provider.",
      };
  }
  return {
    status: 500,
    code: "INTERNAL_ERROR",
    message: "Request failed due to an internal error.",
  };
}

interface RequestContext {
  readonly requestId: string;
  readonly identity?: string;
  readonly origin?: string;
}

async function handleRequest(
  request: IncomingMessage,
  response: ServerResponse,
  service: ScanService,
  limits: ApiLimits,
  state: {
    active: number;
    closing: boolean;
    readonly controllers: Set<AbortController>;
    readonly perIdentity: Map<string, number>;
    readonly limiter: BoundedFixedWindowLimiter;
    readonly authLimiter: BoundedFixedWindowLimiter;
  },
): Promise<void> {
  const id = requestId(request);
  const origin = request.headers.origin;
  const context: RequestContext = {
    requestId: id,
    ...(typeof origin === "string" ? { origin } : {}),
  };
  const forwarded = request.headers["x-forwarded-for"];
  const directPeer = clientAddress(request.socket.remoteAddress, undefined, []);
  if (limits.allowExternal && !limits.trustedProxyAddresses.includes(directPeer)) {
    const decision = state.authLimiter.consume(`ip:${directPeer}`);
    if (decision.allowed) log(limits, "proxy_rejected", id, "UNTRUSTED_PROXY");
    sendJson(
      response,
      decision.allowed ? 403 : 429,
      envelope(
        decision.allowed ? "PROXY_REJECTED" : "RATE_LIMITED",
        decision.allowed
          ? "Request did not arrive through the trusted ingress."
          : "Too many rejected requests.",
      ),
      id,
      limits,
      {
        ...(!decision.allowed
          ? { "Retry-After": String(decision.retryAfterSeconds) }
          : {}),
        ...(origin ? { origin } : {}),
      },
    );
    return;
  }
  const remote = clientAddress(
    request.socket.remoteAddress,
    typeof forwarded === "string" ? forwarded : undefined,
    limits.trustedProxyAddresses,
  );
  if (state.closing) {
    sendJson(
      response,
      503,
      envelope("SHUTTING_DOWN", "Service is shutting down."),
      id,
      limits,
    );
    return;
  }
  if (typeof origin === "string" && !limits.allowedOrigins.includes(origin)) {
    const decision = state.authLimiter.consume(`ip:${remote}`);
    if (decision.allowed) log(limits, "origin_rejected", id, "ORIGIN_NOT_ALLOWED");
    sendJson(
      response,
      decision.allowed ? 403 : 429,
      envelope(
        decision.allowed ? "ORIGIN_REJECTED" : "RATE_LIMITED",
        decision.allowed ? "Origin is not allowed." : "Too many rejected requests.",
      ),
      id,
      limits,
      {
        ...(!decision.allowed
          ? { "Retry-After": String(decision.retryAfterSeconds) }
          : {}),
      },
    );
    return;
  }
  const path = new URL(request.url ?? "/", "http://localhost").pathname;
  if (request.method === "OPTIONS") {
    if (typeof origin !== "string" || !limits.allowedOrigins.includes(origin)) {
      sendJson(
        response,
        403,
        envelope("ORIGIN_REJECTED", "Origin is not allowed."),
        id,
        limits,
      );
      return;
    }
    setHeaders(response, id, limits, origin);
    response.statusCode = 204;
    response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    response.setHeader(
      "Access-Control-Allow-Headers",
      "Authorization, Content-Type, X-Request-ID",
    );
    response.setHeader("Access-Control-Max-Age", "600");
    response.end();
    return;
  }
  if (
    request.method === "GET" &&
    ["/health", "/ready"].includes(path) &&
    limits.publicHealth
  ) {
    sendJson(
      response,
      200,
      { schemaVersion: "1.0", status: path === "/health" ? "ok" : "ready" },
      id,
      limits,
      { ...(origin ? { origin } : {}) },
    );
    return;
  }
  const identity = authenticateBearer(
    request.headers.authorization,
    limits.credentials,
    limits.now(),
  );
  if (!identity) {
    const decision = state.authLimiter.consume(`ip:${remote}`);
    if (decision.allowed) log(limits, "authentication_failed", id, "UNAUTHORIZED");
    else if (decision.shouldLogRejection)
      log(limits, "rate_limit_rejected", id, "AUTH_FAILURE_RATE_LIMITED");
    sendJson(
      response,
      decision.allowed ? 401 : 429,
      envelope(
        decision.allowed ? "UNAUTHORIZED" : "RATE_LIMITED",
        decision.allowed
          ? "Bearer authentication is required."
          : "Too many authentication failures.",
      ),
      id,
      limits,
      {
        "WWW-Authenticate": 'Bearer realm="blueleaf"',
        ...(!decision.allowed
          ? { "Retry-After": String(decision.retryAfterSeconds) }
          : {}),
        ...(origin ? { origin } : {}),
      },
    );
    return;
  }
  const identified: RequestContext = { ...context, identity: identity.identity };
  if (request.method === "GET" && ["/health", "/ready"].includes(path)) {
    sendJson(
      response,
      200,
      { schemaVersion: "1.0", status: path === "/health" ? "ok" : "ready" },
      id,
      limits,
      { ...(origin ? { origin } : {}) },
    );
    return;
  }
  const knownPath = ["/health", "/ready", "/v1/scans"].includes(path);
  const expectedMethod = path === "/v1/scans" ? "POST" : "GET";
  if (!knownPath || request.method !== expectedMethod) {
    const methodMismatch = knownPath;
    if (methodMismatch)
      log(limits, "invalid_request", id, "METHOD_NOT_ALLOWED", identity.identity);
    sendJson(
      response,
      methodMismatch ? 405 : 404,
      envelope(
        methodMismatch ? "METHOD_NOT_ALLOWED" : "NOT_FOUND",
        methodMismatch
          ? "HTTP method is not allowed for this route."
          : "Route not found.",
      ),
      id,
      limits,
      {
        ...(methodMismatch ? { Allow: `${expectedMethod}, OPTIONS` } : {}),
        ...(origin ? { origin } : {}),
      },
    );
    return;
  }
  const quota = state.limiter.consume(`identity:${identity.identity}`);
  if (!quota.allowed) {
    if (quota.shouldLogRejection)
      log(limits, "rate_limit_rejected", id, "RATE_LIMITED", identity.identity);
    sendJson(
      response,
      429,
      envelope("RATE_LIMITED", "Scan request rate limit exceeded."),
      id,
      limits,
      { "Retry-After": String(quota.retryAfterSeconds), ...(origin ? { origin } : {}) },
    );
    return;
  }
  if (
    request.headers["content-type"]?.split(";")[0]?.trim().toLowerCase() !==
    "application/json"
  ) {
    log(limits, "invalid_request", id, "UNSUPPORTED_MEDIA_TYPE", identity.identity);
    sendJson(
      response,
      415,
      envelope("UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json."),
      id,
      limits,
      { ...(origin ? { origin } : {}) },
    );
    return;
  }
  const declaredLength = request.headers["content-length"];
  if (
    typeof declaredLength === "string" &&
    /^\d+$/.test(declaredLength) &&
    Number(declaredLength) > limits.maxRequestBytes
  ) {
    log(limits, "invalid_request", id, "REQUEST_TOO_LARGE", identity.identity);
    sendJson(
      response,
      413,
      envelope("REQUEST_TOO_LARGE", "Request body exceeds the configured byte limit."),
      id,
      limits,
      { Connection: "close", ...(origin ? { origin } : {}) },
    );
    request.resume();
    return;
  }
  let scanRequest: ScanRequest;
  try {
    scanRequest = validateScanBody(await readBody(request, limits.maxRequestBytes));
  } catch (error: unknown) {
    const result = publicError(error);
    log(limits, "invalid_request", id, result.code, identity.identity);
    sendJson(response, result.status, envelope(result.code, result.message), id, limits, {
      ...(result.status === 413 ? { Connection: "close" } : {}),
      ...(origin ? { origin } : {}),
    });
    return;
  }
  if (state.closing) {
    sendJson(
      response,
      503,
      envelope("SHUTTING_DOWN", "Service is shutting down."),
      id,
      limits,
    );
    return;
  }
  // Body parsing is asynchronous. Recheck quotas now, immediately before reserving
  // capacity, so concurrent requests cannot all pass using the same stale count.
  const count = state.perIdentity.get(identity.identity) ?? 0;
  if (
    count >= limits.maxConcurrentScansPerIdentity ||
    state.active >= limits.maxConcurrentScans
  ) {
    const perIdentityLimit = count >= limits.maxConcurrentScansPerIdentity;
    log(
      limits,
      "concurrency_rejected",
      id,
      perIdentityLimit ? "IDENTITY_CONCURRENCY_LIMIT" : "GLOBAL_CONCURRENCY_LIMIT",
      identity.identity,
    );
    sendJson(
      response,
      perIdentityLimit ? 429 : 503,
      envelope("CONCURRENCY_LIMIT", "Scan concurrency limit reached."),
      id,
      limits,
      { "Retry-After": "1", ...(origin ? { origin } : {}) },
    );
    return;
  }
  const controller = new AbortController();
  state.controllers.add(controller);
  state.active += 1;
  state.perIdentity.set(identity.identity, count + 1);
  let released = false;
  const release = (): void => {
    if (released) return;
    released = true;
    state.controllers.delete(controller);
    state.active = Math.max(0, state.active - 1);
    const current = state.perIdentity.get(identity.identity) ?? 1;
    if (current <= 1) state.perIdentity.delete(identity.identity);
    else state.perIdentity.set(identity.identity, current - 1);
  };
  const scan = Promise.resolve().then(() => service.scan(scanRequest, controller.signal));
  void scan.finally(release).catch(() => undefined);
  let clientDisconnected = false;
  const onClose = (): void => {
    if (!response.writableEnded && !controller.signal.aborted) {
      clientDisconnected = true;
      controller.abort();
      log(limits, "scan_cancelled", id, "CLIENT_DISCONNECTED", identity.identity);
    }
  };
  response.once("close", onClose);
  let timer: NodeJS.Timeout | undefined;
  try {
    const result = await Promise.race([
      scan,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(
            new ApiFault(
              504,
              "SCAN_TIMEOUT",
              "Scan exceeded the configured duration limit.",
            ),
          );
        }, limits.scanTimeoutMs);
      }),
    ]);
    sendJson(response, 200, result, id, limits, { ...(origin ? { origin } : {}) });
  } catch (error: unknown) {
    if (clientDisconnected) return;
    const result = publicError(error);
    if (result.code === "TARGET_REJECTED")
      log(limits, "target_rejected", id, result.code, identified.identity);
    else if (result.code !== "SCAN_CANCELLED")
      log(limits, "scan_failed", id, result.code, identified.identity);
    sendJson(response, result.status, envelope(result.code, result.message), id, limits, {
      ...(result.retryAfter ? { "Retry-After": String(result.retryAfter) } : {}),
      ...(origin ? { origin } : {}),
    });
  } finally {
    if (timer) clearTimeout(timer);
    response.off("close", onClose);
    if (!released && controller.signal.aborted && !clientDisconnected)
      log(limits, "scan_cancel_requested", id, "ABORTED", identity.identity);
  }
}

export function createApiServer(options: ApiServerOptions): Server {
  const limits = checkOptions(options);
  const state = {
    active: 0,
    closing: false,
    controllers: new Set<AbortController>(),
    perIdentity: new Map<string, number>(),
    limiter: new BoundedFixedWindowLimiter(
      limits.rateLimit,
      options.rateWindowMs ?? 60_000,
      limits.maxRateLimitEntries,
    ),
    authLimiter: new BoundedFixedWindowLimiter(
      10,
      60_000,
      Math.min(limits.maxRateLimitEntries, 10_000),
    ),
  };
  const server = createServer((request, response) => {
    void handleRequest(request, response, options.service, limits, state).catch(
      (error: unknown) => {
        const id = requestId(request);
        log(
          limits,
          "request_failed",
          id,
          error instanceof ApplicationError ? error.code : "INTERNAL_ERROR",
        );
        if (!response.headersSent)
          sendJson(
            response,
            500,
            envelope("INTERNAL_ERROR", "Request failed due to an internal error."),
            id,
            limits,
          );
        else if (!response.writableEnded) response.end();
      },
    );
  });
  server.requestTimeout = limits.requestTimeoutMs;
  server.headersTimeout = Math.min(10_000, limits.requestTimeoutMs);
  server.keepAliveTimeout = 5_000;
  lifecycle.set(server, {
    stop: () => {
      state.closing = true;
      for (const controller of state.controllers) controller.abort();
    },
    active: state.controllers,
  });
  return server;
}

export function shutdownApiServer(
  server: Server,
  graceMs = 10_000,
  logger: SecurityEventLogger = stderrSecurityLogger,
): Promise<void> {
  const state = lifecycle.get(server);
  state?.stop();
  try {
    logger.write({
      event: "shutdown_started",
      timestamp: new Date().toISOString(),
      requestId: randomUUID(),
    });
  } catch {
    /* best effort audit */
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    };
    const timer = setTimeout(() => {
      server.closeAllConnections();
      finish();
    }, graceMs);
    server.close((error) => finish(error));
    server.closeIdleConnections();
  });
}

export function listenApiServer(
  server: Server,
  host: string,
  port: number,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (error: Error): void => reject(error);
    server.once("error", onError);
    server.listen(port, host, () => {
      server.off("error", onError);
      resolve();
    });
  });
}
