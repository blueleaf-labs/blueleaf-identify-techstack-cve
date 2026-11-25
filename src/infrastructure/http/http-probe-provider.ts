import http, {
  type ClientRequest,
  type IncomingHttpHeaders,
  type IncomingMessage,
} from "node:http";
import https from "node:https";
import type { TLSSocket } from "node:tls";
import { performance } from "node:perf_hooks";
import { ApplicationError } from "../../domain/errors.js";
import {
  DEFAULT_APPLICATION_CONFIGURATION,
  type ApplicationConfiguration,
} from "../../config/configuration.js";
import type {
  HttpProvider,
  HttpRequest,
  HttpResponse,
  ProbeTiming,
  RedirectHop,
  TlsMetadata,
} from "../../application/ports.js";
import { SecureTargetResolver, type ResolvedTarget } from "./target-resolver.js";

interface HopResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly cookies: readonly string[];
  readonly body: Uint8Array;
  readonly responseReceivedAt: string;
  readonly remoteAddress?: string;
  readonly tls?: TlsMetadata;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const SENSITIVE_HEADERS = new Set(["authorization", "cookie", "proxy-authorization"]);

function normalizeHeaders(headers: IncomingHttpHeaders): {
  readonly headers: Readonly<Record<string, string>>;
  readonly cookies: readonly string[];
} {
  const normalized = Object.create(null) as Record<string, string>;
  const cookies: string[] = [];
  for (const [rawName, rawValue] of Object.entries(headers)) {
    if (rawValue === undefined) continue;
    const name = rawName.toLowerCase();
    if (name === "set-cookie") {
      cookies.push(...(Array.isArray(rawValue) ? rawValue : [rawValue]));
      continue;
    }
    normalized[name] = (Array.isArray(rawValue) ? rawValue.join(", ") : rawValue).trim();
  }
  return { headers: normalized, cookies };
}

function tlsMetadata(response: IncomingMessage): TlsMetadata | undefined {
  const socket = response.socket;
  if (!("encrypted" in socket) || !socket.encrypted) return undefined;
  const tlsSocket = socket as TLSSocket;
  const certificate = tlsSocket.getPeerCertificate();
  const cipher = tlsSocket.getCipher();
  const peerCertificate = {
    ...(certificate.subjectaltname ? { subjectAltName: certificate.subjectaltname } : {}),
    ...(certificate.fingerprint256 ? { fingerprint256: certificate.fingerprint256 } : {}),
    ...(certificate.valid_from ? { validFrom: certificate.valid_from } : {}),
    ...(certificate.valid_to ? { validTo: certificate.valid_to } : {}),
  };
  return {
    authorized: tlsSocket.authorized,
    ...(tlsSocket.getProtocol() ? { protocol: tlsSocket.getProtocol() as string } : {}),
    ...(cipher.name ? { cipher: cipher.name } : {}),
    ...(Object.keys(peerCertificate).length > 0 ? { peerCertificate } : {}),
  };
}

function errorFromNetworkFailure(error: unknown): ApplicationError {
  if (error instanceof ApplicationError) return error;
  const code =
    typeof error === "object" && error !== null && "code" in error
      ? String(error.code)
      : "";
  if (
    code.startsWith("ERR_TLS") ||
    code.startsWith("ERR_SSL") ||
    code.includes("CERT") ||
    code.includes("VERIFY") ||
    code.includes("SELF_SIGNED") ||
    code.startsWith("DEPTH_ZERO")
  ) {
    return new ApplicationError(
      "TLS_FAILURE",
      "TLS negotiation or certificate validation failed.",
      { cause: error },
    );
  }
  return new ApplicationError(
    "PROVIDER_FAILURE",
    "HTTP probe failed due to a network or protocol error.",
    { cause: error },
  );
}

function redirectHeaders(
  headers: Readonly<Record<string, string>>,
  from: URL,
  to: URL,
): Readonly<Record<string, string>> {
  if (from.origin === to.origin) return headers;
  return Object.fromEntries(
    Object.entries(headers).filter(
      ([name]) => !SENSITIVE_HEADERS.has(name.toLowerCase()),
    ),
  );
}

function requestHeaders(
  headers: Readonly<Record<string, string>> | undefined,
): Record<string, string> {
  const normalized = Object.create(null) as Record<string, string>;
  for (const [name, value] of Object.entries(headers ?? {})) {
    const lowerName = name.toLowerCase();
    if (["host", "connection", "proxy-authorization"].includes(lowerName)) continue;
    normalized[name] = value;
  }
  return normalized;
}

function isRedirect(status: number, headers: Readonly<Record<string, string>>): boolean {
  return REDIRECT_STATUSES.has(status) && headers["location"] !== undefined;
}

function parseContentLength(
  headers: Readonly<Record<string, string>>,
): number | undefined {
  const value = headers["content-length"];
  if (value === undefined || !/^\d+$/.test(value)) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : undefined;
}

/** Bounded HTTP/HTTPS transport with DNS pinning and redirect target revalidation. */
export class HttpProbeProvider implements HttpProvider {
  public constructor(
    private readonly configuration: ApplicationConfiguration,
    private readonly resolver: SecureTargetResolver = new SecureTargetResolver(),
    private readonly trustedCertificates: readonly string[] = [],
  ) {}

  public async request(input: HttpRequest): Promise<HttpResponse> {
    if (!Number.isFinite(input.timeoutMs) || input.timeoutMs <= 0) {
      throw new ApplicationError("INVALID_INPUT", "Request timeout must be positive.");
    }
    const timeoutMs = Math.min(input.timeoutMs, this.configuration.http.timeoutMs);
    const startedAt = new Date();
    const monotonicStart = performance.now();
    const deadline = monotonicStart + timeoutMs;
    if (input.signal?.aborted)
      throw new ApplicationError("CANCELLED", "HTTP probe was cancelled.");
    const initialUrl = input.url;
    let currentUrl = initialUrl;
    let currentHeaders = requestHeaders(input.headers);
    const redirectChain: RedirectHop[] = [];
    let finalHop: HopResponse | undefined;
    let finalResolved: ResolvedTarget | undefined;

    for (;;) {
      const resolved = await this.resolveWithinDeadline(
        currentUrl,
        deadline,
        input.signal,
      );
      finalResolved = resolved;
      const remainingMs = deadline - performance.now();
      if (remainingMs <= 0)
        throw new ApplicationError("TIMEOUT", "HTTP probe exceeded its time limit.");

      let hop: HopResponse;
      try {
        hop = await this.requestHop(
          resolved,
          input.method ?? "GET",
          currentHeaders,
          remainingMs,
          input.signal,
        );
      } catch (error: unknown) {
        throw errorFromNetworkFailure(error);
      }
      finalHop = hop;

      const location = hop.headers["location"];
      if (!isRedirect(hop.status, hop.headers) || location === undefined) break;
      if (
        redirectChain.length >=
        (this.configuration.http.redirectLimit ??
          DEFAULT_APPLICATION_CONFIGURATION.http.redirectLimit ??
          5)
      ) {
        throw new ApplicationError(
          "REDIRECT_LIMIT",
          "HTTP probe exceeded the configured redirect limit.",
        );
      }

      let redirectUrl: URL;
      try {
        redirectUrl = new URL(location, resolved.url);
      } catch (cause) {
        throw new ApplicationError("INVALID_INPUT", "Redirect target URL is malformed.", {
          cause,
        });
      }
      const validatedRedirect = await this.resolveWithinDeadline(
        redirectUrl,
        deadline,
        input.signal,
      );
      if (
        resolved.url.protocol === "https:" &&
        validatedRedirect.url.protocol === "http:"
      ) {
        throw new ApplicationError(
          "TARGET_REJECTED",
          "HTTPS-to-HTTP redirects are not allowed.",
        );
      }
      redirectChain.push({
        from: resolved.url.href,
        status: hop.status,
        to: validatedRedirect.url.href,
      });
      currentHeaders = redirectHeaders(
        currentHeaders,
        resolved.url,
        validatedRedirect.url,
      );
      currentUrl = validatedRedirect.url.href;
    }

    if (!finalHop || !finalResolved) {
      throw new ApplicationError(
        "INTERNAL_ERROR",
        "HTTP probe completed without a response.",
      );
    }

    const completedAt = new Date();
    const timing: ProbeTiming = {
      requestStartedAt: startedAt.toISOString(),
      responseReceivedAt: finalHop.responseReceivedAt,
      completedAt: completedAt.toISOString(),
      durationMs: Math.max(0, performance.now() - monotonicStart),
    };
    const contentType = finalHop.headers["content-type"];
    const contentLength = parseContentLength(finalHop.headers);
    return {
      status: finalHop.status,
      headers: finalHop.headers,
      body: finalHop.body,
      finalUrl: finalResolved.url.href,
      cookies: finalHop.cookies,
      ...(contentType !== undefined ? { contentType } : {}),
      ...(contentLength !== undefined ? { contentLength } : {}),
      redirectChain,
      timing,
      ...(finalHop.tls !== undefined ? { tls: finalHop.tls } : {}),
      ...(finalHop.remoteAddress !== undefined
        ? { remoteAddress: finalHop.remoteAddress }
        : {}),
      resolvedAddresses: finalResolved.addresses.map(({ address }) => address),
    };
  }

  private async resolveWithinDeadline(
    input: string | URL,
    deadline: number,
    signal?: AbortSignal,
  ): Promise<ResolvedTarget> {
    if (signal?.aborted)
      throw new ApplicationError("CANCELLED", "HTTP probe was cancelled.");
    const remainingMs = deadline - performance.now();
    if (remainingMs <= 0)
      throw new ApplicationError("TIMEOUT", "HTTP probe exceeded its time limit.");

    let timer: NodeJS.Timeout | undefined;
    let abortListener: (() => void) | undefined;
    try {
      const pending: Promise<ResolvedTarget>[] = [
        this.resolver.resolve(input, this.configuration),
      ];
      if (signal)
        pending.push(
          new Promise<never>((_resolve, reject) => {
            abortListener = (): void =>
              reject(new ApplicationError("CANCELLED", "HTTP probe was cancelled."));
            signal.addEventListener("abort", abortListener, { once: true });
          }),
        );
      return await Promise.race([
        ...pending,
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(
            () =>
              reject(
                new ApplicationError("TIMEOUT", "HTTP probe exceeded its time limit."),
              ),
            remainingMs,
          );
        }),
      ]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      if (signal && abortListener) signal.removeEventListener("abort", abortListener);
    }
  }

  private requestHop(
    target: ResolvedTarget,
    method: "GET" | "HEAD",
    headers: Readonly<Record<string, string>>,
    timeoutMs: number,
    signal?: AbortSignal,
  ): Promise<HopResponse> {
    const selected = target.addresses[0];
    if (!selected)
      return Promise.reject(
        new ApplicationError("PROVIDER_FAILURE", "Target has no usable address."),
      );

    return new Promise((resolve, reject) => {
      let settled = false;
      let request: ClientRequest | undefined;
      const onAbort = (): void => {
        const error = new ApplicationError("CANCELLED", "HTTP probe was cancelled.");
        finish(error);
        request?.destroy(error);
      };
      const finish = (error: unknown, result?: HopResponse): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        if (error !== undefined) reject(error);
        else if (result !== undefined) resolve(result);
        else
          reject(
            new ApplicationError("PROVIDER_FAILURE", "HTTP response was incomplete."),
          );
      };

      const timer = setTimeout(() => {
        const error = new ApplicationError(
          "TIMEOUT",
          "HTTP probe exceeded its time limit.",
        );
        finish(error);
        request?.destroy(error);
      }, timeoutMs);
      if (signal?.aborted) {
        onAbort();
        return;
      }
      signal?.addEventListener("abort", onAbort, { once: true });
      const pinnedLookup: NonNullable<http.RequestOptions["lookup"]> = (
        _hostname,
        lookupOptions,
        callback,
      ) => {
        if (lookupOptions.all)
          callback(null, [{ address: selected.address, family: selected.family }]);
        else callback(null, selected.address, selected.family);
      };
      const options = {
        protocol: target.url.protocol,
        hostname: target.hostname,
        ...(target.url.port ? { port: Number(target.url.port) } : {}),
        path: `${target.url.pathname}${target.url.search}`,
        method,
        headers: { ...headers },
        agent: false as const,
        lookup: pinnedLookup,
      };
      try {
        request =
          target.url.protocol === "https:"
            ? https.request(
                {
                  ...options,
                  ...(this.trustedCertificates.length > 0
                    ? { ca: [...this.trustedCertificates] }
                    : {}),
                },
                (response) => onResponse(response),
              )
            : http.request(options, (response) => onResponse(response));
      } catch (error: unknown) {
        finish(error);
        return;
      }

      const onResponse = (response: IncomingMessage): void => {
        const responseReceivedAt = new Date().toISOString();
        const status = response.statusCode;
        if (status === undefined) {
          finish(
            new ApplicationError(
              "PROVIDER_FAILURE",
              "HTTP response did not include a status code.",
            ),
          );
          request?.destroy();
          return;
        }
        const { headers: normalized, cookies } = normalizeHeaders(response.headers);
        const chunks: Buffer[] = [];
        let byteCount = 0;
        response.on("data", (chunk: Buffer | string) => {
          const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          byteCount += buffer.byteLength;
          if (byteCount > this.configuration.http.maxResponseBytes) {
            const error = new ApplicationError(
              "RESPONSE_TOO_LARGE",
              "HTTP response exceeded the configured byte limit.",
            );
            finish(error);
            response.destroy(error);
            request?.destroy(error);
            return;
          }
          chunks.push(buffer);
        });
        response.once("aborted", () =>
          finish(
            new ApplicationError("PROVIDER_FAILURE", "HTTP response ended unexpectedly."),
          ),
        );
        response.once("error", (error: Error) => finish(error));
        response.once("end", () => {
          const tls = tlsMetadata(response);
          finish(undefined, {
            status,
            headers: normalized,
            cookies,
            body: Buffer.concat(chunks),
            responseReceivedAt,
            ...(response.socket.remoteAddress
              ? { remoteAddress: response.socket.remoteAddress }
              : {}),
            ...(tls !== undefined ? { tls } : {}),
          });
        });
      };

      request.once("error", (error: Error) => finish(error));
      request.end();
    });
  }
}
