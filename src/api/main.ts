import { fileURLToPath } from "node:url";
import { loadRuntimeSettings, processEnvironmentSource } from "../config/environment.js";
import { createScanApplicationService } from "../infrastructure/composition-root.js";
import { createApiServer, listenApiServer, shutdownApiServer } from "./server.js";
import { stderrSecurityLogger } from "./security.js";
import { ApplicationError } from "../domain/errors.js";

export async function startApi(): Promise<void> {
  const settings = loadRuntimeSettings(processEnvironmentSource);
  const service = createScanApplicationService(settings);
  const server = createApiServer({
    service,
    credentials: settings.apiCredentials,
    host: settings.api.host,
    allowExternal: settings.api.allowExternal,
    publicHealth: settings.api.publicHealth,
    allowedOrigins: settings.api.allowedOrigins,
    trustedProxyAddresses: settings.api.trustedProxyAddresses,
    tlsTerminated: settings.api.tlsTerminated,
    maxRequestBytes: settings.api.maxRequestBytes,
    maxResponseBytes: settings.api.maxResponseBytes,
    scanTimeoutMs: settings.api.scanTimeoutMs,
    maxConcurrentScans: settings.api.maxConcurrentScans,
    maxConcurrentScansPerIdentity: settings.api.maxConcurrentScansPerIdentity,
    requestTimeoutMs: settings.api.requestTimeoutMs,
    rateLimit: settings.api.rateLimit,
    rateWindowMs: settings.api.rateWindowMs,
    maxRateLimitEntries: settings.api.maxRateLimitEntries,
    logger: stderrSecurityLogger,
  });
  await listenApiServer(server, settings.api.host, settings.api.port);
  process.stdout.write(`Blueleaf API listening on port ${settings.api.port}\n`);
  let shuttingDown = false;
  const close = (): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    void shutdownApiServer(server, settings.api.shutdownGraceMs, stderrSecurityLogger)
      .then(() => process.exit(0))
      .catch(() => process.exit(1));
  };
  process.once("SIGINT", close);
  process.once("SIGTERM", close);
}

const isEntrypoint =
  process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isEntrypoint) {
  try {
    await startApi();
  } catch (error: unknown) {
    const code = error instanceof ApplicationError ? error.code : "API_START_FAILURE";
    const message =
      error instanceof ApplicationError && code === "INVALID_CONFIGURATION"
        ? error instanceof Error
          ? error.message
          : "API configuration is invalid."
        : "API could not start; check its non-secret configuration and selected port.";
    process.stderr.write(`${code}: ${message}\n`);
    process.exitCode = 1;
  }
}
