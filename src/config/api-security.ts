import { createHash } from "node:crypto";

export interface ApiCredential {
  readonly identity: string;
  readonly token: string;
  readonly expiresAt?: string;
  readonly disabled?: boolean;
}

export interface SecurityEvent {
  readonly event: string;
  readonly timestamp: string;
  readonly requestId: string;
  readonly code?: string;
  readonly identity?: string;
}

export interface SecurityEventLogger {
  write(event: SecurityEvent): void;
}

const IDENTITY_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;

export function validateApiCredentials(value: readonly ApiCredential[]): void {
  if (value.length === 0 || value.length > 64)
    throw new Error("At least one and at most 64 API credentials must be configured.");
  const identities = new Set<string>();
  const tokenFingerprints = new Set<string>();
  for (const item of value) {
    if (!IDENTITY_PATTERN.test(item.identity) || identities.has(item.identity))
      throw new Error("API credential identities must be unique safe identifiers.");
    identities.add(item.identity);
    if (
      item.token.length < 32 ||
      item.token.length > 512 ||
      !/^[A-Za-z0-9._~+/-]+=*$/.test(item.token)
    )
      throw new Error("API credential tokens must be 32 to 512 characters.");
    const fingerprint = createHash("sha256").update(item.token, "utf8").digest("hex");
    if (tokenFingerprints.has(fingerprint))
      throw new Error("API credential tokens must be unique.");
    tokenFingerprints.add(fingerprint);
    if (item.expiresAt !== undefined && !Number.isFinite(Date.parse(item.expiresAt)))
      throw new Error("API credential expiresAt values must be valid timestamps.");
    if (item.disabled !== undefined && typeof item.disabled !== "boolean")
      throw new Error("API credential disabled values must be boolean.");
  }
  if (
    !value.some(
      (item) =>
        item.disabled !== true &&
        (!item.expiresAt || Date.parse(item.expiresAt) > Date.now()),
    )
  )
    throw new Error("At least one enabled, unexpired API credential is required.");
}
