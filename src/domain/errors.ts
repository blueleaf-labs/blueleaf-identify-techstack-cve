export type ErrorCode =
  | "INVALID_CONFIGURATION"
  | "INVALID_INPUT"
  | "PROVIDER_FAILURE"
  | "RATE_LIMITED"
  | "TIMEOUT"
  | "CANCELLED"
  | "TARGET_REJECTED"
  | "REDIRECT_LIMIT"
  | "RESPONSE_TOO_LARGE"
  | "TLS_FAILURE"
  | "UNSUPPORTED_OPERATION"
  | "NOT_FOUND"
  | "INTERNAL_ERROR";

/** Stable error shape for transport adapters; details must not contain secrets. */
export class ApplicationError extends Error {
  public constructor(
    public readonly code: ErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "ApplicationError";
  }
}

export function isApplicationError(error: unknown): error is ApplicationError {
  return error instanceof ApplicationError;
}
