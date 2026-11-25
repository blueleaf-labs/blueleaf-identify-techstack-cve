import type { IdentificationResult, IdentificationTarget } from "../domain/models.js";
import type { ApplicationConfiguration } from "../config/configuration.js";
import type { ProviderRegistry } from "./ports.js";

/** Input accepted by the shared application service, independent of CLI or HTTP transport. */
export interface IdentifyRequest {
  readonly target: IdentificationTarget;
}

/** Stable application boundary to be called by CLI and a future HTTP API adapter. */
export interface IdentificationService {
  identify(request: IdentifyRequest): Promise<IdentificationResult>;
}

/** Host-provided dependency bundle for constructing application services. */
export interface ApplicationDependencies {
  readonly configuration: ApplicationConfiguration;
  readonly providers: ProviderRegistry;
}
