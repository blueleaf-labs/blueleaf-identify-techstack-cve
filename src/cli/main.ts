import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { ApplicationError } from "../domain/errors.js";
import type { ScanResult } from "../domain/scan.js";
import type { ScanService } from "../application/scan/contracts.js";
import { loadRuntimeSettings, processEnvironmentSource } from "../config/environment.js";
import { createScanApplicationService } from "../infrastructure/composition-root.js";

export const CliExitCode = {
  SUCCESS: 0,
  PARTIAL: 1,
  INVALID_INPUT: 2,
  OPERATIONAL_FAILURE: 3,
} as const;

export interface CliIO {
  readonly stdout: (value: string) => void;
  readonly stderr: (value: string) => void;
}

export interface CliOptions {
  readonly service?: ScanService;
  readonly io?: CliIO;
  readonly readVersion?: () => Promise<string>;
}

const DEFAULT_IO: CliIO = {
  stdout: (value) => process.stdout.write(`${value}\n`),
  stderr: (value) => process.stderr.write(`${value}\n`),
};

const HELP = `blueleaf-identify-techstack-cve

Usage:
  blueleaf [--help] [--version]
  blueleaf scan <http-or-https-url> [--json]

Commands:
  scan URL       Run the bounded passive identification and assessment pipeline.
  --help, -h     Show this help.
  --version, -v  Show the package version.

Options:
  --json         Write the versioned ScanResult as JSON.

Exit codes:
  0  Scan completed with supported assessment coverage.
  1  Scan completed with unknown, partial, conflicting, or unavailable assessment data.
  2  Invalid request, usage, or target rejected by policy.
  3  Operational failure such as network, TLS, provider, or timeout error.

No crawl, port scan, fuzzing, brute force, or exploitation options are available. Scan only
systems you own or are authorized to assess.`;

function isHelp(args: readonly string[]): boolean {
  return args.length === 0 || args.includes("--help") || args.includes("-h");
}

function wantsJson(args: readonly string[]): boolean {
  return args.includes("--json");
}

function parseScan(args: readonly string[]): string {
  if (args[0] !== "scan")
    throw new ApplicationError(
      "INVALID_INPUT",
      `Unknown command: ${args[0] ?? ""}. Use --help for usage.`,
    );
  const values = args.slice(1).filter((item) => item !== "--json");
  const unknownOption = values.find((item) => item.startsWith("-"));
  if (unknownOption)
    throw new ApplicationError(
      "INVALID_INPUT",
      `Unsupported scan option: ${unknownOption}. Use --help for supported options.`,
    );
  if (values.length !== 1)
    throw new ApplicationError(
      "INVALID_INPUT",
      "Usage: blueleaf scan <http-or-https-url> [--json]",
    );
  return values[0]!;
}

function partialResult(result: ScanResult): boolean {
  const uncertainStates = new Set([
    "LIKELY_VULNERABLE",
    "VERSION_UNKNOWN",
    "TECHNOLOGY_UNKNOWN",
    "INSUFFICIENT_EVIDENCE",
    "INTELLIGENCE_UNAVAILABLE",
    "CONFLICTING_EVIDENCE",
  ]);
  return (
    result.intelligence.status === "PARTIAL_RESULTS" ||
    result.intelligence.status === "PROVIDER_UNAVAILABLE" ||
    result.intelligence.status === "INTELLIGENCE_UNAVAILABLE" ||
    result.assessment.intelligenceCoverage.status !== "complete" ||
    uncertainStates.has(result.assessment.state) ||
    result.assessment.technologyAssessments.some((item) =>
      uncertainStates.has(item.state),
    ) ||
    result.remediation.plans.some((item) =>
      ["MANUAL_REVIEW_REQUIRED", "REMEDIATION_UNAVAILABLE"].includes(item.state),
    )
  );
}

export function formatHumanResult(result: ScanResult): string {
  const lines = [
    `Target: ${result.target.url}`,
    `HTTP: ${result.probe.status} (${result.probe.contentType ?? "content type unavailable"}; ${result.probe.receivedBodyBytes} bytes)`,
    `Technologies: ${result.fingerprint.detections.length ? "" : "none detected"}`,
  ];
  for (const detection of result.fingerprint.detections) {
    const version = result.versions.assessments.find(
      (item) => item.technologyId === detection.technologyId,
    );
    lines.push(
      `  - ${detection.displayName}${version?.selectedUpstreamVersion ? ` ${version.selectedUpstreamVersion.normalized}` : " (version unknown)"} [detection ${detection.detectionConfidence.toFixed(2)}, version ${detection.versionConfidence.toFixed(2)}]`,
    );
  }
  lines.push(`Security assessment: ${result.assessment.state}`);
  lines.push(
    `Intelligence: ${result.intelligence.status} (${result.intelligence.sourceResults.map((item) => `${item.providerId}=${item.status}`).join(", ") || "no providers queried"})`,
  );
  lines.push("Remediation:");
  if (result.remediation.plans.length === 0)
    lines.push("  - no technology remediation plans");
  for (const plan of result.remediation.plans) {
    const target = plan.recommendedTargetVersion?.version;
    lines.push(
      `  - ${plan.displayName}: ${plan.state}${target ? `; target ${target}` : ""}`,
    );
    for (const advisory of plan.advisoryPlans)
      lines.push(
        `      ${advisory.advisoryId ?? "advisory"}: ${advisory.state} (priority ${advisory.priority.level})`,
      );
  }
  lines.push(
    "Note: assessment coverage is limited to the configured sources; unknown or incomplete results do not mean secure.",
  );
  return lines.join("\n");
}

async function packageVersion(): Promise<string> {
  const packageUrl = new URL("../../package.json", import.meta.url);
  const packageJson = JSON.parse(await readFile(packageUrl, "utf8")) as {
    version: string;
  };
  return packageJson.version;
}

function errorCode(error: unknown): string {
  return error instanceof ApplicationError ? error.code : "INTERNAL_ERROR";
}

function errorMessage(error: unknown): string {
  return error instanceof ApplicationError
    ? error.message
    : "Scan failed due to an internal error.";
}

export async function runCli(
  args: readonly string[],
  options: CliOptions = {},
): Promise<number> {
  const io = options.io ?? DEFAULT_IO;
  const json = wantsJson(args);
  if (isHelp(args)) {
    io.stdout(HELP);
    return CliExitCode.SUCCESS;
  }
  if (args.length === 1 && (args[0] === "--version" || args[0] === "-v")) {
    try {
      io.stdout(await (options.readVersion ?? packageVersion)());
      return CliExitCode.SUCCESS;
    } catch {
      io.stderr("Unable to read package version.");
      return CliExitCode.OPERATIONAL_FAILURE;
    }
  }
  try {
    const targetUrl = parseScan(args);
    const service =
      options.service ??
      createScanApplicationService(loadRuntimeSettings(processEnvironmentSource));
    const result = await service.scan({
      schemaVersion: "1.0",
      target: { url: targetUrl },
    });
    io.stdout(json ? JSON.stringify(result) : formatHumanResult(result));
    return partialResult(result) ? CliExitCode.PARTIAL : CliExitCode.SUCCESS;
  } catch (error: unknown) {
    const code = errorCode(error);
    const status =
      code === "INVALID_INPUT" || code === "TARGET_REJECTED"
        ? CliExitCode.INVALID_INPUT
        : CliExitCode.OPERATIONAL_FAILURE;
    const message = errorMessage(error);
    io.stderr(
      json ? JSON.stringify({ schemaVersion: "1.0", error: { code, message } }) : message,
    );
    return status;
  }
}

const isEntrypoint =
  process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isEntrypoint) process.exitCode = await runCli(process.argv.slice(2));
