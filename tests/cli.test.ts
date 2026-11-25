import { describe, expect, it } from "vitest";
import { runCli, CliExitCode } from "../src/cli/main.js";
import { createTestScanService } from "./helpers/scan-fixture.js";
import { validateScanResult } from "./helpers/schema-validator.js";

function io(): {
  readonly stdout: string[];
  readonly stderr: string[];
  readonly adapter: {
    readonly stdout: (value: string) => void;
    readonly stderr: (value: string) => void;
  };
} {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    stdout,
    stderr,
    adapter: {
      stdout: (value: string): void => {
        stdout.push(value);
      },
      stderr: (value: string): void => {
        stderr.push(value);
      },
    },
  };
}

describe("Blueleaf CLI", () => {
  it("prints usage and version", async () => {
    const streams = io();
    await expect(runCli(["--help"], { io: streams.adapter })).resolves.toBe(
      CliExitCode.SUCCESS,
    );
    expect(streams.stdout[0]).toContain("blueleaf scan <http-or-https-url> [--json]");
    expect(streams.stdout[0]).toContain("systems you own");
    await expect(
      runCli(["--version"], {
        io: streams.adapter,
        readVersion: async (): Promise<string> => "1.2.3",
      }),
    ).resolves.toBe(0);
    expect(streams.stdout[1]).toBe("1.2.3");
  });

  it("runs a valid scan and formats human-readable technology and assessment output", async () => {
    const streams = io();
    await expect(
      runCli(["scan", "https://example.test/path"], {
        service: createTestScanService(),
        io: streams.adapter,
      }),
    ).resolves.toBe(CliExitCode.PARTIAL);
    expect(streams.stdout[0]).toContain("Technologies:");
    expect(streams.stdout[0]).toContain("PHP 8.2.1");
    expect(streams.stdout[0]).toContain("Security assessment:");
    expect(streams.stdout[0]).toContain("MANUAL_REVIEW_REQUIRED");
    expect(streams.stdout[0]).not.toContain("response-secret");
    expect(streams.stdout[0]).not.toContain("cookie-secret");
  });

  it("emits machine-readable ScanResult JSON and partial exit codes", async () => {
    const streams = io();
    const code = await runCli(["scan", "https://example.test", "--json"], {
      service: createTestScanService({ packageMappings: [] }),
      io: streams.adapter,
    });
    expect(code).toBe(CliExitCode.PARTIAL);
    const result = JSON.parse(streams.stdout[0]!) as Record<string, unknown>;
    expect(validateScanResult(result), JSON.stringify(validateScanResult.errors)).toBe(
      true,
    );
    expect(result["schemaVersion"]).toBe("1.0");
    expect(result["assessment"]).toBeDefined();
    expect(result["remediation"]).toBeDefined();
    expect(streams.stdout[0]).not.toContain("response-secret-never-serialize");
  });

  it("returns actionable validation errors and invalid-input exit codes", async () => {
    const streams = io();
    await expect(
      runCli(["scan", "file:///etc/passwd"], {
        service: createTestScanService(),
        io: streams.adapter,
      }),
    ).resolves.toBe(CliExitCode.INVALID_INPUT);
    expect(streams.stderr[0]).toContain("absolute HTTP or HTTPS URL");
    await expect(
      runCli(["scan", "https://example.test", "--crawl"], {
        service: createTestScanService(),
        io: streams.adapter,
      }),
    ).resolves.toBe(CliExitCode.INVALID_INPUT);
    expect(streams.stderr[1]).toContain("Unsupported scan option");
  });

  it("returns operational failure without exposing stacks or internal details", async () => {
    const streams = io();
    const service = {
      scan: async (): Promise<never> => {
        throw new Error("C:\\internal\\path token=private");
      },
    };
    await expect(
      runCli(["scan", "https://example.test", "--json"], {
        service,
        io: streams.adapter,
      }),
    ).resolves.toBe(CliExitCode.OPERATIONAL_FAILURE);
    expect(streams.stderr[0]).toBe(
      JSON.stringify({
        schemaVersion: "1.0",
        error: {
          code: "INTERNAL_ERROR",
          message: "Scan failed due to an internal error.",
        },
      }),
    );
    expect(streams.stderr[0]).not.toContain("private");
  });
});
