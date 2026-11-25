import { ApplicationError } from "../../domain/errors.js";
import type {
  AdvisoryAffectedPackage,
  AdvisoryRangeEvent,
  AdvisoryVersionRange,
  NormalizedAdvisory,
} from "../../domain/intelligence.js";

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function string(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
function stringList(value: unknown): readonly string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && item.length > 0)
    : [];
}

export interface OsvQueryPage {
  readonly advisories: readonly NormalizedAdvisory[];
  readonly nextPageToken?: string;
}

export interface OsvBatchPageItem {
  readonly advisoryIds: readonly string[];
  readonly nextPageToken?: string;
  readonly complete: boolean;
}

export interface OsvBatchPage {
  readonly results: readonly OsvBatchPageItem[];
}

/** Normalize an OSV package-query envelope and all contained records. */
export function adaptOsvQueryPage(input: unknown, retrievedAt: string): OsvQueryPage {
  if (!record(input) || (input["vulns"] !== undefined && !Array.isArray(input["vulns"])))
    throw new ApplicationError(
      "PROVIDER_FAILURE",
      "OSV returned an invalid query response.",
    );
  if (
    input["next_page_token"] !== undefined &&
    typeof input["next_page_token"] !== "string"
  )
    throw new ApplicationError(
      "PROVIDER_FAILURE",
      "OSV returned an invalid query page token.",
    );
  const advisories = ((input["vulns"] ?? []) as unknown[]).map((item) =>
    adaptOsvAdvisory(item, retrievedAt),
  );
  return {
    advisories,
    ...(string(input["next_page_token"])
      ? { nextPageToken: input["next_page_token"] as string }
      : {}),
  };
}

/** Normalize OSV batch envelopes so no source response structure leaks to provider clients. */
export function adaptOsvBatchPage(input: unknown, expectedCount: number): OsvBatchPage {
  if (
    !record(input) ||
    !Array.isArray(input["results"]) ||
    input["results"].length !== expectedCount
  )
    throw new ApplicationError(
      "PROVIDER_FAILURE",
      "OSV returned an invalid batch response.",
    );
  const results: OsvBatchPageItem[] = [];
  for (const item of input["results"]) {
    if (
      !record(item) ||
      (item["vulns"] !== undefined && !Array.isArray(item["vulns"])) ||
      (item["next_page_token"] !== undefined &&
        typeof item["next_page_token"] !== "string")
    ) {
      results.push({ advisoryIds: [], complete: false });
      continue;
    }
    const advisoryIds: string[] = [];
    let complete = true;
    for (const advisory of (item["vulns"] ?? []) as unknown[]) {
      if (!record(advisory) || !string(advisory["id"])) {
        complete = false;
        continue;
      }
      advisoryIds.push(advisory["id"] as string);
    }
    results.push({
      advisoryIds,
      complete,
      ...(string(item["next_page_token"])
        ? { nextPageToken: item["next_page_token"] as string }
        : {}),
    });
  }
  return { results };
}

/** The OSV wire format is deliberately confined to this infrastructure adapter. */
export function adaptOsvAdvisory(
  input: unknown,
  retrievedAt: string,
): NormalizedAdvisory {
  if (!record(input) || !string(input["id"]))
    throw new ApplicationError(
      "PROVIDER_FAILURE",
      "OSV returned an invalid advisory record.",
    );
  for (const field of ["aliases", "affected", "severity", "references"] as const) {
    if (input[field] !== undefined && !Array.isArray(input[field]))
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        `OSV returned invalid ${field} data.`,
      );
  }
  if (!Array.isArray(input["affected"]))
    throw new ApplicationError(
      "PROVIDER_FAILURE",
      "OSV advisory is missing affected package data.",
    );
  for (const field of ["summary", "details"] as const) {
    if (input[field] !== undefined && typeof input[field] !== "string")
      throw new ApplicationError("PROVIDER_FAILURE", `OSV returned an invalid ${field}.`);
  }
  const id = input["id"] as string;
  const affectedPackages: AdvisoryAffectedPackage[] = [];
  for (const entry of (input["affected"] ?? []) as unknown[]) {
    if (
      !record(entry) ||
      !record(entry["package"]) ||
      !string(entry["package"]["name"]) ||
      !string(entry["package"]["ecosystem"])
    )
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "OSV returned an invalid affected package.",
      );
    const pkg = entry["package"];
    const ranges: AdvisoryVersionRange[] = [];
    if (entry["ranges"] !== undefined && !Array.isArray(entry["ranges"]))
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "OSV returned invalid version ranges.",
      );
    for (const range of (entry["ranges"] ?? []) as unknown[]) {
      if (
        !record(range) ||
        !["ECOSYSTEM", "SEMVER", "GIT"].includes(String(range["type"])) ||
        !Array.isArray(range["events"])
      )
        throw new ApplicationError(
          "PROVIDER_FAILURE",
          "OSV returned an invalid range entry.",
        );
      const events: AdvisoryRangeEvent[] = [];
      for (const event of range["events"]) {
        if (!record(event))
          throw new ApplicationError(
            "PROVIDER_FAILURE",
            "OSV returned an invalid range event.",
          );
        const normalized: {
          introduced?: string;
          fixed?: string;
          lastAffected?: string;
          limit?: string;
        } = {};
        for (const [from, to] of [
          ["introduced", "introduced"],
          ["fixed", "fixed"],
          ["last_affected", "lastAffected"],
          ["limit", "limit"],
        ] as const) {
          if (event[from] !== undefined) {
            if (typeof event[from] !== "string")
              throw new ApplicationError(
                "PROVIDER_FAILURE",
                "OSV returned an invalid range boundary.",
              );
            normalized[to] = event[from] as string;
          }
        }
        events.push(normalized);
      }
      ranges.push({
        type: range["type"] as string,
        events,
        ...(string(range["repo"]) ? { repository: range["repo"] as string } : {}),
      });
    }
    if (
      entry["versions"] !== undefined &&
      (!Array.isArray(entry["versions"]) ||
        !entry["versions"].every((value) => typeof value === "string"))
    )
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "OSV returned invalid explicit version data.",
      );
    const explicitVersions = stringList(entry["versions"]);
    const fixedVersions = [
      ...new Set(
        ranges.flatMap((range) =>
          range.events.flatMap((event) => (event.fixed ? [event.fixed] : [])),
        ),
      ),
    ].sort();
    affectedPackages.push({
      package: { name: pkg["name"] as string, ecosystem: pkg["ecosystem"] as string },
      ranges,
      explicitVersions,
      fixedVersions,
    });
  }
  const severity: { type: string; score: string }[] = [];
  for (const item of (input["severity"] ?? []) as unknown[]) {
    if (!record(item) || !string(item["type"]) || !string(item["score"]))
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "OSV returned an invalid severity record.",
      );
    severity.push({ type: item["type"] as string, score: item["score"] as string });
  }
  for (const entry of (input["affected"] ?? []) as unknown[]) {
    if (
      record(entry) &&
      record(entry["ecosystem_specific"]) &&
      entry["ecosystem_specific"]["severity"] !== undefined
    ) {
      const value = entry["ecosystem_specific"]["severity"];
      if (typeof value !== "string")
        throw new ApplicationError(
          "PROVIDER_FAILURE",
          "OSV returned invalid ecosystem severity data.",
        );
      severity.push({ type: "ECOSYSTEM_SPECIFIC", score: value });
    }
  }
  const references: { type?: string; url: string }[] = [];
  for (const item of (input["references"] ?? []) as unknown[]) {
    if (!record(item) || !string(item["url"]))
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "OSV returned an invalid reference.",
      );
    references.push({
      ...(string(item["type"]) ? { type: item["type"] as string } : {}),
      url: item["url"] as string,
    });
  }
  for (const field of ["published", "modified", "withdrawn"] as const)
    if (
      input[field] !== undefined &&
      (typeof input[field] !== "string" ||
        Number.isNaN(Date.parse(input[field] as string)))
    )
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        `OSV returned an invalid ${field} timestamp.`,
      );
  const modified = string(input["modified"]);
  return {
    id,
    aliases: [
      ...new Set(stringList(input["aliases"]).filter((alias) => alias !== id)),
    ].sort(),
    ...(string(input["summary"]) ? { summary: input["summary"] as string } : {}),
    ...(string(input["details"]) ? { details: input["details"] as string } : {}),
    affectedPackages,
    severity,
    references,
    ...(string(input["published"]) ? { publishedAt: input["published"] as string } : {}),
    ...(modified ? { modifiedAt: modified } : {}),
    ...(string(input["withdrawn"]) ? { withdrawnAt: input["withdrawn"] as string } : {}),
    provenance: {
      providerId: "osv",
      recordUrl: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`,
      retrievedAt,
      ...(modified ? { sourceModifiedAt: modified } : {}),
    },
  };
}
