import { ApplicationError } from "../../domain/errors.js";
import type {
  AdvisoryCpeConfiguration,
  AdvisoryCpeMatch,
  AdvisoryCpeNode,
  AdvisoryReference,
  AdvisorySeverity,
  NormalizedAdvisory,
} from "../../domain/intelligence.js";

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function text(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
function validDate(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

function cpeMatch(value: unknown): AdvisoryCpeMatch {
  if (!record(value) || !text(value["criteria"]))
    throw new ApplicationError("PROVIDER_FAILURE", "NVD returned an invalid CPE match.");
  const result: {
    criteria: string;
    vulnerable?: boolean;
    matchCriteriaId?: string;
    versionStartIncluding?: string;
    versionStartExcluding?: string;
    versionEndIncluding?: string;
    versionEndExcluding?: string;
  } = { criteria: value["criteria"] as string };
  if (value["vulnerable"] !== undefined) {
    if (typeof value["vulnerable"] !== "boolean")
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "NVD returned an invalid vulnerable flag.",
      );
    result.vulnerable = value["vulnerable"];
  }
  const fields = [
    ["matchCriteriaId", "matchCriteriaId"],
    ["versionStartIncluding", "versionStartIncluding"],
    ["versionStartExcluding", "versionStartExcluding"],
    ["versionEndIncluding", "versionEndIncluding"],
    ["versionEndExcluding", "versionEndExcluding"],
  ] as const;
  for (const [source, target] of fields) {
    if (value[source] !== undefined) {
      if (typeof value[source] !== "string")
        throw new ApplicationError(
          "PROVIDER_FAILURE",
          "NVD returned an invalid CPE range field.",
        );
      result[target] = value[source] as string;
    }
  }
  return result;
}

function cpeNode(value: unknown): AdvisoryCpeNode {
  if (!record(value))
    throw new ApplicationError(
      "PROVIDER_FAILURE",
      "NVD returned an invalid CPE configuration node.",
    );
  const matches = value["cpeMatch"] ?? [];
  const nodes = value["nodes"] ?? [];
  if (!Array.isArray(matches) || !Array.isArray(nodes))
    throw new ApplicationError(
      "PROVIDER_FAILURE",
      "NVD returned invalid CPE configuration children.",
    );
  const result: {
    operator?: string;
    negate?: boolean;
    matches: AdvisoryCpeMatch[];
    nodes: AdvisoryCpeNode[];
  } = {
    matches: matches.map(cpeMatch),
    nodes: nodes.map(cpeNode),
  };
  if (value["operator"] !== undefined) {
    if (typeof value["operator"] !== "string")
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "NVD returned an invalid CPE operator.",
      );
    result.operator = value["operator"];
  }
  if (value["negate"] !== undefined) {
    if (typeof value["negate"] !== "boolean")
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "NVD returned an invalid CPE negate flag.",
      );
    result.negate = value["negate"];
  }
  return result;
}

function cpeConfiguration(value: unknown): AdvisoryCpeConfiguration {
  if (!record(value))
    throw new ApplicationError(
      "PROVIDER_FAILURE",
      "NVD returned an invalid CPE configuration.",
    );
  const nodes = value["nodes"] ?? [];
  if (!Array.isArray(nodes))
    throw new ApplicationError(
      "PROVIDER_FAILURE",
      "NVD returned invalid CPE configuration nodes.",
    );
  const result: { operator?: string; negate?: boolean; nodes: AdvisoryCpeNode[] } = {
    nodes: nodes.map(cpeNode),
  };
  if (value["operator"] !== undefined) {
    if (typeof value["operator"] !== "string")
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "NVD returned an invalid CPE operator.",
      );
    result.operator = value["operator"];
  }
  if (value["negate"] !== undefined) {
    if (typeof value["negate"] !== "boolean")
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "NVD returned an invalid CPE negate flag.",
      );
    result.negate = value["negate"];
  }
  return result;
}

function normalizeRecord(wrapper: unknown, retrievedAt: string): NormalizedAdvisory {
  if (!record(wrapper) || !record(wrapper["cve"]))
    throw new ApplicationError(
      "PROVIDER_FAILURE",
      "NVD returned a malformed CVE record.",
    );
  const cve = wrapper["cve"];
  const id = text(cve["id"]);
  if (!id || !/^CVE-\d{4}-\d{4,}$/.test(id))
    throw new ApplicationError(
      "PROVIDER_FAILURE",
      "NVD returned an invalid CVE identifier.",
    );
  for (const field of ["published", "lastModified"] as const)
    if (cve[field] !== undefined && !validDate(cve[field]))
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        `NVD returned an invalid ${field} timestamp.`,
      );

  const descriptions = cve["descriptions"] ?? [];
  if (!Array.isArray(descriptions))
    throw new ApplicationError("PROVIDER_FAILURE", "NVD returned invalid descriptions.");
  for (const description of descriptions)
    if (!record(description) || typeof description["value"] !== "string")
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "NVD returned an invalid description entry.",
      );
  const description =
    descriptions.find((item) => record(item) && item["lang"] === "en") ?? descriptions[0];

  const severity: AdvisorySeverity[] = [];
  const metrics = cve["metrics"] ?? {};
  if (!record(metrics))
    throw new ApplicationError("PROVIDER_FAILURE", "NVD returned invalid CVSS metrics.");
  for (const [metricKey, values] of Object.entries(metrics)) {
    if (!Array.isArray(values))
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "NVD returned an invalid CVSS metric list.",
      );
    for (const metric of values) {
      if (!record(metric) || !record(metric["cvssData"]))
        throw new ApplicationError(
          "PROVIDER_FAILURE",
          "NVD returned an invalid CVSS metric.",
        );
      const data = metric["cvssData"];
      const score = data["baseScore"];
      if (typeof score !== "number" && typeof score !== "string")
        throw new ApplicationError(
          "PROVIDER_FAILURE",
          "NVD returned a CVSS metric without a score.",
        );
      severity.push({
        type: text(data["version"]) ?? metricKey,
        score: String(score),
        ...(text(data["baseSeverity"])
          ? { severity: data["baseSeverity"] as string }
          : {}),
        ...(text(data["vectorString"]) ? { vector: data["vectorString"] as string } : {}),
      });
    }
  }

  const weaknesses = cve["weaknesses"] ?? [];
  if (!Array.isArray(weaknesses))
    throw new ApplicationError("PROVIDER_FAILURE", "NVD returned invalid weakness data.");
  const cweIds = new Set<string>();
  for (const weakness of weaknesses) {
    if (!record(weakness) || !Array.isArray(weakness["description"]))
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "NVD returned an invalid weakness record.",
      );
    for (const item of weakness["description"])
      if (
        record(item) &&
        typeof item["value"] === "string" &&
        /^CWE-\d+$/.test(item["value"])
      )
        cweIds.add(item["value"]);
  }

  const referencesValue = cve["references"] ?? [];
  if (!Array.isArray(referencesValue))
    throw new ApplicationError("PROVIDER_FAILURE", "NVD returned invalid references.");
  const references: AdvisoryReference[] = referencesValue.map((item) => {
    if (!record(item) || !text(item["url"]))
      throw new ApplicationError(
        "PROVIDER_FAILURE",
        "NVD returned an invalid reference.",
      );
    return {
      url: item["url"] as string,
      type: "REFERENCE",
      ...(Array.isArray(item["tags"])
        ? { tags: item["tags"].filter((tag): tag is string => typeof tag === "string") }
        : {}),
    };
  });

  const configurations = cve["configurations"] ?? [];
  if (!Array.isArray(configurations))
    throw new ApplicationError(
      "PROVIDER_FAILURE",
      "NVD returned invalid CPE configurations.",
    );
  const status = text(cve["vulnStatus"])?.toLowerCase();
  const recordStatus = status?.includes("reject")
    ? "rejected"
    : status?.includes("withdraw")
      ? "withdrawn"
      : status
        ? "active"
        : "unknown";
  const modifiedAt = text(cve["lastModified"]);
  const descriptionText = text(
    description && record(description) ? description["value"] : undefined,
  );
  return {
    id,
    aliases: [],
    ...(descriptionText ? { summary: descriptionText } : {}),
    ...(descriptionText ? { details: descriptionText } : {}),
    affectedPackages: [],
    severity,
    references,
    ...(validDate(cve["published"]) ? { publishedAt: cve["published"] } : {}),
    ...(modifiedAt ? { modifiedAt } : {}),
    recordStatus,
    cweIds: [...cweIds].sort(),
    cpeConfigurations: configurations.map(cpeConfiguration),
    provenance: {
      providerId: "nvd",
      authority: "primary",
      originalIdentifier: id,
      recordUrl: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`,
      retrievedAt,
      ...(modifiedAt ? { sourceModifiedAt: modifiedAt } : {}),
    },
  };
}

export interface NvdPage {
  readonly advisories: readonly NormalizedAdvisory[];
  readonly startIndex: number;
  readonly resultsPerPage: number;
  readonly totalResults: number;
}

/** NVD's API response envelope and CVE schema are isolated to this adapter. */
export function adaptNvdPage(input: unknown, retrievedAt: string): NvdPage {
  if (!record(input) || !Array.isArray(input["vulnerabilities"]))
    throw new ApplicationError(
      "PROVIDER_FAILURE",
      "NVD returned a malformed vulnerabilities response.",
    );
  const integers = [input["startIndex"], input["resultsPerPage"], input["totalResults"]];
  if (!integers.every((value) => Number.isSafeInteger(value) && (value as number) >= 0))
    throw new ApplicationError(
      "PROVIDER_FAILURE",
      "NVD returned invalid pagination metadata.",
    );
  return {
    advisories: input["vulnerabilities"].map((item) =>
      normalizeRecord(item, retrievedAt),
    ),
    startIndex: input["startIndex"] as number,
    resultsPerPage: input["resultsPerPage"] as number,
    totalResults: input["totalResults"] as number,
  };
}
