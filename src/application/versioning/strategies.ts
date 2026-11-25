import { ApplicationError } from "../../domain/errors.js";
import type {
  ParsedUpstreamVersion,
  VersionComponents,
  VersionParseResult,
  VersionParsingStatus,
} from "../../domain/versions.js";

export interface VersionStrategy {
  readonly id: string;
  /** Use `*` only for the generic fallback strategy. */
  readonly technologyIds: readonly string[];
  parse(rawValue: string): VersionParseResult;
  compare(
    left: ParsedUpstreamVersion,
    right: ParsedUpstreamVersion,
  ): -1 | 0 | 1 | undefined;
}

const SEMVER_PATTERN =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/;
const INCOMPLETE_PATTERN = /^(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?$/;
const PACKAGE_VERSION_PATTERN =
  /^(?:(\d+):)?(.+)-(\d+(?:\+deb\d+u\d+|~deb\d+u\d+|ubuntu\d+(?:\.\d+)*|el\d+(?:_\d+)?|fc\d+|\.(?:el\d+(?:_\d+)?|fc\d+)|~(?:bookworm|bullseye|jammy|focal|noble)))$/i;
const KNOWN_UNSUPPORTED_VENDOR_SUFFIX =
  /-(?:ubuntu|debian|deb|alpine|rhel|centos|amazon|amzn|suse|opensuse|bookworm|bullseye|jammy|focal|noble)(?:[-+~._]?[0-9A-Za-z._+-]*)?$/i;
const VENDOR_LIKE_BUILD_SUFFIX =
  /\+(?:deb\d|ubuntu\d|alpine\d|rhel|centos|amazon|amzn|suse|opensuse|el\d|fc\d)/i;
const PRERELEASE_PATTERN = /^(?:alpha|beta|rc|dev|preview)(?:[.-]?[0-9A-Za-z.-]*)?$/i;

function parseResult(
  status: VersionParsingStatus,
  reason: string,
  options: Partial<VersionParseResult> = {},
): VersionParseResult {
  return { status, reason, ...options };
}

function validIdentifiers(
  value: string | undefined,
  prerelease: boolean,
): readonly string[] | undefined {
  if (value === undefined) return undefined;
  const identifiers = value.split(".");
  if (
    identifiers.some(
      (identifier) =>
        identifier.length === 0 ||
        !/^[0-9A-Za-z-]+$/.test(identifier) ||
        (prerelease &&
          /^\d+$/.test(identifier) &&
          identifier.length > 1 &&
          identifier.startsWith("0")),
    )
  ) {
    return undefined;
  }
  return identifiers;
}

function parseStrictSemVer(value: string): ParsedUpstreamVersion | undefined {
  const normalizedInput = value.startsWith("v") ? value.slice(1) : value;
  const match = SEMVER_PATTERN.exec(normalizedInput);
  if (!match) return undefined;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if (![major, minor, patch].every(Number.isSafeInteger)) return undefined;
  const prerelease = validIdentifiers(match[4], true);
  const build = validIdentifiers(match[5], false);
  if (
    (match[4] !== undefined && prerelease === undefined) ||
    (match[5] !== undefined && build === undefined)
  ) {
    return undefined;
  }
  const normalized = `${major}.${minor}.${patch}${prerelease ? `-${prerelease.join(".")}` : ""}${build ? `+${build.join(".")}` : ""}`;
  return {
    scheme: "semver",
    normalized,
    components: { major, minor, patch },
    ...(prerelease !== undefined ? { prerelease } : {}),
    ...(build !== undefined ? { build } : {}),
  };
}

function compareNumericIdentifiers(left: string, right: string): number {
  const normalizedLeft = left.replace(/^0+(?=\d)/, "");
  const normalizedRight = right.replace(/^0+(?=\d)/, "");
  if (normalizedLeft.length !== normalizedRight.length) {
    return normalizedLeft.length < normalizedRight.length ? -1 : 1;
  }
  return normalizedLeft < normalizedRight ? -1 : normalizedLeft > normalizedRight ? 1 : 0;
}

function compareIdentifier(left: string | number, right: string | number): number {
  const leftText = String(left);
  const rightText = String(right);
  const leftNumeric = /^\d+$/.test(leftText);
  const rightNumeric = /^\d+$/.test(rightText);
  if (leftNumeric && rightNumeric) return compareNumericIdentifiers(leftText, rightText);
  if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
  return leftText < rightText ? -1 : leftText > rightText ? 1 : 0;
}

export function compareSemVer(
  left: ParsedUpstreamVersion,
  right: ParsedUpstreamVersion,
): -1 | 0 | 1 | undefined {
  if (
    left.scheme !== "semver" ||
    right.scheme !== "semver" ||
    left.components.minor === undefined ||
    left.components.patch === undefined ||
    right.components.minor === undefined ||
    right.components.patch === undefined
  ) {
    return undefined;
  }
  for (const component of ["major", "minor", "patch"] as const) {
    const leftValue = left.components[component];
    const rightValue = right.components[component];
    if (leftValue === undefined || rightValue === undefined) return undefined;
    if (leftValue !== rightValue) return leftValue < rightValue ? -1 : 1;
  }
  const leftPre = left.prerelease;
  const rightPre = right.prerelease;
  if (leftPre === undefined && rightPre === undefined) return 0;
  if (leftPre === undefined) return 1;
  if (rightPre === undefined) return -1;
  const sharedLength = Math.min(leftPre.length, rightPre.length);
  for (let index = 0; index < sharedLength; index += 1) {
    const leftIdentifier = leftPre[index];
    const rightIdentifier = rightPre[index];
    if (leftIdentifier === undefined || rightIdentifier === undefined) continue;
    const comparison = compareIdentifier(leftIdentifier, rightIdentifier);
    if (comparison !== 0) return comparison < 0 ? -1 : 1;
  }
  if (leftPre.length === rightPre.length) return 0;
  return leftPre.length < rightPre.length ? -1 : 1;
}

function parseIncomplete(value: string): VersionComponents | undefined {
  const match = INCOMPLETE_PATTERN.exec(value.startsWith("v") ? value.slice(1) : value);
  if (!match) return undefined;
  const major = Number(match[1]);
  const minor = match[2] === undefined ? undefined : Number(match[2]);
  if (
    !Number.isSafeInteger(major) ||
    (minor !== undefined && !Number.isSafeInteger(minor))
  ) {
    return undefined;
  }
  return { major, ...(minor !== undefined ? { minor } : {}) };
}

function parsePackageVersion(rawValue: string): VersionParseResult | undefined {
  const match = PACKAGE_VERSION_PATTERN.exec(rawValue);
  if (!match) return undefined;
  const upstreamValue = match[2];
  const revision = match[3];
  if (upstreamValue === undefined || revision === undefined) return undefined;
  const suffix = revision.toLowerCase();
  const distribution =
    suffix.includes("deb") || suffix.includes("bookworm") || suffix.includes("bullseye")
      ? "debian"
      : suffix.includes("ubuntu") ||
          suffix.includes("jammy") ||
          suffix.includes("focal") ||
          suffix.includes("noble")
        ? "ubuntu"
        : suffix.includes("el")
          ? "rhel-family"
          : suffix.includes("fc")
            ? "fedora"
            : undefined;
  const epoch = match[1] === undefined ? undefined : Number(match[1]);
  const packageDetails = {
    rawValue,
    upstreamValue,
    ...(distribution !== undefined ? { distribution } : {}),
    ...(epoch !== undefined && Number.isSafeInteger(epoch) ? { epoch } : {}),
    revision,
  };
  const upstream = parseStrictSemVer(upstreamValue);
  if (!upstream) {
    return parseResult(
      "ambiguous",
      "A distribution package suffix was recognized, but its upstream component is not valid SemVer.",
      { vendorPackageVersion: packageDetails },
    );
  }
  return parseResult(
    "parsed",
    "The upstream version and recognized distribution package revision were parsed separately.",
    {
      parsedUpstreamVersion: upstream,
      vendorPackageVersion: packageDetails,
    },
  );
}

class SemVerStrategy implements VersionStrategy {
  public readonly id: string = "semver";
  public readonly technologyIds: readonly string[] = ["*"];

  public parse(rawValue: string): VersionParseResult {
    const value = rawValue.trim();
    if (!value) return parseResult("unknown", "No version value was observed.");
    if (value.length > 128)
      return parseResult(
        "unsupported",
        "The version value exceeds the supported parsing limit.",
      );
    const packageVersion = parsePackageVersion(value);
    if (packageVersion) return packageVersion;
    if (/^\d+\.\d+\.\d+-\d+$/.test(value)) {
      return parseResult(
        "ambiguous",
        "A numeric package revision could be either a SemVer prerelease or vendor revision; it is not discarded.",
      );
    }
    if (KNOWN_UNSUPPORTED_VENDOR_SUFFIX.test(value)) {
      return parseResult(
        "unsupported",
        "A vendor or distribution suffix was observed but is not recognized by the generic strategy.",
      );
    }
    const parsed = parseStrictSemVer(value);
    if (parsed) {
      if (VENDOR_LIKE_BUILD_SUFFIX.test(value)) {
        return parseResult(
          "ambiguous",
          "A vendor-like build suffix is retained but cannot be distinguished safely from SemVer build metadata.",
        );
      }
      return parseResult("parsed", "The value is a complete semantic version.", {
        parsedUpstreamVersion: parsed,
      });
    }
    const partial = parseIncomplete(value);
    if (partial) {
      return parseResult(
        "incomplete",
        "The version has missing minor or patch components and cannot be compared safely.",
        { partialUpstreamComponents: partial },
      );
    }
    if (/^v?\d+(?:\.\d+){2,}/i.test(value)) {
      return parseResult(
        "malformed",
        "The value resembles SemVer but violates its component or identifier syntax.",
      );
    }
    return parseResult(
      "unsupported",
      "The value is not a supported semantic version format.",
    );
  }

  public compare(
    left: ParsedUpstreamVersion,
    right: ParsedUpstreamVersion,
  ): -1 | 0 | 1 | undefined {
    return compareSemVer(left, right);
  }
}

interface ProductStrategyOptions {
  readonly compactPhpPrerelease?: boolean;
  readonly normalizePrereleaseMarkers?: boolean;
}

class ProductSemVerStrategy extends SemVerStrategy {
  public constructor(
    public override readonly id: string,
    public override readonly technologyIds: readonly string[],
    private readonly options: ProductStrategyOptions = {},
  ) {
    super();
  }

  public override parse(rawValue: string): VersionParseResult {
    const value = rawValue.trim();
    if (!value) return parseResult("unknown", "No version value was observed.");
    if (value.length > 128)
      return parseResult(
        "unsupported",
        "The version value exceeds the supported parsing limit.",
      );
    const packageVersion = parsePackageVersion(value);
    if (packageVersion) return packageVersion;
    if (/^\d+\.\d+\.\d+-\d+$/.test(value)) {
      return parseResult(
        "ambiguous",
        "A numeric package revision could be either a prerelease or vendor revision; it is not discarded.",
      );
    }
    if (KNOWN_UNSUPPORTED_VENDOR_SUFFIX.test(value)) {
      return parseResult(
        "unsupported",
        "A vendor or distribution suffix was observed but is not recognized by this strategy.",
      );
    }
    let strategyValue = value;
    if (
      this.options.compactPhpPrerelease === true &&
      /^(\d+\.\d+\.\d+)(RC|alpha|beta)(\d+)$/i.test(value)
    ) {
      strategyValue = value.replace(/^(\d+\.\d+\.\d+)(RC|alpha|beta)(\d+)$/i, "$1-$2$3");
    }
    const parsed = parseStrictSemVer(strategyValue);
    if (parsed) {
      if (VENDOR_LIKE_BUILD_SUFFIX.test(value)) {
        return parseResult(
          "ambiguous",
          "A vendor-like build suffix is retained but cannot be distinguished safely from an upstream SemVer build identifier.",
        );
      }
      if (
        parsed.prerelease !== undefined &&
        !PRERELEASE_PATTERN.test(parsed.prerelease.join("."))
      ) {
        return parseResult(
          "ambiguous",
          "The hyphenated suffix is not a recognized prerelease marker and may be package-specific.",
        );
      }
      const normalized =
        this.options.normalizePrereleaseMarkers === true &&
        parsed.prerelease !== undefined
          ? parsed.normalized.replace(
              /-(alpha|beta|rc|dev|preview)/i,
              (_, marker: string) => `-${marker.toLowerCase()}`,
            )
          : parsed.normalized;
      return parseResult(
        "parsed",
        `Parsed with the ${this.id} ecosystem strategy using upstream SemVer syntax.`,
        {
          parsedUpstreamVersion: { ...parsed, normalized },
        },
      );
    }
    const partial = parseIncomplete(value);
    if (partial) {
      return parseResult(
        "incomplete",
        "The version has missing minor or patch components and cannot be compared safely.",
        { partialUpstreamComponents: partial },
      );
    }
    if (/^v?\d+(?:\.\d+){2,}/i.test(value)) {
      return parseResult(
        "malformed",
        "The value resembles a release version but violates supported component or identifier syntax.",
      );
    }
    return parseResult(
      "unsupported",
      `The ${this.id} strategy does not recognize this version format.`,
    );
  }
}

export const DEFAULT_VERSION_STRATEGIES: readonly VersionStrategy[] = [
  new SemVerStrategy(),
  new ProductSemVerStrategy("php", ["php"], {
    compactPhpPrerelease: true,
    normalizePrereleaseMarkers: true,
  }),
  new ProductSemVerStrategy("nginx", ["nginx"]),
  new ProductSemVerStrategy("apache", ["apache"]),
];

/** Selects an ecosystem strategy, falling back to strict generic SemVer for unknown technologies. */
export class VersionStrategyRegistry {
  private readonly byId: ReadonlyMap<string, VersionStrategy>;
  private readonly byTechnology: ReadonlyMap<string, VersionStrategy>;
  private readonly fallback: VersionStrategy;

  public constructor(
    strategies: readonly VersionStrategy[] = DEFAULT_VERSION_STRATEGIES,
  ) {
    const byId = new Map<string, VersionStrategy>();
    const byTechnology = new Map<string, VersionStrategy>();
    let fallback: VersionStrategy | undefined;
    for (const strategy of strategies) {
      if (
        !strategy ||
        typeof strategy.id !== "string" ||
        strategy.id.trim().length === 0 ||
        !/^[a-z0-9][a-z0-9._-]*$/.test(strategy.id) ||
        !Array.isArray(strategy.technologyIds) ||
        strategy.technologyIds.length === 0 ||
        typeof strategy.parse !== "function" ||
        typeof strategy.compare !== "function" ||
        byId.has(strategy.id)
      ) {
        throw new ApplicationError(
          "INVALID_CONFIGURATION",
          "Version strategies require unique identifiers, technology IDs, parser, and comparator functions.",
        );
      }
      byId.set(strategy.id, strategy);
      for (const technologyId of strategy.technologyIds) {
        if (technologyId === "*") {
          if (fallback) {
            throw new ApplicationError(
              "INVALID_CONFIGURATION",
              "Only one generic fallback version strategy is allowed.",
            );
          }
          fallback = strategy;
          continue;
        }
        if (
          !technologyId ||
          !/^[a-z0-9][a-z0-9._-]*$/.test(technologyId) ||
          byTechnology.has(technologyId)
        ) {
          throw new ApplicationError(
            "INVALID_CONFIGURATION",
            `A version strategy is already registered for ${technologyId || "an empty technology ID"}.`,
          );
        }
        byTechnology.set(technologyId, strategy);
      }
    }
    if (!fallback) {
      throw new ApplicationError(
        "INVALID_CONFIGURATION",
        "A generic fallback version strategy is required.",
      );
    }
    this.byId = byId;
    this.byTechnology = byTechnology;
    this.fallback = fallback;
  }

  public forTechnology(technologyId: string): VersionStrategy {
    return this.byTechnology.get(technologyId) ?? this.fallback;
  }

  public byStrategyId(strategyId: string): VersionStrategy | undefined {
    return this.byId.get(strategyId);
  }
}
