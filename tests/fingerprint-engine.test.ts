import { describe, expect, it } from "vitest";
import {
  BUILTIN_FINGERPRINT_DEFINITIONS,
  FingerprintEngine,
  validateFingerprintDefinitions,
} from "../src/index.js";
import type {
  Evidence,
  EvidenceCollection,
  EvidenceSource,
  EvidenceType,
  FingerprintDefinitionSet,
  TechnologyDetection,
} from "../src/index.js";

function makeEvidence(
  type: EvidenceType,
  source: EvidenceSource,
  normalizedValue: string,
  options: { readonly key?: string; readonly versionHint?: string } = {},
): Evidence {
  return {
    type,
    source,
    normalizedValue,
    strength: type === "header" || type === "cookie" ? "direct" : "derived",
    reason: "Fixture observation.",
    ...(options.key !== undefined ? { key: options.key } : {}),
    ...(options.versionHint !== undefined ? { versionHint: options.versionHint } : {}),
  };
}

function collection(...evidence: readonly Evidence[]): EvidenceCollection {
  return {
    schemaVersion: "1.0",
    evidence,
    processing: {
      bodyBytesReceived: 0,
      bodyBytesExamined: 0,
      bodyTruncated: false,
      evidenceTruncated: false,
    },
  };
}

function detection(
  result: ReturnType<FingerprintEngine["fingerprint"]>,
  id: string,
): TechnologyDetection | undefined {
  return result.detections.find((item) => item.technologyId === id);
}

describe("FingerprintEngine", () => {
  const engine = new FingerprintEngine();

  it("detects PHP from an explicit version header while treating it as spoofable", () => {
    const result = engine.fingerprint(
      collection(
        makeEvidence("header", "response.headers", "PHP/8.2.3", {
          key: "x-powered-by",
          versionHint: "8.2.3",
        }),
      ),
    );
    const php = detection(result, "php");

    expect(php?.versionCandidate?.value).toBe("8.2.3");
    expect(php?.versionConfidence).toBe(0.65);
    expect(php?.detectionConfidence).toBe(0.72);
    expect(php?.matchedEvidenceReferences[0]?.evidenceIndex).toBe(0);
    expect(php?.detectionReasons.join(" ")).toMatch(/spoofed/i);
  });

  it("detects PHP from indirect session and generator signals without inventing a version", () => {
    const php = detection(
      engine.fingerprint(
        collection(
          makeEvidence("cookie", "response.cookies", "phpsessid=<redacted>", {
            key: "phpsessid",
          }),
          makeEvidence("html-generator", "html.generator", "PHP"),
        ),
      ),
      "php",
    );

    expect(php?.detectionConfidence).toBe(0.85);
    expect(php?.versionCandidate).toBeUndefined();
    expect(php?.versionConfidence).toBe(0);
    expect(php?.matchedEvidenceReferences).toHaveLength(2);
  });

  it.each([
    ["nginx", "nginx/1.25.4", "1.25.4"],
    ["apache", "Apache/2.4.62", "2.4.62"],
  ])("detects %s and preserves explicit version provenance", (id, value, version) => {
    const name = id === "apache" ? "Apache HTTP Server" : "nginx";
    const result = engine.fingerprint(
      collection(
        makeEvidence("header", "response.headers", value, {
          key: "server",
          versionHint: version,
        }),
      ),
    );
    const found = detection(result, id);

    expect(found?.displayName).toBe(name);
    expect(found?.versionCandidate).toMatchObject({ value: version });
    expect(found?.versionCandidate?.evidenceReferences[0]?.normalizedValue).toBe(value);
  });

  it("keeps weak intermediary evidence below an explicit header confidence", () => {
    const result = engine.fingerprint(
      collection(makeEvidence("header", "response.headers", "1.1 nginx", { key: "via" })),
    );
    const nginx = detection(result, "nginx");

    expect(nginx?.detectionConfidence).toBe(0.38);
    expect(nginx?.versionCandidate).toBeUndefined();
    expect(nginx?.detectionReasons.join(" ")).toMatch(/intermediary/i);
  });

  it("caps a lone spoofable header and does not treat it as unquestionable truth", () => {
    const result = engine.fingerprint(
      collection(
        makeEvidence("header", "response.headers", "PHP/8.1", {
          key: "x-powered-by",
          versionHint: "8.1",
        }),
      ),
    );
    const php = detection(result, "php");

    expect(php?.detectionConfidence).toBeLessThan(1);
    expect(php?.detectionReasons[0]).toMatch(/configurable|spoofed/i);
    expect(php?.versionCandidate?.value).toBe("8.1");
  });

  it("reduces confidence and preserves contradictory Apache/nginx evidence", () => {
    const conflict = makeEvidence(
      "header",
      "response.headers",
      "nginx/1.25.4 Apache/2.4.62",
      { key: "server", versionHint: "1.25.4" },
    );
    const result = engine.fingerprint(collection(conflict));
    const nginx = detection(result, "nginx");
    const apache = detection(result, "apache");

    expect(nginx?.detectionConfidence).toBeLessThan(0.82);
    expect(apache?.detectionConfidence).toBeLessThan(0.82);
    expect(nginx?.contradictoryEvidence[0]).toMatchObject({
      technologyId: "apache",
      evidenceIndex: 0,
    });
    expect(apache?.contradictoryEvidence[0]).toMatchObject({
      technologyId: "nginx",
      evidenceIndex: 0,
    });
    expect(nginx?.versionCandidate).toBeUndefined();
    expect(apache?.versionCandidate).toBeUndefined();
  });

  it("does not raise confidence for duplicate evidence matching the same rule", () => {
    const item = makeEvidence("header", "response.headers", "nginx", { key: "server" });
    const one = detection(engine.fingerprint(collection(item)), "nginx");
    const two = detection(engine.fingerprint(collection(item, { ...item })), "nginx");

    expect(two?.detectionConfidence).toBe(one?.detectionConfidence);
    expect(two?.matchedEvidenceReferences).toHaveLength(2);
  });

  it("combines independent PHP signals using the documented noisy-OR score", () => {
    const php = detection(
      engine.fingerprint(
        collection(
          makeEvidence("header", "response.headers", "PHP/8.2", {
            key: "x-powered-by",
            versionHint: "8.2",
          }),
          makeEvidence("cookie", "response.cookies", "phpsessid=<redacted>", {
            key: "phpsessid",
          }),
        ),
      ),
      "php",
    );

    expect(php?.detectionConfidence).toBe(0.93);
  });

  it("does not attach a generic version hint to a different technology token", () => {
    const apache = detection(
      engine.fingerprint(
        collection(
          makeEvidence("header", "response.headers", "Apache/2.4 nginx", {
            key: "server",
            versionHint: "2.4",
          }),
        ),
      ),
      "nginx",
    );

    expect(apache?.versionCandidate).toBeUndefined();
  });

  it("retains conflicting version candidates and all evidence references", () => {
    const result = engine.fingerprint(
      collection(
        makeEvidence("header", "response.headers", "nginx/1.2.0", {
          key: "server",
          versionHint: "1.2.0",
        }),
        makeEvidence("header", "response.headers", "nginx/1.3.0", {
          key: "server",
          versionHint: "1.3.0",
        }),
      ),
    );
    const nginx = detection(result, "nginx");

    expect(nginx?.versionCandidates.map((candidate) => candidate.value)).toEqual([
      "1.2.0",
      "1.3.0",
    ]);
    expect(nginx?.versionCandidate?.evidenceReferences[0]?.evidenceIndex).toBe(0);
    expect(nginx?.matchedEvidenceReferences).toHaveLength(2);
  });

  it("returns no detection for unknown technologies and empty evidence", () => {
    const unknown = engine.fingerprint(
      collection(
        makeEvidence("header", "response.headers", "AcmeEdge/9.2", {
          key: "server",
          versionHint: "9.2",
        }),
      ),
    );

    expect(unknown.detections).toEqual([]);
    expect(engine.fingerprint(collection()).detections).toEqual([]);
  });

  it("rejects malformed or unsupported Evidence Collection payloads", () => {
    expect(() =>
      engine.fingerprint({
        schemaVersion: "2.0",
        evidence: [],
      } as unknown as EvidenceCollection),
    ).toThrow(/EvidenceCollection schema version 1.0/);
    expect(() =>
      engine.fingerprint(
        collection({ type: "unknown", normalizedValue: "value" } as unknown as Evidence),
      ),
    ).toThrow(/EvidenceCollection schema version 1.0/);
  });

  it("validates versioned definitions and rejects invalid or duplicate rule identifiers", () => {
    const invalid = JSON.parse(
      JSON.stringify(BUILTIN_FINGERPRINT_DEFINITIONS),
    ) as FingerprintDefinitionSet;
    const first = invalid.definitions[0];
    if (!first) throw new Error("Expected built-in definition fixture.");
    const invalidPack = {
      ...invalid,
      definitions: [
        {
          ...first,
          id: "invalid id",
          signals: [{ ...first.signals[0], weight: 2, expression: "executable" }],
        },
        first,
        first,
      ],
    };

    expect(validateFingerprintDefinitions(invalid)).toEqual([]);
    expect(validateFingerprintDefinitions(invalidPack).join(" ")).toMatch(
      /id must be unique|weight must be greater/i,
    );
    expect(() => new FingerprintEngine(invalidPack as FingerprintDefinitionSet)).toThrow(
      /Invalid fingerprint definitions/,
    );
  });

  it("produces stable output regardless of definition ordering", () => {
    const input = collection(
      makeEvidence("header", "response.headers", "Apache/2.4.62", {
        key: "server",
        versionHint: "2.4.62",
      }),
      makeEvidence("header", "response.headers", "PHP/8.2.3", {
        key: "x-powered-by",
        versionHint: "8.2.3",
      }),
    );
    const shuffled = new FingerprintEngine({
      ...BUILTIN_FINGERPRINT_DEFINITIONS,
      definitions: [...BUILTIN_FINGERPRINT_DEFINITIONS.definitions].reverse(),
    });

    expect(shuffled.fingerprint(input)).toEqual(engine.fingerprint(input));
    expect(engine.fingerprint(input)).toEqual(engine.fingerprint(input));
  });

  it("takes an immutable snapshot of validated knowledge", () => {
    const mutableDefinitions = JSON.parse(
      JSON.stringify(BUILTIN_FINGERPRINT_DEFINITIONS),
    ) as {
      schemaVersion: "1.0";
      definitions: Array<{
        id: string;
        displayName: string;
        category: string;
        minimumConfidence: number;
        singleSignalConfidenceCap: number;
        signals: Array<{ id: string; value: string }>;
      }>;
    };
    const snapshotEngine = new FingerprintEngine(
      mutableDefinitions as unknown as FingerprintDefinitionSet,
    );
    const php = mutableDefinitions.definitions.find((item) => item.id === "php");
    if (!php?.signals[0]) throw new Error("Expected PHP rule fixture.");
    php.signals[0].value = "not-php";

    expect(
      detection(
        snapshotEngine.fingerprint(
          collection(
            makeEvidence("header", "response.headers", "PHP/8.2", {
              key: "x-powered-by",
              versionHint: "8.2",
            }),
          ),
        ),
        "php",
      ),
    ).toBeDefined();
  });
});
