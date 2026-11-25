import { readFile } from "node:fs/promises";
import type { HttpResponse } from "../../src/application/ports.js";

export function createProbeResult(overrides: Partial<HttpResponse> = {}): HttpResponse {
  return {
    status: 200,
    headers: {},
    body: new Uint8Array(),
    finalUrl: "https://example.test/base/",
    ...overrides,
  };
}

export async function loadEvidenceHtmlFixture(): Promise<Uint8Array> {
  return new Uint8Array(
    await readFile(new URL("../fixtures/evidence-sample.html", import.meta.url)),
  );
}
