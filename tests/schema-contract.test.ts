import { describe, expect, it } from "vitest";
import { compileAllSchemas } from "./helpers/schema-validator.js";

describe("published JSON Schema contracts", () => {
  it("compiles every schema and local cross-reference", () => {
    expect(compileAllSchemas).not.toThrow();
  });
});
