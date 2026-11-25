import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Ajv2020, type AnySchema, type ValidateFunction } from "ajv/dist/2020.js";

const schemaDirectory = fileURLToPath(new URL("../../schemas/", import.meta.url));
const ajv = new Ajv2020({ allErrors: true, strict: false });
const schemaIds: string[] = [];

ajv.addFormat("date-time", {
  type: "string",
  validate: (value: string): boolean =>
    Number.isFinite(Date.parse(value)) &&
    value.includes("T") &&
    /(?:Z|[+-]\d{2}:\d{2})$/.test(value),
});
ajv.addFormat("uri", {
  type: "string",
  validate: (value: string): boolean => {
    try {
      new URL(value);
      return true;
    } catch {
      return false;
    }
  },
});

for (const filename of readdirSync(schemaDirectory).filter((item) =>
  item.endsWith(".json"),
)) {
  const schema = JSON.parse(
    readFileSync(`${schemaDirectory}${filename}`, "utf8"),
  ) as AnySchema;
  ajv.addSchema(schema);
  if (typeof schema === "object" && schema !== null && typeof schema.$id === "string")
    schemaIds.push(schema.$id);
}

function validator(id: string): ValidateFunction {
  const result = ajv.getSchema(id);
  if (!result) throw new Error(`Schema is unavailable: ${id}`);
  return result;
}

export const validateScanResult = validator(
  "https://blueleaf.dev/schemas/scan-result-1.0.json",
);
export const validateApiError = validator(
  "https://blueleaf.dev/schemas/api-error-1.0.json",
);

export function compileAllSchemas(): void {
  for (const id of schemaIds) {
    if (!validator(id)) throw new Error(`Schema is invalid: ${id}`);
  }
}
