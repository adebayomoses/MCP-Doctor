import { Ajv } from "ajv";
import Ajv2020Module from "ajv/dist/2020.js";
import addFormatsModule from "ajv-formats";

const addFormats: (a: any) => void = (addFormatsModule as any).default ?? addFormatsModule;

const Ajv2020 = (Ajv2020Module as any).default ?? Ajv2020Module;

let ajv2020: any;
let ajv07: any;

function getAjv(schema: any) {
  const decl = typeof schema?.$schema === "string" ? schema.$schema : "";
  if (decl.includes("draft-07") || decl.includes("draft-06") || decl.includes("draft-04")) {
    if (!ajv07) {
      ajv07 = new Ajv({ strict: false, allErrors: true, validateFormats: false });
      try { addFormats(ajv07 as any); } catch { /* optional */ }
    }
    return ajv07;
  }
  if (!ajv2020) {
    ajv2020 = new Ajv2020({ strict: false, allErrors: true, validateFormats: false });
    try { addFormats(ajv2020 as any); } catch { /* optional */ }
  }
  return ajv2020;
}

/** Validate that `schema` is itself a valid JSON Schema. Returns human-readable problems. */
export function checkJsonSchema(schema: unknown): string[] {
  if (schema === null || typeof schema !== "object" || Array.isArray(schema)) {
    return ["schema is not a JSON object"];
  }
  const problems: string[] = [];
  const inst = getAjv(schema);
  try {
    const ok = inst.validateSchema(schema);
    if (!ok) {
      for (const e of inst.errors ?? []) problems.push(`${e.instancePath || "(root)"} ${e.message}`);
    } else {
      inst.compile(schema);
    }
  } catch (e) {
    const msg = (e as Error).message;
    // Unresolvable external $refs are not a defect in the schema's own structure.
    if (!/can't resolve reference/i.test(msg)) problems.push(msg.split("\n")[0]);
  }
  return [...new Set(problems)].slice(0, 6);
}

/** Cross-field consistency checks on an object schema. */
export function checkSchemaConsistency(schema: any): string[] {
  const problems: string[] = [];
  if (!schema || typeof schema !== "object") return problems;
  const props = schema.properties && typeof schema.properties === "object" ? Object.keys(schema.properties) : [];
  if (schema.required !== undefined && !Array.isArray(schema.required)) {
    problems.push("`required` must be an array of property names");
  } else if (Array.isArray(schema.required)) {
    for (const r of schema.required) {
      if (typeof r !== "string") problems.push("`required` contains a non-string entry");
      else if (!props.includes(r) && schema.additionalProperties === false)
        problems.push(`required property "${r}" is not defined in properties`);
      else if (!props.includes(r) && props.length > 0)
        problems.push(`required property "${r}" is not defined in properties`);
    }
  }
  for (const [name, p] of Object.entries<any>(schema.properties ?? {})) {
    if (p && typeof p === "object") {
      if (p.enum && p.type === "string" && p.enum.some((v: unknown) => typeof v !== "string"))
        problems.push(`property "${name}" has type string but non-string enum values`);
      if (p.default !== undefined && Array.isArray(p.enum) && !p.enum.includes(p.default))
        problems.push(`property "${name}" default is not in its enum`);
      if (typeof p.minimum === "number" && typeof p.maximum === "number" && p.minimum > p.maximum)
        problems.push(`property "${name}" has minimum greater than maximum`);
      if (typeof p.minLength === "number" && typeof p.maxLength === "number" && p.minLength > p.maxLength)
        problems.push(`property "${name}" has minLength greater than maxLength`);
    }
  }
  return problems;
}
