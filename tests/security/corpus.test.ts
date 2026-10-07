import { describe, expect, it } from "vitest";
import { evaluate } from "../../src/core/detector.js";
import { SEVERITY_ORDER, type Severity } from "../../src/core/types.js";
import { cfg, makeSnapshot } from "../fixtures/snapshot.js";
import { ATTACKS, BENIGN } from "./corpus.js";

const rank = (s: Severity) => SEVERITY_ORDER.indexOf(s);
/** Rules whose findings should fail a build on benign text. */
const CONTENT_RULES = ["MCP-004", "MCP-005", "MCP-006", "MCP-031"];

describe("detection corpus: attacks must be caught", () => {
  for (const a of ATTACKS) {
    it(a.name, () => {
      const { result } = evaluate(makeSnapshot({ tools: [a.tool], instructions: a.instructions }), cfg());
      const hits = result.findings.filter((f) => a.expect.includes(f.rule));
      expect(hits.length, `expected one of ${a.expect.join(", ")}; got ${result.findings.map((f) => f.rule).join(", ")}`).toBeGreaterThan(0);
      if (a.atLeast) expect(Math.max(...hits.map((h) => rank(h.severity)))).toBeGreaterThanOrEqual(rank(a.atLeast));
    });
  }
});

describe("detection corpus: benign descriptions must not be flagged", () => {
  for (const b of BENIGN) {
    it(b.name, () => {
      const { result } = evaluate(makeSnapshot({ tools: [b.tool] }), cfg());
      const bad = result.findings.filter((f) => CONTENT_RULES.includes(f.rule) && rank(f.severity) >= rank("medium"));
      expect(bad.map((f) => `${f.rule}: ${f.message} ${f.evidence ?? ""}`)).toEqual([]);
    });
  }
});

describe("detection corpus: summary", () => {
  it("reports recall and false-positive rate", () => {
    let caught = 0;
    for (const a of ATTACKS) {
      const { result } = evaluate(makeSnapshot({ tools: [a.tool], instructions: a.instructions }), cfg());
      if (result.findings.some((f) => a.expect.includes(f.rule))) caught++;
    }
    let falsePositives = 0;
    for (const b of BENIGN) {
      const { result } = evaluate(makeSnapshot({ tools: [b.tool] }), cfg());
      if (result.findings.some((f) => CONTENT_RULES.includes(f.rule) && rank(f.severity) >= rank("medium"))) falsePositives++;
    }
    console.log(`corpus: recall ${caught}/${ATTACKS.length}, false positives ${falsePositives}/${BENIGN.length}`);
    expect(caught).toBe(ATTACKS.length);
    expect(falsePositives).toBe(0);
  });
});
