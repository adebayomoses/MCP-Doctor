import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { welcome } from "../../src/cli/welcome.js";

/** Drive the menu with scripted keystrokes and capture what it prints. */
async function run(answers: string[]) {
  const input = new PassThrough();
  const output = new PassThrough();
  let printed = "";
  output.on("data", (c) => (printed += c));
  const p = welcome(input as any, output as any);
  for (const a of answers) {
    await new Promise((ok) => setTimeout(ok, 30));
    input.write(a + "\n");
  }
  const choice = await p;
  return { choice, printed };
}

describe("first-run welcome menu", () => {
  it("offers the web app, the demo, installed servers and help", async () => {
    const { printed } = await run([""]);
    expect(printed).toContain("Open the web app");
    expect(printed).toContain("demo scan");
    expect(printed).toContain("MCP servers I already use");
    expect(printed).toContain("Show all commands");
  });
  it("pressing Enter picks the recommended option, the web app", async () => {
    expect((await run([""])).choice).toEqual(["ui"]);
    expect((await run(["1"])).choice).toEqual(["ui"]);
  });
  it("2 runs the demo and 4 shows help", async () => {
    expect((await run(["2"])).choice).toEqual(["demo"]);
    expect((await run(["4"])).choice).toBeUndefined();
  });
  it("an unrecognised answer explains itself instead of guessing", async () => {
    const r = await run(["banana"]);
    expect(r.choice).toBeUndefined();
    expect(r.printed).toContain("Please type 1, 2, 3 or 4");
  });
});
