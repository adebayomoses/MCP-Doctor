import { describe, expect, it } from "vitest";
import { AUTH_ERROR } from "../../src/core/scanner.js";
import { classifyTool } from "../../src/detectors/tools/capabilities.js";
import { evaluate } from "../../src/core/detector.js";
import { cfg, makeSnapshot, tool } from "../fixtures/snapshot.js";

const caps = (name: string, description: string, props: Record<string, any> = {}) =>
  classifyTool(tool(name, { description, inputSchema: { type: "object", properties: props } })).map((c) => c.capability);

/**
 * These cases were false positives found by scanning real remote servers from the official MCP
 * registry (descriptions paraphrased from the real tools). Each must stay quiet.
 */
describe("capability classification: real-world false positives", () => {
  it("a bare 'create'/'delete' verb is not a filesystem operation", () => {
    expect(caps("create_campaign", "Queue a cold email campaign against a lead list. It starts sending soon.")).not.toContain("fs_write");
    expect(caps("delete_list", "Permanently delete a list and every lead in it. Irreversible.")).not.toContain("fs_delete");
    expect(caps("create_user", "Creates a user account.")).toEqual([]);
    expect(caps("remove_member", "Removes a member from the team.")).toEqual([]);
  });
  it("still recognises genuine filesystem tools", () => {
    expect(caps("write_file", "x")).toContain("fs_write");
    expect(caps("create_directory", "x")).toContain("fs_write");
    expect(caps("move_file", "x")).toContain("fs_write");
    expect(caps("delete_file", "x")).toContain("fs_delete");
    expect(caps("rm", "x")).toContain("fs_delete");
    expect(caps("anything", "Writes the content to a file on disk.")).toContain("fs_write");
  });
  it("a description that denies returning credentials is not credential access", () => {
    expect(caps("list_mailboxes", "Connected sending mailboxes with their id and from address. Credentials are never returned.")).not.toContain("credentials");
    expect(caps("login_help", "Explains the login flow. Does not expose passwords or API keys.")).not.toContain("credentials");
    expect(caps("count_tokens", "Counts the number of tokens in a prompt.")).not.toContain("credentials");
    expect(caps("preview_leads", "Find leads and see how many exist. Works without any password or API key.")).not.toContain("credentials");
  });
  it("still recognises tools that really handle credentials", () => {
    expect(caps("get-env", "Returns all environment variables.")).toContain("credentials");
    expect(caps("read_secret", "x")).toContain("credentials");
    expect(caps("rotate_api_key", "x")).toContain("credentials");
    expect(caps("dump", "Returns the stored passwords and private keys for the account.")).toContain("credentials");
  });
  it("the server-level MCP-007 bundle is not triggered by those lookalikes", () => {
    const tools = [
      tool("create_campaign", { description: "Queue a campaign." }),
      tool("create_list", { description: "Create a lead list." }),
      tool("delete_list", { description: "Delete a list." }),
      tool("list_mailboxes", { description: "Mailboxes. Credentials are never returned." }),
    ];
    const f = evaluate(makeSnapshot({ tools }), cfg()).result.findings;
    expect(f.filter((x) => x.rule === "MCP-007" || x.rule === "MCP-011")).toEqual([]);
  });
});

describe("authentication error detection", () => {
  it.each([
    "Streamable HTTP error: Error POSTing to endpoint: 401 Unauthorized",
    'Error POSTing to endpoint: {"error":{"code":-32001,"message":"invalid or missing MCP token"}}',
    "HTTP 403 Forbidden",
    "Missing API key",
    "authentication required",
    "Bearer token is required",
    "expired access token",
    "OAuth authorization needed",
  ])("treats as auth: %s", (m) => expect(AUTH_ERROR.test(m)).toBe(true));

  it.each([
    "Connection closed",
    "spawn ENOENT",
    "Connection timed out after 30000 ms",
    "fetch failed: ECONNREFUSED",
    "Server's protocol version is not supported: 1999-01-01",
    "Unexpected token < in JSON at position 0",
  ])("does not treat as auth: %s", (m) => expect(AUTH_ERROR.test(m)).toBe(false));
});
