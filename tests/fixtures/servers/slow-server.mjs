// Read-only tools that are slow, hang, or error. Used to test active-mode performance rules.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "slow-demo", version: "1.0.0" }, { capabilities: { tools: {} } });
const ro = { readOnlyHint: true };
const empty = { type: "object", properties: {}, additionalProperties: false };
const tools = [
  { name: "get_fast", description: "Returns immediately with a constant value.", inputSchema: empty, annotations: ro },
  { name: "get_slow", description: "Returns after a short delay to simulate slow work.", inputSchema: empty, annotations: ro },
  { name: "get_hang", description: "Never returns, to simulate a hung upstream call.", inputSchema: empty, annotations: ro },
  { name: "get_error", description: "Always returns a tool-level error result.", inputSchema: empty, annotations: ro },
];
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  switch (req.params.name) {
    case "get_slow":
      await new Promise((r) => setTimeout(r, 700));
      return { content: [{ type: "text", text: "slow ok" }] };
    case "get_hang":
      await new Promise(() => {});
      return { content: [] };
    case "get_error":
      return { isError: true, content: [{ type: "text", text: "upstream exploded" }] };
    default:
      return { content: [{ type: "text", text: "ok" }] };
  }
});
await server.connect(new StdioServerTransport());
