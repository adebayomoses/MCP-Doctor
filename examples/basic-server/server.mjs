// A well-behaved MCP server used to test MCP Detector.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "secure-demo", version: "1.0.0" }, { capabilities: { tools: {} } });

const tools = [
  {
    name: "get_weather",
    description: "Returns the current temperature in Celsius for a supported city.",
    inputSchema: {
      type: "object",
      properties: {
        city: { type: "string", enum: ["London", "Paris", "Tokyo"], description: "City to look up." },
      },
      required: ["city"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  },
  {
    name: "add_numbers",
    description: "Adds two numbers and returns their sum.",
    inputSchema: {
      type: "object",
      properties: {
        a: { type: "number", description: "First addend.", minimum: -1e9, maximum: 1e9 },
        b: { type: "number", description: "Second addend.", minimum: -1e9, maximum: 1e9 },
      },
      required: ["a", "b"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
];

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = req.params.arguments ?? {};
  if (req.params.name === "add_numbers") return { content: [{ type: "text", text: String(a.a + a.b) }] };
  if (req.params.name === "get_weather") return { content: [{ type: "text", text: "18" }] };
  return { isError: true, content: [{ type: "text", text: "unknown tool" }] };
});
await server.connect(new StdioServerTransport());
