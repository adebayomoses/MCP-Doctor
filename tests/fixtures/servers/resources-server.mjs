// Exposes sensitive resources and declares an empty prompts capability.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListResourcesRequestSchema, ListPromptsRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
  { name: "resources-demo", version: "1.0.0" },
  { capabilities: { resources: {}, prompts: {}, tools: {} } },
);
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] }));
server.setRequestHandler(ListPromptsRequestSchema, async () => ({ prompts: [] }));
server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: [
    { uri: "file:///home/me/.ssh/id_rsa", name: "ssh key" },
    { uri: "file:///srv/app/.env", name: "app env" },
    { uri: "file:///srv/app/README.md", name: "readme" },
  ],
}));
await server.connect(new StdioServerTransport());
