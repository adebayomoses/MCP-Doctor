import { existsSync, writeFileSync } from "node:fs";
import { Command } from "commander";

const TEMPLATE = `# mcp-detector.yml

# The server to scan. Use either a command (stdio) or a url (http/sse).
server:
  command: npx
  args: ["-y", "@modelcontextprotocol/server-everything"]
  # url: https://example.com/mcp
  # headers:
  #   Authorization: "Bearer \${TOKEN}"

severity:
  fail_on: high        # info | low | medium | high | critical | none

rules:
  prompt_injection: true
  tool_poisoning: true
  secret_exposure: true
  dangerous_permissions: true
  command_injection: true
  performance: true
  # Per-rule overrides:
  # MCP-024: off
  # MCP-010: low

thresholds:
  latency_ms: 3000
  timeout_ms: 10000

# Active mode calls tools that look read-only to measure latency/timeouts.
# active:
#   enabled: true
#   allow: [my_safe_tool]
#   deny: [dangerous_tool]

# ignore:
#   rules: [MCP-024]
#   tools: [legacy_tool]

# Your own rules (declarative YAML; no code is executed):
# community_rules:
#   - ./team-rules/
`;

export function initCommand(): Command {
  return new Command("init")
    .description("Create a starter mcp-detector.yml in the current directory")
    .option("--force", "overwrite an existing file")
    .action((opts: { force?: boolean }) => {
      const file = "mcp-detector.yml";
      if (existsSync(file) && !opts.force) throw new Error(`${file} already exists (use --force to overwrite).`);
      writeFileSync(file, TEMPLATE, "utf8");
      process.stdout.write(`Created ${file}\n`);
    });
}
