// Minimal hand-rolled JSON-RPC server that answers initialize with a bogus protocol version.
import readline from "node:readline";

const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  if (msg.method === "initialize") {
    const result = { protocolVersion: "1999-01-01", capabilities: {}, serverInfo: { name: "old", version: "0" } };
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }) + "\n");
  }
});
