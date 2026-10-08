import { SUPPORTED_PROTOCOL_VERSIONS } from "@modelcontextprotocol/sdk/types.js";
import { explainConnectError } from "../core/explain.js";
import type { Rule } from "../core/types.js";

const VERSION_ERR = /protocol version/i;

export const protocolRules: Rule[] = [
  {
    id: "MCP-001",
    name: "Protocol initialization failure",
    category: "protocol",
    severity: "critical",
    group: "protocol",
    description: "The scanner could not connect to the server or complete the MCP initialize handshake.",
    why: "A server that cannot initialize cannot be used by any MCP client, and nothing else about it can be verified.",
    recommendation:
      "Run the server command by hand and check its stderr. For stdio servers make sure stdout carries only JSON-RPC messages (log to stderr). For HTTP servers confirm the URL, transport type and any required headers.",
    check({ snapshot, config }) {
      if (snapshot.connected) return [];
      if (snapshot.connectError && VERSION_ERR.test(snapshot.connectError)) return [];
      const stderr = snapshot.stderr?.trim().split("\n").slice(-3).join(" | ");
      const why = explainConnectError(snapshot.connectError ?? "", {
        command: config.server?.command,
        url: config.server?.url,
        timeoutMs: config.thresholds.connect_ms,
        stderr: snapshot.stderr,
      });
      return [
        {
          message: `Could not initialize: ${snapshot.connectError ?? "unknown error"}. ${why.title} ${why.hint}`,
          evidence: stderr ? `server stderr: ${stderr.slice(0, 300)}` : undefined,
        },
      ];
    },
  },
  {
    id: "MCP-002",
    name: "Invalid protocol version",
    category: "protocol",
    severity: "high",
    group: "protocol",
    description: "The server negotiated a protocol version that is malformed or not supported by the MCP SDK.",
    why: "Clients and servers must agree on a protocol version; an unsupported or malformed version causes undefined behaviour or refused connections.",
    recommendation: `Respond to initialize with a date-formatted version the client requested or one you support (supported by this scanner: ${SUPPORTED_PROTOCOL_VERSIONS.join(", ")}). Upgrade your MCP SDK if it is old.`,
    check({ snapshot }) {
      if (!snapshot.connected) {
        if (snapshot.connectError && VERSION_ERR.test(snapshot.connectError))
          return [{ message: snapshot.connectError }];
        return [];
      }
      const v = snapshot.protocolVersion;
      if (!v) return [];
      if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) return [{ message: `Protocol version "${v}" is not in YYYY-MM-DD format.` }];
      if (!SUPPORTED_PROTOCOL_VERSIONS.includes(v))
        return [{ message: `Protocol version "${v}" is not a known MCP revision.` }];
      return [];
    },
  },
  {
    id: "MCP-016",
    name: "Ping failed",
    category: "protocol",
    severity: "medium",
    group: "protocol",
    description: "The server did not answer a `ping` request.",
    why: "The MCP specification requires servers to respond to ping; clients use it for liveness checks.",
    recommendation: "Handle the `ping` method and return an empty result object.",
    check({ snapshot }) {
      if (!snapshot.connected || !snapshot.ping || snapshot.ping.ok) return [];
      return [{ message: `ping failed: ${snapshot.ping.error ?? "no response"}` }];
    },
  },
  {
    id: "MCP-017",
    name: "Unknown method not rejected",
    category: "protocol",
    severity: "low",
    group: "protocol",
    description: "The server did not return a JSON-RPC error for an unknown method (it hung or returned success).",
    why: "JSON-RPC requires an error (-32601 Method not found) for unknown methods. Hanging requests leave clients waiting until they time out.",
    recommendation: "Make sure unrecognised methods produce a JSON-RPC error response. Most MCP SDKs do this by default; custom transports often do not.",
    check({ snapshot }) {
      const u = snapshot.unknownMethod;
      if (!snapshot.connected || !u || u.rejected) return [];
      return [
        {
          message: u.timedOut
            ? "An unknown method received no response (request timed out)."
            : "An unknown method returned a success response instead of an error.",
        },
      ];
    },
  },
  {
    id: "MCP-018",
    name: "Discovery request failed",
    category: "protocol",
    severity: "medium",
    group: "protocol",
    description: "The server advertises a capability (tools/resources/prompts) but the corresponding list request failed.",
    why: "If a declared capability cannot be listed, clients cannot use it and may treat the whole server as broken.",
    recommendation: "Either implement the list method for each advertised capability or remove the capability from the initialize response.",
    check({ snapshot }) {
      return Object.entries(snapshot.listErrors).map(([name, err]) => ({
        message: `${name}/list failed: ${err}`,
      }));
    },
  },
];
