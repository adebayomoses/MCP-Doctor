import type { ResolvedConfig } from "../core/types.js";

export function defaultConfig(): ResolvedConfig {
  return {
    severity: { fail_on: "none" },
    groups: {
      protocol: true,
      prompt_injection: true,
      tool_poisoning: true,
      secret_exposure: true,
      dangerous_permissions: true,
      command_injection: true,
      schema: true,
      quality: true,
      performance: true,
      network_risk: true,
      rug_pull: true,
    },
    ruleOverrides: {},
    thresholds: { latency_ms: 3000, timeout_ms: 10000, connect_ms: 30000, max_timeout_rate: 0.05 },
    active: false,
    activeAllow: [],
    activeDeny: [],
    ignore: { rules: [], tools: [] },
    communityRules: [],
    plugins: [],
  };
}
