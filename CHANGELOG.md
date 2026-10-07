# Changelog

All notable changes are documented here. Format based on [Keep a Changelog](https://keepachangelog.com/); versions follow [SemVer](https://semver.org/).

## [0.1.0] - Unreleased

### Added
- CLI: `scan`, `inspect`, `test`, `report`, `rules`, `init`.
- Transports: stdio, Streamable HTTP (with SSE fallback).
- 32 detection rules (MCP-001 – MCP-032) across protocol, schema, security, tools, quality and performance.
- Health score (0–100) with per-category breakdown.
- Terminal, JSON and Markdown output; `--fail-on` severity gate for CI.
- `mcp-detector.yml` configuration (rule groups, per-rule overrides, thresholds, ignore lists, active mode allow/deny).
- Passive-by-default scanning; opt-in `--active` mode that only calls tools that look read-only.
- Evasion-resistant text analysis: zero-width characters, full-width and homoglyph letters, and base64/hex-encoded payloads are normalised or decoded before pattern matching.
- MCP-031 network risk (capture/tunnel hosts, image-embedded exfiltration, internal and cloud-metadata addresses, non-HTTP schemes) and MCP-032 rug-pull detection.
- `mcp-detector pin` and `mcp-detector.lock.json` baseline; `scan --baseline` / `--no-baseline`.
- Labelled detection corpus (attack and benign samples) used as a regression suite for precision and recall.
- GitHub Action (`github-action/action.yml`) with job-summary report.
- Example servers (`examples/secure-server`, `examples/vulnerable-server`) and a test suite with stdio and HTTP integration tests.
