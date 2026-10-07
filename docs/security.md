# Security model

## Safe by default

| Mode | What MCP Detector sends |
|---|---|
| default (passive) | `initialize`, `ping`, one unknown-method probe, and `tools/list`, `resources/list`, `prompts/list` |
| `--active` | the above, plus `tools/call` for tools judged read-only |

The unknown-method probe (`mcp-detector/unknown-method`) checks that a server answers with a JSON-RPC error instead of hanging. It has no side effects.

## What active mode will call

A tool is called only if **all** of these hold:

1. It is not in `active.deny`.
2. It is not annotated `destructiveHint: true`.
3. Either it is in `active.allow`, or it is annotated `readOnlyHint: true`, or its name starts with a read verb (`get`, `list`, `read`, `search`, `find`, `fetch`, `query`, `show`, `describe`, `status`, `info`, `ping`, `echo`, `version`, `health`, `count`, `lookup`, `view`, `check`) **and** does not contain a write verb (`delete`, `write`, `create`, `update`, `exec`, `run`, `send`, `deploy`, …).

Required arguments are filled with minimal placeholder values (`"test"`, `1`, `false`, first enum value). Everything else is listed as skipped. To widen or narrow the set:

```yaml
active:
  enabled: true
  allow: [render_report]
  deny: [get_secrets]
```

**Do not run `--active` against production systems unless you have allow-listed the tools you are comfortable calling.**

## Indicators, not verdicts

Detection is heuristic (pattern matching and capability inference from names, descriptions and schemas). Consequently:

- A finding means "this looks like X, here is why", not "this is exploitable".
- Absence of findings does not mean a server is safe. MCP Detector does not analyse server source code or runtime behaviour beyond what `--active` observes.
- The health score is an engineering signal, not a certification.

## How server output is treated

Everything a server returns (descriptions, instructions, tool output, stderr) is untrusted text. MCP Detector only pattern-matches it. It never evaluates it, follows links in it, or passes it to a model.

Secrets detected in that text are shown redacted (first four characters and a length).

## Scanning stdio servers

`scan -- <command>` **runs that command** with your privileges, exactly as an MCP client would. Only scan code you would be willing to run, or run MCP Detector inside a container/CI sandbox.

Credentials you pass via `--header` or `--env` are sent only to the server you are scanning and are not written to reports. The JSON report contains the target command/URL, so avoid putting secrets in the command line itself; use `--env`/`--header`.

## Rug pulls: pin what you reviewed

A server can show honest tool definitions while you review it and swap in malicious ones later. Clients rarely tell you.

```bash
mcp-detector pin -- node ./build/index.js     # writes mcp-detector.lock.json
```

The lockfile stores a SHA-256 of every tool's title, description, input/output schema and annotations (plus the server instructions). Subsequent scans in that directory pick it up automatically and report **MCP-032** for:

| Change | Severity |
|---|---|
| a tool's description or schema changed | high |
| annotations changed (e.g. `readOnlyHint` flipped) | medium |
| a tool was added (capability expansion) | medium |
| server instructions changed | high |
| a tool was removed | low |

The description change is shown as a before/after excerpt. Commit the lockfile so changes appear in code review, and use `--fail-on high` in CI. To accept a legitimate change, review it and run `mcp-detector pin` again; it prints what changed and warns if the server currently has critical/high findings, because **pinning marks the current state as trusted**. Use `--baseline <file>` for a non-default path or `--no-baseline` to ignore it.

## Obfuscation

Pattern matching runs on the text as written, then on a normalised copy (Unicode NFKC, zero-width and tag characters removed, Cyrillic/Greek look-alike letters folded to Latin), and on any base64 or hex blob that decodes to readable text. Findings say when a match was only found after normalising or decoding. This defeats the common tricks (`ig<U+200B>nore`, Cyrillic `іgnore`, `ｉｇｎｏｒｅ`, encoded payloads) but a determined attacker can still phrase an instruction in a way no pattern expects, which is why pinning matters.

## Measured detection quality

`tests/security/corpus.ts` is a labelled corpus: 27 attack samples (poisoning, shadowing, injection, exfiltration channels, obfuscation, secrets, dangerous tools) and 22 realistic benign descriptions that resemble attacks on the surface ("Important: dates must be ISO 8601", "Ignores whitespace", Slack-webhook notifiers, docs links). The suite requires every attack to be caught and none of the benign samples to trigger a medium-or-higher content finding. When you fix a false positive or add a rule, add a sample to the corpus. This is a regression suite, not a benchmark: it shows the rules do what they were written to do, not that they catch everything.

## Detection categories

| Category | Rules | Summary |
|---|---|---|
| Prompt injection | MCP-004 | Override/concealment phrasing in descriptions, instructions, prompts, resources, tool output |
| Tool poisoning | MCP-005 | Hidden tags, HTML comments, invisible Unicode, sensitive-file references, exfiltration cues, tool shadowing |
| Secret exposure | MCP-006 | Known key formats and hard-coded secret assignments in metadata, defaults, examples, output and stderr |
| Dangerous permissions | MCP-007, 011, 012 | Shell execution, filesystem writes/deletes, credential access, database writes, SSRF-prone fetchers |
| Command injection | MCP-008 | CLI wrappers that take unconstrained string arguments |
| Network risk | MCP-028, 031 | Plain-HTTP transport; capture/tunnel hosts (webhook.site, ngrok…), image-embedded exfiltration, cloud-metadata and private addresses, `file://`/`gopher://` schemes |
| Sensitive resources | MCP-030 | Resources pointing at SSH keys, `.env`, cloud credentials |
| Rug pull | MCP-032 | Tool definitions that changed since `pin` |
