# Community rules

You can add detection rules without changing MCP Detector. There are two kinds:

| | Declarative rules | Plugins |
|---|---|---|
| Format | YAML or JSON | JavaScript module |
| Power | regular-expression matching on server text | anything (`check()` is arbitrary code) |
| Runs code from the rule file | **No** | **Yes** |
| Enabled by | `--rules <path>` or `community_rules:` in config | `plugins:` in config **and** `--allow-plugins` on the command line |

Declarative rules are the recommended way to share rules, because they can be reviewed as data and cannot do anything but match text.

## Writing a declarative rule

```yaml
# acme-rules.yml
rules:
  - id: ACME-001                  # PREFIX-NNN; the MCP- prefix is reserved for built-in rules
    name: Tool promises to run without confirmation
    category: security            # protocol | security | tools | schema | performance | quality (default: security)
    severity: medium              # info | low | medium | high | critical
    description: A tool description says the tool acts without asking the user first.   # required
    why: Tools that skip confirmation remove the human from the loop.                    # required
    recommendation: Remove "without confirmation" behaviour or mark the tool destructive. # required
    applies_to: [tool_description]   # tool_name | tool_description | parameter_description | instructions | resource | prompt | output
                                     # default: tool_description, parameter_description
    tools: ["acme_*"]                # optional glob(s) on tool names
    match:
      any:                           # 1-20 regular expressions; the rule fires if any matches
        - "\\bwithout (asking|confirmation)\\b"
      none:                          # optional: if any of these match the same text, the rule does not fire
        - "\\bnever\\b.{0,20}\\bwithout asking\\b"
      flags: i                       # default i; allowed: i m s u
```

A file may hold one rule, a list of rules, or `rules: [...]`. A directory loads every `.yml`, `.yaml` and `.json` file in it.

`description`, `why` and `recommendation` are **required**. Every shared rule must explain what it detects, why it matters and how to fix it, and those fields are shown in reports.

Use it:

```bash
mcp-detector scan --rules ./acme-rules.yml -- node build/index.js
```

```yaml
# mcp-detector.yml
community_rules: [./acme-rules.yml, ./team-rules/]
rules:
  ACME-001: high            # re-level or disable community rules like any other rule
  ACME-002: off
```

Matching works like the built-in rules: it runs on the text as written, after Unicode normalisation (zero-width characters removed, look-alike letters folded), and on decoded base64/hex blobs, so a rule cannot be evaded with the trivial tricks. Findings include the matched text as evidence.

### Regular-expression safety

Rules run on every scanned text, so a careless pattern must not be able to hang a scan. Patterns are refused when:

- they are longer than 300 characters or invalid;
- a repeated group contains a quantifier or alternation, such as `(a+)+`, `(a|b)*`, `(x?){20}`, which is the classic source of exponential backtracking (rewrite as `a+` or `(?:a|b)` without the outer repetition);
- they contain more than 4 open-ended repetitions (`*`, `+` or `{n,}`, outside character classes). Each extra one multiplies the worst-case matching time, so `.*.*.*.*.*x` is refused instantly without being run. Use bounded forms such as `.{0,40}` instead;
- they are measurably slow on small adversarial inputs (a final timing check, bounded in cost because of the limit above).

Matching is limited to the first 20,000 characters of each text. This is a best-effort guard, not a proof of safety. Review rule files from sources you do not trust, like any other configuration.

## Plugins

```js
// my-plugin.mjs
export default {
  id: "ACME-050", name: "…", category: "quality", severity: "low",
  description: "…", why: "…", recommendation: "…",
  check({ snapshot, config }) {
    return snapshot.tools.filter((t) => /* … */ false).map((t) => ({ tool: t.name, message: "…", evidence: "…" }));
  },
};
```

```yaml
# mcp-detector.yml
plugins: [./my-plugin.mjs]
```

```bash
mcp-detector scan --allow-plugins -- node build/index.js
```

**A plugin runs with your privileges.** The config file alone never loads one: if `plugins:` is set and `--allow-plugins` is not, MCP Detector prints a warning and skips them. That matters because you may scan a repository whose `mcp-detector.yml` you did not write.

Export one rule or an array. Rules must be pure functions of the snapshot: no network, no file access, no tool calls.

## Sharing rules

There is no hosted marketplace. A rule set is just a file or folder, so you can share it however you share code: a Git repository, a gist, an npm package containing YAML files. A good rule pack has:

1. A README saying what it detects and why.
2. Rule IDs under a prefix you own (`ACME-`, your org name).
3. For each rule, test samples: at least one text it must flag and one near-miss it must not.

To propose a rule for the built-in set, see [CONTRIBUTING.md](../CONTRIBUTING.md).
