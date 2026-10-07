# Security Policy

## Reporting a vulnerability in MCP Detector

Please **do not open a public issue** for security problems in MCP Detector itself (for example: a malicious server being able to make the scanner execute code, write files, or leak the credentials you passed it).

Report privately using GitHub's "Report a vulnerability" button on the repository's Security tab. Include the version, a description, and a proof of concept if you have one. We aim to acknowledge reports within 5 business days.

## Threat model

MCP Detector connects to servers you point it at and reads what they send back. It treats **all server output as untrusted data**:

- It never executes, evaluates or follows instructions found in server text.
- It does not call tools unless you pass `--active`, and even then only tools that look read-only (see [docs/security.md](docs/security.md)).
- Secrets found in server text are redacted in reports.
- Scanning a **stdio** server runs the command you give it, with your privileges. Only scan code you are willing to run.

## False positives and false negatives

Findings are heuristic indicators. Reports of detection bugs (a rule firing wrongly, or missing an obvious case) are welcome as normal issues; please include a minimal tool definition.
