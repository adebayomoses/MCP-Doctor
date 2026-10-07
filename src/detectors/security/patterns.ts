export interface Pattern {
  id: string;
  label: string;
  re: RegExp;
}

/** Instructions aimed at overriding the model's behaviour. */
export const PROMPT_INJECTION_PATTERNS: Pattern[] = [
  { id: "ignore-previous", label: "tells the model to ignore previous instructions", re: /\b(ignore|disregard|forget|override)\b[^.\n]{0,30}\b(previous|prior|above|earlier|all|any|system)\b[^.\n]{0,20}\b(instructions?|prompts?|rules?|guidelines?|context)\b/i },
  { id: "new-instructions", label: "introduces replacement instructions", re: /\b(new|updated|real|actual|secret) (instructions?|system prompt|rules)\s*[:\-]/i },
  { id: "role-override", label: "tries to reassign the model's role", re: /\byou (must|should|are now|will now|have to)\b[^.\n]{0,30}\b(act as|pretend|behave as|obey|follow only|ignore)\b/i },
  { id: "conceal", label: "asks the model to hide something from the user", re: /\b(do not|don't|never|without)\b[^.\n]{0,25}\b(tell|inform|notify|mention|reveal|show|alert)\b[^.\n]{0,20}\b(the )?user\b/i },
  { id: "reveal-prompt", label: "asks for the system prompt or hidden context", re: /\b(reveal|print|output|repeat|leak|show)\b[^.\n]{0,25}\b(system prompt|hidden (instructions|prompt)|your instructions)\b/i },
  { id: "jailbreak", label: "contains jailbreak phrasing", re: /\b(jailbreak|DAN mode|developer mode enabled|bypass (all )?(safety|restrictions|filters|guardrails))\b/i },
  { id: "chat-markers", label: "contains chat-template control tokens", re: /(<\|(im_start|im_end|system|assistant|user)\|>|\[\/?INST\]|<<SYS>>|\n\s*(system|assistant)\s*:\s)/i },
];

/** Metadata that tries to steer the model toward unsafe actions (tool poisoning). */
export const TOOL_POISONING_PATTERNS: Pattern[] = [
  { id: "important-tag", label: "uses hidden-instruction tags (e.g. <IMPORTANT>)", re: /<\s*(important|system|instructions?|secret|hidden|admin)\s*>/i },
  { id: "html-comment", label: "contains an HTML comment that the user will not see", re: /<!--[\s\S]{0,400}?-->/ },
  { id: "sensitive-file", label: "references sensitive files or credentials", re: /(~\/\.ssh|\bid_(rsa|ed25519|ecdsa)\b|\.aws\/credentials|\.npmrc|\.netrc|\/etc\/(passwd|shadow)|\bmcp\.json\b|claude_desktop_config|\.env\b|\bkeychain\b|\bprivate key\b)/i },
  { id: "before-using", label: "demands a side action before the tool is used", re: /\b(before|prior to|first)\b[^.\n]{0,30}\b(using|calling|invoking|running)\b[^.\n]{0,30}\b(this tool|this function|any tool|the tool)\b[^.\n]{0,60}\b(you must|must|should|need to|read|send|call|fetch|include)\b/i },
  { id: "exfiltrate", label: "asks for data to be sent elsewhere", re: /\b(send|post|upload|forward|transmit|exfiltrate|leak|email|include|pass)\b[^.\n]{0,50}\b(to|in|via|into)\b[^.\n]{0,30}\b(https?:\/\/|webhook|this url|the url|remote server|attacker|parameter|sidenote|side note)/i },
  { id: "tool-shadowing", label: "tries to change how other tools behave", re: /\b(when|if|whenever)\b[^.\n]{0,40}\b(other|another|any|the)\b[^.\n]{0,15}\b(tool|server|function)\b[^.\n]{0,40}\b(is )?(used|called|invoked)\b|\binstead of (using|calling)\b[^.\n]{0,30}\b(tool|function)\b/i },
  { id: "do-not-mention", label: "asks the model not to reveal these instructions", re: /\b(do not|don't|never)\b[^.\n]{0,20}\b(mention|reveal|disclose|tell|show)\b[^.\n]{0,30}\b(this|these|it)\b/i },
  { id: "always-call", label: "forces the model to always call this tool", re: /\b(you (must|should) )?always (call|use|invoke|run)\b[^.\n]{0,25}\b(this tool|this function)\b[^.\n]{0,25}\b(first|before|after|every|each)\b/i },
];

/** Invisible or direction-changing characters used to hide text from reviewers. */
export const HIDDEN_CHARS_RE = /[​-‏‪-‮⁠-⁤⁦-⁩﻿\u{E0000}-\u{E007F}]/u;

export interface SecretPattern {
  label: string;
  re: RegExp;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  { label: "AWS access key ID", re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { label: "GitHub token", re: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b/ },
  { label: "Slack token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { label: "Private key block", re: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----/ },
  { label: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { label: "Stripe live key", re: /\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b/ },
  { label: "Anthropic/OpenAI-style API key", re: /\bsk-(ant-)?[A-Za-z0-9_-]{32,}\b/ },
  { label: "JSON Web Token", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { label: "Credentials in URL", re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:[^\s@/]{4,}@[^\s/]+/i },
  {
    label: "Hard-coded secret assignment",
    re: /\b(api[_-]?key|secret|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret)\b["']?\s*[:=]\s*["']?(?!your|<|\$|\{|xxx|\*|example|changeme|placeholder|test)[A-Za-z0-9_\-+/=]{12,}/i,
  },
];

/** Show enough of a secret to identify it without reproducing it. */
export function redact(s: string): string {
  const t = s.trim();
  if (t.length <= 8) return "***";
  return `${t.slice(0, 4)}…[redacted ${t.length} chars]`;
}
