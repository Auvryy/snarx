export const SNARX_SCHEMA_VERSION = "0.1.0" as const;

export type AgentSource = "claude-code" | "codex" | "agy" | "gemini-cli" | "mcp-proxy";

export interface SnarxEvent {
  seq: number;
  timestamp: string;
  source: AgentSource;
  kind: "tool_list" | "tool_call" | "tool_result" | "hook_decision" | "message";
  payload: Record<string, unknown>;
  prevHash: string;
  hash: string;
}

const SECRET_PATTERNS: readonly { label: string; regex: RegExp }[] = [
  { label: "OPENAI_KEY", regex: /\bsk-[A-Za-z0-9_-]{16,}\b/g },
  { label: "GITHUB_TOKEN", regex: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g },
  { label: "AWS_ACCESS_KEY", regex: /\bAKIA[0-9A-Z]{16}\b/g },
  {
    label: "PRIVATE_KEY",
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  },
];

export interface RedactResult {
  redacted: string;
  matches: string[];
}

/**
 * Scrubs known credential patterns prior to hashing, signing, or exporting a .snarx bundle.
 */
export function redactSecrets(input: string): RedactResult {
  let output = input;
  const matches: string[] = [];

  for (const { label, regex } of SECRET_PATTERNS) {
    regex.lastIndex = 0;
    if (regex.test(output)) {
      matches.push(label);
      regex.lastIndex = 0;
      output = output.replace(regex, `[REDACTED:${label}]`);
    }
  }

  return { redacted: output, matches };
}
