export const SNARX_SCHEMA_VERSION = "0.1.0" as const;

export type AgentSource = "claude-code" | "codex" | "agy" | "gemini-cli" | "mcp-proxy";

export type SnarxEventKind =
  | "tool_list"
  | "tool_call"
  | "tool_result"
  | "hook_decision"
  | "message";

export interface SnarxEventInput {
  timestamp: string;
  source: AgentSource;
  kind: SnarxEventKind;
  actor?: string;
  toolName?: string;
  serverName?: string;
  tokens?: number;
  isError?: boolean;
  payload: Record<string, unknown>;
}

export interface SnarxEvent extends SnarxEventInput {
  seq: number;
  prevHash: string;
  hash: string;
}

export interface SnarxBundle {
  schemaVersion: typeof SNARX_SCHEMA_VERSION;
  bundleId: string;
  createdAt: string;
  redacted: boolean;
  redactedCount: number;
  events: SnarxEvent[];
  rootHash: string;
  signature?: {
    algorithm: "Ed25519";
    publicKeyBase64: string;
    valueBase64: string;
  };
}

export type FindingSeverity = "critical" | "high" | "medium" | "low";

export interface SecurityFinding {
  ruleId: "SNX-01" | "SNX-02" | "SNX-03" | "SNX-04" | "SNX-05";
  title: string;
  severity: FindingSeverity;
  seq: number;
  summary: string;
  evidence?: Record<string, unknown>;
}
