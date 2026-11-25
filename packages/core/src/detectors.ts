import { canonicalJson, sha256Hex, verifyBundle } from "./crypto.js";
import type { FindingSeverity, SecurityFinding, SnarxBundle } from "./schema.js";

const SENSITIVE_HOME_PATH_RE =
  /(?:~\/|\$HOME\/|\/home\/[^/\s]+\/)\.(?:ssh|aws|gnupg)\b|\/etc\/shadow\b/i;

// Matches .env, ./.env, /app/.env.local, .env.production — but ignores .env.example / .env.sample / .env.template
const SENSITIVE_ENV_FILE_RE =
  /(?:^|["'\s/\\])\.env(?:\.(?!example\b|sample\b|template\b)[A-Za-z0-9_-]+)?(?=$|["'\s])/i;

export interface InvisibleUnicodeMatch {
  count: number;
  codePoints: string[];
}

/**
 * Finds invisible Unicode characters commonly used for hidden prompt injection:
 * - Zero-width characters: U+200B..U+200D, U+FEFF
 * - Bidi override/isolate controls: U+202A..U+202E, U+2066..U+2069
 * - Unicode Tag block: U+E0000..U+E007F
 */
export function findInvisibleUnicode(text: string): InvisibleUnicodeMatch {
  const uniqueCodePoints = new Set<string>();
  let count = 0;

  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp === undefined) continue;
    if (
      (cp >= 0x200b && cp <= 0x200d) ||
      cp === 0xfeff ||
      (cp >= 0x202a && cp <= 0x202e) ||
      (cp >= 0x2066 && cp <= 0x2069) ||
      (cp >= 0xe0000 && cp <= 0xe007f)
    ) {
      count += 1;
      uniqueCodePoints.add(`U+${cp.toString(16).toUpperCase().padStart(4, "0")}`);
    }
  }

  return { count, codePoints: Array.from(uniqueCodePoints) };
}

export function detectInvisibleUnicode(text: string): boolean {
  return findInvisibleUnicode(text).count > 0;
}

export function isSensitivePathAccess(serializedPayload: string): boolean {
  return (
    SENSITIVE_HOME_PATH_RE.test(serializedPayload) || SENSITIVE_ENV_FILE_RE.test(serializedPayload)
  );
}

/**
 * Evaluates all deterministic, zero-LLM security rules against a .snarx bundle.
 */
export async function scanBundle(bundle: SnarxBundle): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];

  // SNX-05: Cryptographic hash-chain & Ed25519 signature integrity
  const integrity = await verifyBundle(bundle);
  if (!integrity.valid) {
    findings.push({
      ruleId: "SNX-05",
      title: "Trace Tampering or Integrity Failure",
      severity: "critical",
      seq: bundle.events.length,
      summary: integrity.errors.join("; "),
      evidence: {
        chainValid: integrity.chainValid,
        signatureValid: integrity.signatureValid,
      },
    });
  }

  const pinnedToolHashes = new Map<string, string>();
  let streakKey: string | null = null;
  let streakTool = "unknown";
  let streakCount = 0;
  let streakLastSeq = 0;

  const flushErrorStreak = () => {
    if (streakCount >= 3) {
      findings.push({
        ruleId: "SNX-04",
        title: "Runaway Failing Tool Loop",
        severity: "medium",
        seq: streakLastSeq,
        summary: `Tool "${streakTool}" failed identically ${streakCount} consecutive times.`,
        evidence: { toolName: streakTool, repeatCount: streakCount },
      });
    }
    streakKey = null;
    streakTool = "unknown";
    streakCount = 0;
    streakLastSeq = 0;
  };

  for (const ev of bundle.events) {
    const serialized = JSON.stringify(ev.payload);

    // SNX-01: Invisible Unicode prompt injection
    const hidden = findInvisibleUnicode(serialized);
    if (hidden.count > 0) {
      findings.push({
        ruleId: "SNX-01",
        title: "Hidden Unicode Prompt Injection",
        severity: "high",
        seq: ev.seq,
        summary: `Detected ${hidden.count} invisible Unicode character(s) (${hidden.codePoints.join(", ")}) in ${ev.kind}${ev.toolName ? ` (${ev.toolName})` : ""}.`,
        evidence: { count: hidden.count, codePoints: hidden.codePoints },
      });
    }

    // SNX-02: Continuous MCP tools/list SHA-256 hash-pinning (rug pull detection)
    if (ev.kind === "tool_list" && Array.isArray(ev.payload.tools)) {
      const server = ev.serverName ?? "default";
      for (const tool of ev.payload.tools) {
        if (tool && typeof tool === "object" && "name" in tool && typeof tool.name === "string") {
          const key = `${server}::${tool.name}`;
          const hash = await sha256Hex(canonicalJson(tool));
          const previous = pinnedToolHashes.get(key);
          if (previous && previous !== hash) {
            findings.push({
              ruleId: "SNX-02",
              title: "MCP Supply-Chain Tool Rug Pull",
              severity: "critical",
              seq: ev.seq,
              summary: `Tool "${tool.name}" on server "${server}" mutated its schema/description mid-session.`,
              evidence: { server, toolName: tool.name, previousHash: previous, newHash: hash },
            });
          }
          pinnedToolHashes.set(key, hash);
        }
      }
    }

    // SNX-03: Sensitive credential path access or secret exfiltration
    if (ev.kind === "tool_call" && isSensitivePathAccess(serialized)) {
      findings.push({
        ruleId: "SNX-03",
        title: "Sensitive Credential Path Access",
        severity: "critical",
        seq: ev.seq,
        summary: `Tool call "${ev.toolName ?? "unknown"}" targeted a sensitive credential path (~/.ssh, ~/.aws, ~/.gnupg, or .env).`,
      });
    }

    // SNX-04: Runaway failing tool loop
    if (ev.kind === "tool_result" && ev.isError) {
      const key = `${ev.toolName ?? "unknown"}::${serialized}`;
      if (key === streakKey) {
        streakCount += 1;
        streakLastSeq = ev.seq;
      } else {
        flushErrorStreak();
        streakKey = key;
        streakTool = ev.toolName ?? "unknown";
        streakCount = 1;
        streakLastSeq = ev.seq;
      }
    } else if (ev.kind === "tool_result") {
      flushErrorStreak();
    }
  }

  flushErrorStreak();
  return findings;
}

export interface BundleSummary {
  bundleId: string;
  eventCount: number;
  totalTokens: number;
  redactedCount: number;
  servers: string[];
  tools: string[];
  findingsBySeverity: Record<FindingSeverity, number>;
}

/**
 * Computes high-level metrics for CLI scan output and the browser workbench header.
 */
export function summarizeBundle(
  bundle: SnarxBundle,
  findings: readonly SecurityFinding[],
): BundleSummary {
  const servers = new Set<string>();
  const tools = new Set<string>();
  let totalTokens = 0;

  for (const ev of bundle.events) {
    if (ev.serverName) servers.add(ev.serverName);
    if (ev.toolName) tools.add(ev.toolName);
    if (typeof ev.tokens === "number" && Number.isFinite(ev.tokens)) {
      totalTokens += ev.tokens;
    }
  }

  const findingsBySeverity: Record<FindingSeverity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const finding of findings) {
    findingsBySeverity[finding.severity] += 1;
  }

  return {
    bundleId: bundle.bundleId,
    eventCount: bundle.events.length,
    totalTokens,
    redactedCount: bundle.redactedCount,
    servers: Array.from(servers).sort(),
    tools: Array.from(tools).sort(),
    findingsBySeverity,
  };
}
