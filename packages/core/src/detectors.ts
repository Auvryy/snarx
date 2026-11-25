import { canonicalJson, sha256Hex, verifyBundle } from "./crypto.js";
import type { SecurityFinding, SnarxBundle } from "./schema.js";

const SENSITIVE_PATH_RE =
  /(?:~\/|\$HOME\/|\/home\/[^/\s]+\/)\.(?:ssh|aws|gnupg|env)\b|\/etc\/shadow\b/i;

/**
 * Detects invisible Unicode characters commonly used for hidden prompt injection:
 * - Zero-width characters: U+200B..U+200D, U+FEFF
 * - Bidi override/isolate controls: U+202A..U+202E, U+2066..U+2069
 * - Unicode Tag block: U+E0000..U+E007F
 */
export function detectInvisibleUnicode(text: string): boolean {
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
      return true;
    }
  }
  return false;
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
  let consecutiveErrorKey: string | null = null;
  let consecutiveErrorCount = 0;

  for (const ev of bundle.events) {
    const serialized = JSON.stringify(ev.payload);

    // SNX-01: Invisible Unicode prompt injection
    if (detectInvisibleUnicode(serialized)) {
      findings.push({
        ruleId: "SNX-01",
        title: "Hidden Unicode Prompt Injection",
        severity: "high",
        seq: ev.seq,
        summary: `Invisible Unicode control/tag characters detected in ${ev.kind}${ev.toolName ? ` (${ev.toolName})` : ""}.`,
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
    if (ev.kind === "tool_call" && SENSITIVE_PATH_RE.test(serialized)) {
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
      if (key === consecutiveErrorKey) {
        consecutiveErrorCount += 1;
      } else {
        consecutiveErrorKey = key;
        consecutiveErrorCount = 1;
      }
      if (consecutiveErrorCount === 3) {
        findings.push({
          ruleId: "SNX-04",
          title: "Runaway Failing Tool Loop",
          severity: "medium",
          seq: ev.seq,
          summary: `Tool "${ev.toolName ?? "unknown"}" failed identically 3+ consecutive times.`,
        });
      }
    } else if (ev.kind === "tool_result") {
      consecutiveErrorKey = null;
      consecutiveErrorCount = 0;
    }
  }

  return findings;
}
