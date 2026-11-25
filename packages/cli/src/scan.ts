import { readFile } from "node:fs/promises";
import { parseBundle, scanBundle, summarizeBundle } from "@snarx/core";

export interface ScanCommandOptions {
  json?: boolean;
}

export interface ScanCommandOutput {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export async function executeScan(
  filePath: string,
  options: ScanCommandOptions = {},
): Promise<ScanCommandOutput> {
  let raw: string;
  try {
    raw = await readFile(filePath, "utf8");
  } catch (err) {
    return {
      exitCode: 2,
      stdout: "",
      stderr: `snarx scan: failed to read "${filePath}": ${err instanceof Error ? err.message : String(err)}\n`,
    };
  }

  const parsed = parseBundle(raw);
  if (!parsed.ok) {
    return {
      exitCode: 2,
      stdout: "",
      stderr: `snarx scan: invalid .snarx bundle — ${parsed.error}\n`,
    };
  }

  const findings = await scanBundle(parsed.bundle);
  const summary = summarizeBundle(parsed.bundle, findings);
  const hasHighOrCritical =
    summary.findingsBySeverity.critical > 0 || summary.findingsBySeverity.high > 0;
  const exitCode = hasHighOrCritical ? 1 : 0;

  if (options.json) {
    return {
      exitCode,
      stdout: `${JSON.stringify({ summary, findings }, null, 2)}\n`,
      stderr: "",
    };
  }

  const lines: string[] = [
    `snarx scan — ${filePath}`,
    `Bundle: ${summary.bundleId} | Events: ${summary.eventCount} | Tokens: ${summary.totalTokens} | Redacted: ${summary.redactedCount}`,
    `Findings: ${findings.length} (critical=${summary.findingsBySeverity.critical}, high=${summary.findingsBySeverity.high}, medium=${summary.findingsBySeverity.medium}, low=${summary.findingsBySeverity.low})`,
  ];

  if (findings.length === 0) {
    lines.push("Status: CLEAN — no security findings detected.");
  } else {
    lines.push("");
    for (const f of findings) {
      lines.push(
        `  [${f.severity.toUpperCase()}] ${f.ruleId} (seq #${f.seq}) ${f.title}: ${f.summary}`,
      );
    }
  }

  return {
    exitCode,
    stdout: `${lines.join("\n")}\n`,
    stderr: "",
  };
}
