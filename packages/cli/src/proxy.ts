import { spawn } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { createInterface } from "node:readline";
import {
  type SnarxEventInput,
  canonicalJson,
  findInvisibleUnicode,
  generateSigningKeyPair,
  sealBundle,
  sha256Hex,
} from "@snarx/core";

export interface ProxyOptions {
  command: string;
  args: string[];
  outPath: string;
  serverName: string;
  sign: boolean;
}

interface PendingRequest {
  method: string;
  toolName?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Transparently wraps a stdio MCP server, forwarding newline-delimited JSON-RPC frames
 * without modifying stdout, alerting on stderr for live rug-pulls / hidden Unicode,
 * and sealing a redacted, hash-chained .snarx bundle on exit.
 */
export async function runProxy(options: ProxyOptions): Promise<number> {
  const child = spawn(options.command, options.args, {
    stdio: ["pipe", "pipe", "inherit"],
  });

  const events: SnarxEventInput[] = [];
  const pending = new Map<string, PendingRequest>();
  const pinnedToolHashes = new Map<string, string>();
  let flushed = false;

  const inspectToolsListLive = async (tools: unknown[]) => {
    for (const tool of tools) {
      if (!isRecord(tool) || typeof tool.name !== "string") continue;
      const hash = await sha256Hex(canonicalJson(tool));
      const prev = pinnedToolHashes.get(tool.name);
      if (prev && prev !== hash) {
        process.stderr.write(
          `[snarx ALERT] SNX-02 MCP rug pull detected: tool "${tool.name}" on "${options.serverName}" mutated mid-session!\n`,
        );
      }
      pinnedToolHashes.set(tool.name, hash);
    }
  };

  const handleClientLine = (line: string) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    try {
      const msg: unknown = JSON.parse(trimmed);
      if (!isRecord(msg) || typeof msg.method !== "string") return;

      const method = msg.method;
      const idKey = msg.id !== undefined ? String(msg.id) : undefined;
      const params = isRecord(msg.params) ? msg.params : {};

      if (method === "tools/call") {
        const toolName = typeof params.name === "string" ? params.name : "unknown";
        if (idKey) pending.set(idKey, { method, toolName });
        events.push({
          timestamp: new Date().toISOString(),
          source: "mcp-proxy",
          serverName: options.serverName,
          kind: "tool_call",
          toolName,
          payload: params,
        });
      } else if (method === "tools/list") {
        if (idKey) pending.set(idKey, { method });
      }
    } catch {
      // Non-JSON framing is forwarded untouched without breaking the MCP pipe.
    }
  };

  const handleServerLine = async (line: string) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    try {
      const msg: unknown = JSON.parse(trimmed);
      if (!isRecord(msg) || msg.id === undefined) return;

      const req = pending.get(String(msg.id));
      if (!req) return;
      pending.delete(String(msg.id));

      const isError = isRecord(msg.error);
      const payload = isError
        ? (msg.error as Record<string, unknown>)
        : isRecord(msg.result)
          ? msg.result
          : { value: msg.result };

      const hidden = findInvisibleUnicode(trimmed);
      if (hidden.count > 0) {
        process.stderr.write(
          `[snarx ALERT] SNX-01 invisible Unicode (${hidden.codePoints.join(", ")}) detected in response from "${options.serverName}"!\n`,
        );
      }

      if (req.method === "tools/list" && !isError && Array.isArray(payload.tools)) {
        await inspectToolsListLive(payload.tools);
        events.push({
          timestamp: new Date().toISOString(),
          source: "mcp-proxy",
          serverName: options.serverName,
          kind: "tool_list",
          payload,
        });
      } else if (req.method === "tools/call") {
        const resultIsError = isError || payload.isError === true;
        const event: SnarxEventInput = {
          timestamp: new Date().toISOString(),
          source: "mcp-proxy",
          serverName: options.serverName,
          kind: "tool_result",
          isError: resultIsError,
          payload,
        };
        if (req.toolName !== undefined) {
          event.toolName = req.toolName;
        }
        events.push(event);
      }
    } catch {
      // Ignore non-JSON lines while preserving raw forwarding.
    }
  };

  const clientRl = createInterface({ input: process.stdin, crlfDelay: Number.POSITIVE_INFINITY });
  clientRl.on("line", (line) => {
    handleClientLine(line);
    if (child.stdin && !child.stdin.destroyed) {
      child.stdin.write(`${line}\n`);
    }
  });
  clientRl.on("close", () => {
    if (child.stdin && !child.stdin.destroyed) {
      child.stdin.end();
    }
  });

  const serverProcessing: Promise<void>[] = [];
  if (child.stdout) {
    const serverRl = createInterface({ input: child.stdout, crlfDelay: Number.POSITIVE_INFINITY });
    serverRl.on("line", (line) => {
      process.stdout.write(`${line}\n`);
      serverProcessing.push(handleServerLine(line));
    });
  }

  const flushBundle = async () => {
    if (flushed) return;
    flushed = true;
    await Promise.allSettled(serverProcessing);
    const keyPair = options.sign ? await generateSigningKeyPair() : undefined;
    const bundle = await sealBundle(events, keyPair ? { keyPair } : {});
    await writeFile(options.outPath, `${JSON.stringify(bundle, null, 2)}\n`, "utf8");
    process.stderr.write(
      `[snarx] Sealed ${bundle.events.length} event(s) (redacted=${bundle.redactedCount}, signed=${Boolean(bundle.signature)}) -> ${options.outPath}\n`,
    );
  };

  const forwardSignal = (sig: NodeJS.Signals) => {
    if (!child.killed) {
      child.kill(sig);
    }
  };
  process.on("SIGINT", forwardSignal);
  process.on("SIGTERM", forwardSignal);

  const exitCode = await new Promise<number>((resolve) => {
    child.on("error", (err) => {
      process.stderr.write(`snarx proxy: failed to spawn "${options.command}": ${err.message}\n`);
      resolve(127);
    });
    child.on("close", (code) => {
      resolve(code ?? 0);
    });
  });

  process.off("SIGINT", forwardSignal);
  process.off("SIGTERM", forwardSignal);
  clientRl.close();
  await flushBundle();

  return exitCode;
}
