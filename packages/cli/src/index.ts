#!/usr/bin/env node
import { basename } from "node:path";
import { SNARX_SCHEMA_VERSION, redactSecrets } from "@snarx/core";
import { runProxy } from "./proxy.js";
import { executeScan } from "./scan.js";

function printHelp(): void {
  console.log(`snarx v${SNARX_SCHEMA_VERSION} — Local-first AI agent security sandbox & debugger

Usage:
  snarx scan <file.snarx> [--json]
      Verify bundle integrity and run deterministic security detectors.

  snarx proxy [--out <file.snarx>] [--server <name>] [--no-sign] -- <mcp-cmd> [args...]
      Transparently wrap a stdio MCP server, alert on live rug pulls/hidden Unicode,
      redact secrets, and write a signed .snarx trace bundle on exit.

  snarx redact-check <text>
      Verify secret redaction locally.

  snarx --version | --help
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === "--help" || command === "-h" || command === "help") {
    printHelp();
    process.exit(0);
  }

  if (command === "--version" || command === "-v") {
    console.log(`snarx v${SNARX_SCHEMA_VERSION}`);
    process.exit(0);
  }

  if (command === "redact-check") {
    const input = args.slice(1).join(" ");
    const result = redactSecrets(input);
    console.log(JSON.stringify(result, null, 2));
    process.exit(0);
  }

  if (command === "scan") {
    const rest = args.slice(1);
    const json = rest.includes("--json");
    const filePath = rest.find((arg) => !arg.startsWith("-"));
    if (!filePath) {
      console.error("snarx scan: missing <file.snarx> argument");
      process.exit(2);
    }
    const result = await executeScan(filePath, { json });
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    process.exit(result.exitCode);
  }

  if (command === "proxy") {
    const rest = args.slice(1);
    const sepIndex = rest.indexOf("--");
    if (sepIndex === -1 || sepIndex === rest.length - 1) {
      console.error("snarx proxy: expected `-- <mcp-command> [args...]`");
      process.exit(2);
    }

    const flagArgs = rest.slice(0, sepIndex);
    const cmdParts = rest.slice(sepIndex + 1);
    const targetCmd = cmdParts[0];
    if (!targetCmd) {
      console.error("snarx proxy: missing MCP command after `--`");
      process.exit(2);
    }

    let outPath = `snarx-session-${Date.now()}.snarx`;
    let serverName = basename(targetCmd);
    let sign = true;

    for (let i = 0; i < flagArgs.length; i++) {
      const flag = flagArgs[i];
      if (flag === "--out" && flagArgs[i + 1]) {
        outPath = flagArgs[i + 1] ?? outPath;
        i += 1;
      } else if (flag === "--server" && flagArgs[i + 1]) {
        serverName = flagArgs[i + 1] ?? serverName;
        i += 1;
      } else if (flag === "--no-sign") {
        sign = false;
      }
    }

    const exitCode = await runProxy({
      command: targetCmd,
      args: cmdParts.slice(1),
      outPath,
      serverName,
      sign,
    });
    process.exit(exitCode);
  }

  console.error(`snarx: unknown command "${command}". Run "snarx --help" for usage.`);
  process.exit(2);
}

void main();
