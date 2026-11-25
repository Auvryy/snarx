import { describe, expect, it } from "vitest";
import {
  canonicalJson,
  generateSigningKeyPair,
  parseBundle,
  sealBundle,
  verifyBundle,
} from "./crypto.js";

describe("canonicalJson, parseBundle, sealBundle & verifyBundle", () => {
  it("serializes arrays with undefined slots as valid JSON null", () => {
    expect(canonicalJson({ b: 1, a: [1, undefined, 2] })).toBe('{"a":[1,null,2],"b":1}');
  });

  it("redacts secrets before hashing and verifies Ed25519 signature", async () => {
    const keyPair = await generateSigningKeyPair();
    const bundle = await sealBundle(
      [
        {
          timestamp: "2026-11-25T10:00:00Z",
          source: "mcp-proxy",
          kind: "tool_result",
          toolName: "read_file",
          payload: { content: "API_KEY=sk-secret1234567890abcdef" },
        },
      ],
      { keyPair, bundleId: "test-bundle-1" },
    );

    expect(bundle.redacted).toBe(true);
    expect(bundle.redactedCount).toBe(1);
    expect(bundle.events[0]?.payload.content).toBe("API_KEY=[REDACTED:OPENAI_KEY]");
    expect(bundle.signature?.algorithm).toBe("Ed25519");

    const parsed = parseBundle(JSON.stringify(bundle));
    expect(parsed.ok).toBe(true);

    const verification = await verifyBundle(bundle);
    expect(verification.valid).toBe(true);
    expect(verification.chainValid).toBe(true);
    expect(verification.signatureValid).toBe(true);
  });

  it("verifies empty bundles cleanly", async () => {
    const bundle = await sealBundle([]);
    const verification = await verifyBundle(bundle);
    expect(verification.valid).toBe(true);
    expect(verification.chainValid).toBe(true);
    expect(verification.signatureValid).toBeNull();
  });

  it("detects tampering when an event payload is altered after sealing", async () => {
    const keyPair = await generateSigningKeyPair();
    const bundle = await sealBundle(
      [
        {
          timestamp: "2026-11-25T10:00:00Z",
          source: "claude-code",
          kind: "tool_call",
          toolName: "bash",
          payload: { command: "ls -la" },
        },
      ],
      { keyPair },
    );

    if (bundle.events[0]) {
      bundle.events[0].payload.command = "cat ~/.ssh/id_rsa";
    }

    const verification = await verifyBundle(bundle);
    expect(verification.valid).toBe(false);
    expect(verification.chainValid).toBe(false);
    expect(verification.errors.length).toBeGreaterThan(0);
  });

  it("detects forged Ed25519 signature even when hash chain is intact", async () => {
    const keyPair = await generateSigningKeyPair();
    const bundle = await sealBundle(
      [
        {
          timestamp: "2026-11-25T10:00:00Z",
          source: "agy",
          kind: "message",
          payload: { text: "hello" },
        },
      ],
      { keyPair },
    );

    if (bundle.signature) {
      bundle.signature.valueBase64 = btoa("0".repeat(64));
    }

    const verification = await verifyBundle(bundle);
    expect(verification.chainValid).toBe(true);
    expect(verification.signatureValid).toBe(false);
    expect(verification.valid).toBe(false);
  });

  it("rejects malformed untrusted JSON in parseBundle", () => {
    expect(parseBundle("not json").ok).toBe(false);
    expect(parseBundle("{}").ok).toBe(false);
    expect(
      parseBundle(
        JSON.stringify({
          schemaVersion: "9.9.9",
          bundleId: "x",
          createdAt: "now",
          rootHash: "0".repeat(64),
          events: [],
        }),
      ).ok,
    ).toBe(false);
  });
});
