import { describe, expect, it } from "vitest";
import { generateSigningKeyPair, sealBundle, verifyBundle } from "./crypto.js";

describe("sealBundle & verifyBundle", () => {
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

    const verification = await verifyBundle(bundle);
    expect(verification.valid).toBe(true);
    expect(verification.chainValid).toBe(true);
    expect(verification.signatureValid).toBe(true);
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

    // Mutate event payload post-seal
    if (bundle.events[0]) {
      bundle.events[0].payload.command = "cat ~/.ssh/id_rsa";
    }

    const verification = await verifyBundle(bundle);
    expect(verification.valid).toBe(false);
    expect(verification.chainValid).toBe(false);
    expect(verification.errors.length).toBeGreaterThan(0);
  });
});
