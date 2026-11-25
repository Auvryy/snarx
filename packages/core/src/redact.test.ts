import { describe, expect, it } from "vitest";
import { redactSecrets, redactUnknown } from "./redact.js";

describe("redactSecrets & redactUnknown", () => {
  it("redacts OpenAI, Anthropic, Google, AWS, and DB URL secrets with accurate counts", () => {
    // Build synthetic test keys dynamically so GitHub Secret Scanning never fires false alerts
    const fakeAnthropic = ["sk-ant", "api03-1234567890abcdef"].join("-");
    const fakeOpenAi = ["sk", "proj1234567890abcdef"].join("-");
    const fakeGoogle = ["AIza", "SyA1234567890abcdefghijkLMNOPQRSTUV"].join("");
    const fakeAws = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
    const sample = [
      `ANTHROPIC=${fakeAnthropic}`,
      `OPENAI=${fakeOpenAi}`,
      `GOOGLE=${fakeGoogle}`,
      `AWS=${fakeAws}`,
      "DB=postgres://admin:supersecret@db.internal:5432/app",
    ].join(" ");

    const result = redactSecrets(sample);

    expect(result.redacted).toContain("[REDACTED:ANTHROPIC_KEY]");
    expect(result.redacted).toContain("[REDACTED:OPENAI_KEY]");
    expect(result.redacted).toContain("[REDACTED:GOOGLE_API_KEY]");
    expect(result.redacted).toContain("[REDACTED:AWS_ACCESS_KEY]");
    expect(result.redacted).toContain("[REDACTED:DATABASE_URL]");
    expect(result.matchCount).toBe(5);
  });

  it("counts multiple occurrences of the same secret type", () => {
    const sample = "a=sk-first1234567890abcd b=sk-second1234567890abc";
    const result = redactSecrets(sample);
    expect(result.matchCount).toBe(2);
    expect(result.matches).toEqual(["OPENAI_KEY"]);
  });

  it("handles circular object references without throwing", () => {
    const obj: Record<string, unknown> = { token: "sk-circular1234567890ab" };
    obj.self = obj;

    const res = redactUnknown(obj);
    expect(res.count).toBe(1);
    expect((res.value as Record<string, unknown>).self).toBe("[CIRCULAR]");
  });

  it("leaves safe strings untouched", () => {
    const result = redactSecrets("normal tool output without secrets");
    expect(result.redacted).toBe("normal tool output without secrets");
    expect(result.matches).toEqual([]);
    expect(result.matchCount).toBe(0);
  });
});
