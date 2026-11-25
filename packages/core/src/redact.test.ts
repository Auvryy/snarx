import { describe, expect, it } from "vitest";
import { redactSecrets } from "./index.js";

describe("redactSecrets", () => {
  it("redacts API keys and AWS access keys before signing", () => {
    const sample = "OPENAI=sk-proj1234567890abcdef AWS=AKIAIOSFODNN7EXAMPLE";
    const result = redactSecrets(sample);

    expect(result.redacted).toBe("OPENAI=[REDACTED:OPENAI_KEY] AWS=[REDACTED:AWS_ACCESS_KEY]");
    expect(result.matches).toEqual(["OPENAI_KEY", "AWS_ACCESS_KEY"]);
  });

  it("leaves safe strings untouched", () => {
    const result = redactSecrets("normal tool output without secrets");
    expect(result.redacted).toBe("normal tool output without secrets");
    expect(result.matches).toEqual([]);
  });
});
