const SECRET_PATTERNS: readonly { label: string; regex: RegExp }[] = [
  { label: "OPENAI_KEY", regex: /\bsk-[A-Za-z0-9_-]{16,}\b/g },
  { label: "GITHUB_TOKEN", regex: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g },
  { label: "AWS_ACCESS_KEY", regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { label: "BEARER_TOKEN", regex: /\bBearer\s+[A-Za-z0-9._-]{20,}\b/g },
  {
    label: "PRIVATE_KEY",
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  },
];

export interface RedactResult {
  redacted: string;
  matches: string[];
}

/**
 * Scrubs known credential patterns prior to hashing, signing, or exporting a .snarx bundle.
 */
export function redactSecrets(input: string): RedactResult {
  let output = input;
  const matches: string[] = [];

  for (const { label, regex } of SECRET_PATTERNS) {
    regex.lastIndex = 0;
    if (regex.test(output)) {
      matches.push(label);
      regex.lastIndex = 0;
      output = output.replace(regex, `[REDACTED:${label}]`);
    }
  }

  return { redacted: output, matches };
}

export function redactUnknown(value: unknown): { value: unknown; count: number } {
  if (typeof value === "string") {
    const res = redactSecrets(value);
    return { value: res.redacted, count: res.matches.length };
  }

  if (Array.isArray(value)) {
    let count = 0;
    const next = value.map((item) => {
      const res = redactUnknown(item);
      count += res.count;
      return res.value;
    });
    return { value: next, count };
  }

  if (value !== null && typeof value === "object") {
    let count = 0;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      const res = redactUnknown(v);
      count += res.count;
      out[k] = res.value;
    }
    return { value: out, count };
  }

  return { value, count: 0 };
}
