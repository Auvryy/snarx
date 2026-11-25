const SECRET_PATTERNS: readonly { label: string; regex: RegExp }[] = [
  { label: "ANTHROPIC_KEY", regex: /\bsk-ant-[A-Za-z0-9_-]{16,}\b/g },
  { label: "OPENAI_KEY", regex: /\bsk-[A-Za-z0-9_-]{16,}\b/g },
  { label: "GOOGLE_API_KEY", regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { label: "GITHUB_TOKEN", regex: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g },
  { label: "AWS_ACCESS_KEY", regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { label: "BEARER_TOKEN", regex: /\bBearer\s+[A-Za-z0-9._-]{20,}\b/g },
  {
    label: "DATABASE_URL",
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s/]+:[^@\s]+@[^\s"']+/gi,
  },
  {
    label: "PRIVATE_KEY",
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  },
];

export interface RedactResult {
  redacted: string;
  matches: string[];
  matchCount: number;
}

/**
 * Scrubs known credential patterns prior to hashing, signing, or exporting a .snarx bundle.
 */
export function redactSecrets(input: string): RedactResult {
  let output = input;
  const matches: string[] = [];
  let matchCount = 0;

  for (const { label, regex } of SECRET_PATTERNS) {
    regex.lastIndex = 0;
    const found = output.match(regex);
    if (found && found.length > 0) {
      matches.push(label);
      matchCount += found.length;
      regex.lastIndex = 0;
      output = output.replace(regex, `[REDACTED:${label}]`);
    }
  }

  return { redacted: output, matches, matchCount };
}

function redactUnknownInner(
  value: unknown,
  seen: WeakSet<object>,
): { value: unknown; count: number } {
  if (typeof value === "string") {
    const res = redactSecrets(value);
    return { value: res.redacted, count: res.matchCount };
  }

  if (Array.isArray(value)) {
    if (seen.has(value)) {
      return { value: "[CIRCULAR]", count: 0 };
    }
    seen.add(value);
    let count = 0;
    const next = value.map((item) => {
      const res = redactUnknownInner(item, seen);
      count += res.count;
      return res.value;
    });
    return { value: next, count };
  }

  if (value !== null && typeof value === "object") {
    if (seen.has(value)) {
      return { value: "[CIRCULAR]", count: 0 };
    }
    seen.add(value);
    let count = 0;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      const res = redactUnknownInner(v, seen);
      count += res.count;
      out[k] = res.value;
    }
    return { value: out, count };
  }

  return { value, count: 0 };
}

export function redactUnknown(value: unknown): { value: unknown; count: number } {
  return redactUnknownInner(value, new WeakSet<object>());
}
