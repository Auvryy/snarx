import { redactUnknown } from "./redact.js";
import {
  SNARX_SCHEMA_VERSION,
  type SnarxBundle,
  type SnarxEvent,
  type SnarxEventInput,
} from "./schema.js";

const GENESIS_HASH = "0".repeat(64);
const encoder = new TextEncoder();

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => (item === undefined ? "null" : canonicalJson(item))).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => a.localeCompare(b));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}

export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(input));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function generateSigningKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
}

export interface SealOptions {
  bundleId?: string;
  createdAt?: string;
  keyPair?: CryptoKeyPair;
  /**
   * Redaction is ON by default (core invariant). Only disable via explicit unsafe opt-out.
   */
  unsafeSkipRedaction?: boolean;
}

async function hashEventBody(
  seq: number,
  prevHash: string,
  event: SnarxEventInput,
): Promise<string> {
  const canonical = canonicalJson({
    seq,
    prevHash,
    timestamp: event.timestamp,
    source: event.source,
    kind: event.kind,
    actor: event.actor,
    toolName: event.toolName,
    serverName: event.serverName,
    tokens: event.tokens,
    isError: event.isError,
    payload: event.payload,
  });
  return sha256Hex(canonical);
}

/**
 * Redacts secrets (unless explicitly opted out), SHA-256 hash-chains every event,
 * and optionally signs the bundle rootHash with Ed25519 via Web Crypto API.
 */
export async function sealBundle(
  rawEvents: readonly SnarxEventInput[],
  options: SealOptions = {},
): Promise<SnarxBundle> {
  const shouldRedact = !options.unsafeSkipRedaction;
  let redactedCount = 0;
  let prevHash = GENESIS_HASH;
  const events: SnarxEvent[] = [];

  for (let i = 0; i < rawEvents.length; i++) {
    const raw = rawEvents[i];
    if (!raw) continue;
    const seq = i + 1;

    let payload = raw.payload;
    if (shouldRedact) {
      const res = redactUnknown(raw.payload);
      payload = res.value as Record<string, unknown>;
      redactedCount += res.count;
    }

    const sanitized: SnarxEventInput = { ...raw, payload };
    const hash = await hashEventBody(seq, prevHash, sanitized);

    events.push({
      ...sanitized,
      seq,
      prevHash,
      hash,
    });

    prevHash = hash;
  }

  const rootHash = prevHash;
  const bundle: SnarxBundle = {
    schemaVersion: SNARX_SCHEMA_VERSION,
    bundleId: options.bundleId ?? crypto.randomUUID(),
    createdAt: options.createdAt ?? new Date().toISOString(),
    redacted: shouldRedact,
    redactedCount,
    events,
    rootHash,
  };

  if (options.keyPair) {
    const sigBuffer = await crypto.subtle.sign(
      { name: "Ed25519" },
      options.keyPair.privateKey,
      encoder.encode(rootHash),
    );
    const pubRaw = await crypto.subtle.exportKey("raw", options.keyPair.publicKey);
    bundle.signature = {
      algorithm: "Ed25519",
      publicKeyBase64: bytesToBase64(new Uint8Array(pubRaw)),
      valueBase64: bytesToBase64(new Uint8Array(sigBuffer)),
    };
  }

  return bundle;
}

export type ParseBundleResult = { ok: true; bundle: SnarxBundle } | { ok: false; error: string };

/**
 * Safely parses and validates untrusted JSON text (e.g., from browser drag-and-drop or CLI)
 * into a SnarxBundle without throwing uncaught exceptions.
 */
export function parseBundle(jsonText: string): ParseBundleResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText);
  } catch (err) {
    return {
      ok: false,
      error: `Invalid JSON: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, error: "Bundle root must be a JSON object" };
  }

  const obj = parsed as Record<string, unknown>;
  if (obj.schemaVersion !== SNARX_SCHEMA_VERSION) {
    return {
      ok: false,
      error: `Unsupported schemaVersion "${String(obj.schemaVersion)}" (expected "${SNARX_SCHEMA_VERSION}")`,
    };
  }
  if (typeof obj.bundleId !== "string" || obj.bundleId.length === 0) {
    return { ok: false, error: "Missing or invalid bundleId" };
  }
  if (typeof obj.createdAt !== "string") {
    return { ok: false, error: "Missing or invalid createdAt" };
  }
  if (typeof obj.rootHash !== "string" || obj.rootHash.length !== 64) {
    return { ok: false, error: "Missing or invalid 64-char SHA-256 rootHash" };
  }
  if (!Array.isArray(obj.events)) {
    return { ok: false, error: "Bundle events must be an array" };
  }

  for (let i = 0; i < obj.events.length; i++) {
    const ev = obj.events[i];
    if (ev === null || typeof ev !== "object" || Array.isArray(ev)) {
      return { ok: false, error: `Event at index ${i} must be an object` };
    }
    const rec = ev as Record<string, unknown>;
    if (
      typeof rec.seq !== "number" ||
      typeof rec.timestamp !== "string" ||
      typeof rec.source !== "string" ||
      typeof rec.kind !== "string" ||
      typeof rec.prevHash !== "string" ||
      typeof rec.hash !== "string" ||
      rec.payload === null ||
      typeof rec.payload !== "object" ||
      Array.isArray(rec.payload)
    ) {
      return { ok: false, error: `Malformed event structure at index ${i}` };
    }
  }

  return { ok: true, bundle: parsed as SnarxBundle };
}

export interface VerifyBundleResult {
  valid: boolean;
  chainValid: boolean;
  signatureValid: boolean | null;
  errors: string[];
}

export async function verifyBundle(bundle: SnarxBundle): Promise<VerifyBundleResult> {
  const errors: string[] = [];
  let prevHash = GENESIS_HASH;
  let chainValid = true;

  for (let i = 0; i < bundle.events.length; i++) {
    const ev = bundle.events[i];
    if (!ev) continue;
    const expectedSeq = i + 1;

    if (ev.seq !== expectedSeq) {
      chainValid = false;
      errors.push(`Event at index ${i} has seq ${ev.seq}, expected ${expectedSeq}`);
    }
    if (ev.prevHash !== prevHash) {
      chainValid = false;
      errors.push(`Event seq ${ev.seq} prevHash mismatch`);
    }

    const expectedHash = await hashEventBody(ev.seq, ev.prevHash, ev);
    if (ev.hash !== expectedHash) {
      chainValid = false;
      errors.push(`Event seq ${ev.seq} hash mismatch (possible tampering)`);
    }

    prevHash = ev.hash;
  }

  if (bundle.rootHash !== prevHash) {
    chainValid = false;
    errors.push("Bundle rootHash does not match final event hash");
  }

  let signatureValid: boolean | null = null;
  if (bundle.signature) {
    try {
      const pubBytes = base64ToBytes(bundle.signature.publicKeyBase64);
      const sigBytes = base64ToBytes(bundle.signature.valueBase64);
      const pubKey = await crypto.subtle.importKey(
        "raw",
        pubBytes as BufferSource,
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      signatureValid = await crypto.subtle.verify(
        { name: "Ed25519" },
        pubKey,
        sigBytes as BufferSource,
        encoder.encode(bundle.rootHash),
      );
      if (!signatureValid) {
        errors.push("Ed25519 signature verification failed");
      }
    } catch (err) {
      signatureValid = false;
      errors.push(`Ed25519 signature error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  const valid = chainValid && (signatureValid === null || signatureValid);
  return { valid, chainValid, signatureValid, errors };
}
