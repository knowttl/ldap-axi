import { isAbsolute, win32 } from "node:path";
import { CliError } from "./core.js";
import { readPrivateFile } from "./private-file.js";

export type SecretRef = Readonly<{ env: string } | { file: string }>;
export function validateSecretRef(value: unknown, field: string): asserts value is SecretRef {
  if (value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 1) {
    if ("env" in value && typeof value.env === "string" && /^[A-Za-z_][A-Za-z0-9_]*$/.test(value.env)) return;
    if ("file" in value && typeof value.file === "string" && (process.platform === "win32" ? /^[A-Za-z]:[\\/]/.test(value.file) && win32.isAbsolute(value.file) : isAbsolute(value.file))) return;
  }
  throw new CliError("CONFIG_INVALID", `${field} must be a SecretRef, never an inline secret`, ["Use exactly one env name or absolute local file path; ldap-axi does not store secrets"]);
}
export function secretSource(ref: SecretRef): string { return "env" in ref ? `env:${ref.env}` : `file:${ref.file}`; }
export async function resolveSecret(ref: SecretRef, redactor: SecretRedactor): Promise<string | undefined> {
  let value: string | undefined;
  if ("env" in ref) value = process.env[ref.env];
  else {
    try { value = (await readPrivateFile(ref.file)).replace(/^\uFEFF/, "").trimEnd(); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  }
  if (value) redactor.add(value);
  return value?.trim() ? value : undefined;
}

// The first capture, when present, is a public label retained outside the protected value.
const SECRET_PATTERNS = [
  /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )*PRIVATE KEY-----/g,
  /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
  /(\bAccountKey=)[^;\s]+/gi,
  /([?&]sig=)[^&\s]+/gi,
];

/** One invocation owns the registry; resolved credentials never leak through output or errors. */
export class SecretRedactor {
  private readonly secrets = new Set<string>();
  add(value: string): void {
    if (!value) return;
    this.secrets.add(value);
    this.secrets.add(JSON.stringify(value).slice(1, -1));
    if (value.isWellFormed()) this.secrets.add(encodeURIComponent(value));
  }
  text(value: string): string {
    const spans: [number, number][] = [];
    // All matchers see the original input, so neither can destroy the other's evidence.
    for (const secret of this.secrets) {
      for (let start = value.indexOf(secret); start !== -1; start = value.indexOf(secret, start + 1)) spans.push([start, start + secret.length]);
    }
    for (const pattern of SECRET_PATTERNS) {
      for (const match of value.matchAll(pattern)) spans.push([match.index + (match[1]?.length ?? 0), match.index + match[0].length]);
    }
    const merged: [number, number][] = [];
    for (const [start, end] of spans.sort((a, b) => a[0] - b[0])) {
      const previous = merged.at(-1);
      if (previous && start <= previous[1]) previous[1] = Math.max(previous[1], end);
      else merged.push([start, end]);
    }
    let result = ""; let cursor = 0;
    for (const [start, end] of merged) {
      result += value.slice(cursor, start) + "[REDACTED]";
      cursor = end;
    }
    return result + value.slice(cursor);
  }
}
