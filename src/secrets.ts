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

/** One invocation owns the registry; resolved credentials never leak through output or errors. */
export class SecretRedactor {
  private readonly secrets = new Set<string>();
  add(value: string): void {
    this.secrets.add(value);
    this.secrets.add(JSON.stringify(value).slice(1, -1));
    if (value.isWellFormed()) this.secrets.add(encodeURIComponent(value));
  }
  text(value: string): string {
    for (const secret of [...this.secrets].sort((a, b) => b.length - a.length)) value = value.split(secret).join("[REDACTED]");
    return value;
  }
}
