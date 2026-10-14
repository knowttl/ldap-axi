import { encode } from "@toon-format/toon";
import { CliError } from "./core.js";
import { SecretRedactor } from "./secrets.js";

const patternRedactor = new SecretRedactor();
function quote(value: string): string { return JSON.stringify(value); }
export function render(value: Record<string, unknown>, help: readonly string[] = [], redactor?: SecretRedactor): string {
  const body = encode(redactPayload(value, redactor)).trimEnd();
  return `${body}${help.length ? `\nhelp[${help.length}]: ${help.map(value => quote(redactText(value, redactor))).join(",")}` : ""}\n`;
}
export function redactText(value: string, redactor = patternRedactor): string { return redactor.text(value); }
function redactPayload(value: unknown, redactor?: SecretRedactor): unknown {
  if (typeof value === "string") return redactText(value, redactor);
  if (Array.isArray(value)) return value.map(child => redactPayload(child, redactor));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, child]) => [key,
    /^(?:password|secret|client[_-]?secret|token|access[_-]?token|refresh[_-]?token|authorization|private[_-]?key|accountkey|sas[_-]?token)$/i.test(key) ? "[REDACTED]" : redactPayload(child, redactor)]));
  return value;
}
export function renderError(error: unknown, redactor?: SecretRedactor): { stdout: string; stderr: string; exitCode: number } {
  const known = error instanceof CliError ? error : new CliError("UNKNOWN", "an unexpected error occurred");
  return { stdout: render({ error: known.message, code: known.code }, known.help, redactor), stderr: "", exitCode: known.exitCode };
}
export function truncate(value: string, maximum = 800): string { return value.length <= maximum ? value : `${value.slice(0, maximum)}… (truncated, ${value.length} chars total)`; }
/** Drops undefined-valued keys, so an attribute the server didn't return is omitted rather than rendered null. */
export function compact<T extends Record<string, unknown>>(value: T): Partial<T> { return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined)) as Partial<T>; }
