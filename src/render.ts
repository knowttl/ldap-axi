import { encode } from "@toon-format/toon";
import { CliError } from "./core.js";

function quote(value: string): string { return JSON.stringify(value); }
export function render(value: Record<string, unknown>, help: readonly string[] = []): string {
  const body = encode(redactPayload(value)).trimEnd();
  return `${body}${help.length ? `\nhelp[${help.length}]: ${help.map(quote).join(",")}` : ""}\n`;
}
function redactPayload(value: unknown): unknown {
  if (typeof value === "string") return value
    .replace(/-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )*PRIVATE KEY-----/g, "[REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[REDACTED]")
    .replace(/(\bAccountKey=)[^;\s]+/gi, "$1[REDACTED]")
    .replace(/([?&]sig=)[^&\s]+/gi, "$1[REDACTED]");
  if (Array.isArray(value)) return value.map(redactPayload);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, child]) => [key,
    /^(?:password|secret|client[_-]?secret|token|access[_-]?token|refresh[_-]?token|authorization|private[_-]?key|accountkey|sas[_-]?token)$/i.test(key) ? "[REDACTED]" : redactPayload(child)]));
  return value;
}
export function renderError(error: unknown): { stdout: string; stderr: string; exitCode: number } {
  const known = error instanceof CliError ? error : new CliError("UNKNOWN", "an unexpected error occurred");
  return { stdout: render({ error: known.message, code: known.code }, known.help), stderr: "", exitCode: known.exitCode };
}
export function truncate(value: string, maximum = 800): string { return value.length <= maximum ? value : `${value.slice(0, maximum)}… (truncated, ${value.length} chars total)`; }
/** Drops undefined-valued keys, so an attribute the server didn't return is omitted rather than rendered null. */
export function compact<T extends Record<string, unknown>>(value: T): Partial<T> { return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined)) as Partial<T>; }
