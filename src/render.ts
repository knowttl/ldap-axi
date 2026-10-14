import { encode } from "@toon-format/toon";
import { CliError } from "./core.js";

function quote(value: string): string { return JSON.stringify(value); }
export function render(value: Record<string, unknown>, help: readonly string[] = []): string {
  const body = encode(value).trimEnd();
  return `${body}${help.length ? `\nhelp[${help.length}]: ${help.map(quote).join(",")}` : ""}\n`;
}
export function renderError(error: unknown): { stdout: string; stderr: string; exitCode: number } {
  const known = error instanceof CliError ? error : new CliError("UNKNOWN", "an unexpected error occurred");
  return { stdout: render({ error: known.message, code: known.code }, known.help), stderr: "", exitCode: known.exitCode };
}
export function truncate(value: string, maximum = 800): string { return value.length <= maximum ? value : `${value.slice(0, maximum)}… (truncated, ${value.length} chars total)`; }
/** Drops undefined-valued keys, so an attribute the server didn't return is omitted rather than rendered null. */
export function compact<T extends Record<string, unknown>>(value: T): Partial<T> { return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined)) as Partial<T>; }
