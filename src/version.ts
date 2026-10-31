import { readFileSync } from "node:fs";

export const VERSION: string = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")).version;

export function isVersionRequest(argv: readonly string[]): boolean {
  return argv.length === 1 && ["--version", "-v", "-V"].includes(argv[0]);
}
