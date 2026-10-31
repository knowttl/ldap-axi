#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { isVersionRequest, VERSION } from "./version.js";
import type { RunDependencies } from "./cli-main.js";

export async function run(argv: readonly string[], dependencies: RunDependencies = {}): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  if (isVersionRequest(argv)) return { stdout: `${VERSION}\n`, stderr: "", exitCode: 0 };
  const cli = await import("./cli-main.js");
  return cli.run(argv, dependencies);
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  const result = await run(process.argv.slice(2));
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  process.exitCode = result.exitCode;
}
