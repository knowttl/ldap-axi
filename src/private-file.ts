import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { platform } from "node:os";
import { CliError } from "./core.js";

/** Check provenance before reading, and bind that check to the opened descriptor. */
export async function readPrivateFile(path: string): Promise<string> {
  const windows = platform() === "win32";
  const insecure = () => new CliError("CONFIG_INSECURE", `insecure file: ${path}`, [windows ? "Restrict the file ACL to the owning account; Windows ACL verification is unchecked" : `chmod 600 '${path.replaceAll("'", "'\\''")}'`]);
  const stat = await lstat(path).catch(error => { if ((error as NodeJS.ErrnoException).code === "ENOENT") throw error; throw insecure(); });
  const valid = (metadata: typeof stat) => metadata.isFile() && (windows ||
    ((typeof process.getuid !== "function" || metadata.uid === process.getuid()) && (metadata.mode & 0o077) === 0));
  if (stat.isSymbolicLink() || !valid(stat)) throw insecure();
  const file = await open(path, constants.O_RDONLY | (windows ? 0 : constants.O_NOFOLLOW)).catch(() => { throw insecure(); });
  try {
    const opened = await file.stat();
    if (!valid(opened) || opened.ino !== stat.ino || opened.dev !== stat.dev) throw insecure();
    return await file.readFile("utf8");
  } finally { await file.close(); }
}
