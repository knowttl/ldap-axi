import { mkdir, rm, writeFile } from "node:fs/promises";

const root = ".tmp/package-test";
await rm(root, { recursive: true, force: true });
for (const name of ["prebuild-consumer", "source-consumer", "source-failure-consumer", "replacement-consumer", "missing-consumer", "malformed-consumer", "capability-fallback-consumer", "oversized-download-consumer", "invalid-mode-consumer"]) {
  await mkdir(`${root}/${name}`, { recursive: true });
  await writeFile(`${root}/${name}/package.json`, `${JSON.stringify({ name: `ldap-axi-${name}`, version: "1.0.0", private: true }, null, 2)}\n`);
}
