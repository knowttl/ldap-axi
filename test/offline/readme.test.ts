import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { run } from "../../src/cli.js";
import { BASE, byFilter, entry, RecordedDirectory } from "../support/fixtures.js";

const readme = await readFile("README.md", "utf8");
const profiles = [...readme.matchAll(/```json\n([\s\S]*?)\n```/g)].map(match => match[1]);
const outputs = [...readme.matchAll(/```text\n([\s\S]*?)\n```/g)].map(match => `${match[1]}\n`);

for (const [index, auth] of ["gssapi", "simple"].entries()) {
  test(`README ${auth} profile supports offline diagnosis and a bounded read`, async () => {
    const root = await mkdtemp(join(tmpdir(), "ldap-axi-readme-"));
    const config = join(root, "config.json");
    const previous = process.env.LDAP_AXI_BIND_PASSWORD;
    process.env.LDAP_AXI_BIND_PASSWORD = "synthetic-readme-secret";
    try {
      await writeFile(config, profiles[index], { mode: 0o600 });
      const offline = await run(["auth", "status", "--offline", "--profile", "work", "--config", config], {
        openDirectory: async () => assert.fail("offline diagnosis must not connect"),
      });
      assert.equal(offline.exitCode, 0, offline.stdout);
      assert.doesNotMatch(offline.stdout, /synthetic-readme-secret/);
      if (auth === "gssapi") {
        const listed = await run(["profile", "list", "--config", config]);
        assert.equal(listed.exitCode, 0);
        assert.equal(listed.stdout, outputs[1]);
      }
      const read = await run(["user", "list", "--profile", "work", "--fields", "name,dn", "--limit", "1", "--config", config], {
        openDirectory: async () => new RecordedDirectory("ad", [
          byFilter([], [entry(`CN=Example,${BASE}`, { cn: ["Example"], objectClass: ["user"] })]),
        ], { defaultNamingContext: [BASE] }),
      });
      assert.equal(read.exitCode, 0, read.stdout);
      assert.equal(read.stdout, outputs[0]);
    } finally {
      if (previous === undefined) delete process.env.LDAP_AXI_BIND_PASSWORD;
      else process.env.LDAP_AXI_BIND_PASSWORD = previous;
      await rm(root, { recursive: true, force: true });
    }
  });
}
