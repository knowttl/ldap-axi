import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFile, cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { run } from "../../src/cli.js";
import { homeView, HOME_GUIDANCE } from "../../src/home.js";
import { createSkillMarkdown } from "../../src/skill.js";

const skillPaths = ["skills/ldap-axi/SKILL.md", ".agents/skills/axi/SKILL.md"];

test("generated project skills stay synchronized", async () => {
  const generated = createSkillMarkdown();
  const [publicSkill, localSkill] = await Promise.all([
    readFile("skills/ldap-axi/SKILL.md", "utf8"),
    readFile(".agents/skills/axi/SKILL.md", "utf8"),
  ]);
  // The generator emits LF; git may check the committed files out with CRLF on Windows,
  // so compare content independent of the checkout's line-ending convention.
  const normalizeEol = (value: string): string => value.replace(/\r\n/g, "\n");
  assert.equal(normalizeEol(publicSkill), generated);
  assert.equal(normalizeEol(localSkill), generated);
});

test("skill command discovery agrees with the offline home and executable help", async () => {
  const home = homeView("/synthetic/bin/ldap-axi", "ldaps://synthetic.example.test", true);
  const generated = createSkillMarkdown();
  const commands = [...generated.matchAll(/^- `npx -y @knowttl\/ldap-axi (.+) --help`$/gm)].map(match => match[1]);
  assert.deepEqual(commands, home.data.commands);
  for (const command of commands) {
    const result = await run([...command.split(" "), "--help"], {
      openDirectory: async () => { throw new Error("command discovery must not connect"); },
    });
    assert.equal(result.exitCode, 0, result.stdout);
  }
  for (const line of HOME_GUIDANCE) assert.ok(generated.includes(line.replaceAll("`ldap-axi", "`npx -y @knowttl/ldap-axi")));
  assert.ok(generated.includes(String(home.data.description)));
  assert.doesNotMatch(generated, /synthetic|configured for simple auth|^bin:|^credentials:|^server:/m);
});

test("installed skill links resolve outside the repository", async () => {
  const root = await mkdtemp(join(tmpdir(), "ldap-axi-installed-skill-"));
  try {
    const installed = join(root, "ldap-axi", "SKILL.md");
    await mkdir(dirname(installed), { recursive: true });
    await copyFile(skillPaths[0], installed);
    const markdown = await readFile(installed, "utf8");
    const links = [...markdown.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)].map(match => new URL(match[1]));
    assert.ok(links.length > 0);
    for (const link of links) assert.equal(link.protocol, "https:");
  } finally { await rm(root, { recursive: true, force: true }); }
});

async function generatorFixture(body: (root: string, invoke: (...args: string[]) => ReturnType<typeof spawnSync>) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "ldap-axi-skill-generator-"));
  try {
    for (const path of ["scripts/generate-skill.mjs", "README.md"]) {
      await mkdir(dirname(join(root, path)), { recursive: true });
      await copyFile(path, join(root, path));
    }
    await cp("dist/src", join(root, "dist/src"), { recursive: true });
    await symlink(join(process.cwd(), "node_modules"), join(root, "node_modules"), "junction");
    await writeFile(join(root, "package.json"), '{"type":"module"}');
    // A generation regression must fail even if it tries to swallow a network error.
    const guard = `import net from 'node:net'; import tls from 'node:tls'; import { syncBuiltinESMExports } from 'node:module';
      const denied = () => { process.exit(99); }; net.Socket.prototype.connect = denied; tls.connect = denied; syncBuiltinESMExports();`;
    const invoke = (...args: string[]): ReturnType<typeof spawnSync> => spawnSync(process.execPath, [
      "--import", `data:text/javascript,${encodeURIComponent(guard)}`, join(root, "scripts/generate-skill.mjs"), ...args,
    ], {
      cwd: root, encoding: "utf8",
      env: { ...process.env, LDAP_AXI_URL: "ldaps://synthetic.example.test", LDAP_AXI_BIND_DN: "cn=synthetic", LDAP_AXI_BIND_PASSWORD: "synthetic-secret", LDAP_AXI_CONFIG: join(root, "missing-config.json") },
    });
    await body(root, invoke);
  } finally { await rm(root, { recursive: true, force: true }); }
}

test("skill generation writes both copies without reading settings or connecting", async () => {
  await generatorFixture(async (root, invoke) => {
    const generated = invoke();
    assert.equal(generated.status, 0, String(generated.stderr));
    for (const path of skillPaths) assert.equal(await readFile(join(root, path), "utf8"), createSkillMarkdown());
    assert.equal(invoke("--check").status, 0);
    await writeFile(join(root, skillPaths[0]), createSkillMarkdown().replaceAll("\n", "\r\n"));
    assert.equal(invoke("--check").status, 0);
  });
});

for (const path of [...skillPaths, "docs/commands.md", "README.md"]) for (const state of ["stale", "missing"]) {
  test(`guidance check rejects ${state} ${path} without repairing it`, async () => {
    await generatorFixture(async (root, invoke) => {
      assert.equal(invoke().status, 0);
      const file = join(root, path);
      if (state === "stale") await writeFile(file, path === "README.md" ? "<!-- BEGIN GENERATED COMMANDS -->\nstale\n<!-- END GENERATED COMMANDS -->\n" : "stale\n");
      else await rm(file);
      const checked = invoke("--check");
      assert.equal(checked.status, 1);
      assert.ok(String(checked.stderr).includes(path));
      if (state === "stale") assert.match(await readFile(file, "utf8"), /stale/);
      else await assert.rejects(readFile(file), { code: "ENOENT" });
    });
  });
}
