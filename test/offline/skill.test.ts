import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createSkillMarkdown } from "../../src/skill.js";

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
  assert.match(generated, /computer list/);
});
