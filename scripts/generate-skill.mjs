import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createSkillMarkdown } from "../dist/src/skill.js";

const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== "--check")) {
  console.error("Usage: node scripts/generate-skill.mjs [--check]");
  process.exitCode = 2;
} else {
  const generated = createSkillMarkdown();
  for (const path of ["skills/ldap-axi/SKILL.md", ".agents/skills/axi/SKILL.md"]) {
    const file = new URL(`../${path}`, import.meta.url);
    if (args[0] === "--check") {
      let current;
      try { current = await readFile(file, "utf8"); } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      if (current?.replaceAll("\r\n", "\n") !== generated) {
        console.error(`Stale generated skill: ${path}. Run npm run skill:generate.`);
        process.exitCode = 1;
      }
    } else {
      await mkdir(new URL(".", file), { recursive: true });
      await writeFile(file, generated);
    }
  }
}
