import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createSkillMarkdown } from "../dist/src/skill.js";
import { COMMANDS } from "../dist/src/home.js";
import { run } from "../dist/src/cli.js";

const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== "--check")) {
  console.error("Usage: node scripts/generate-skill.mjs [--check]");
  process.exitCode = 2;
} else {
  const skill = createSkillMarkdown();
  const table = ["| Command | Help summary |", "| --- | --- |"];
  const reference = ["# Command reference", "", "Generated from executable help by `npm run skill:generate`; do not edit by hand.", ""];
  for (const command of COMMANDS) {
    const result = await run([...command.split(" "), "--help"], {
      openDirectory: async () => { throw new Error("Help must never connect"); },
    });
    if (result.exitCode !== 0) throw new Error(`Cannot generate help for ${command}`);
    const summary = result.stdout.split("\n")[0].replaceAll("|", "\\|").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
    table.push(`| [\`${command}\`](docs/commands.md#${command.replaceAll(" ", "-")}) | ${summary} |`);
    reference.push(`## ${command}`, "", "```text", result.stdout.trimEnd(), "```", "");
  }
  const readmeFile = new URL("../README.md", import.meta.url);
  const readme = (await readFile(readmeFile, "utf8")).replaceAll("\r\n", "\n");
  const region = /<!-- BEGIN GENERATED COMMANDS -->[\s\S]*?<!-- END GENERATED COMMANDS -->/;
  if (!region.test(readme)) throw new Error("README is missing generated command markers");
  const generatedReadme = readme.replace(region, `<!-- BEGIN GENERATED COMMANDS -->\n${table.join("\n")}\n<!-- END GENERATED COMMANDS -->`);
  for (const [path, generated] of [
    ["skills/ldap-axi/SKILL.md", skill], [".agents/skills/axi/SKILL.md", skill],
    ["docs/commands.md", reference.join("\n")], ["README.md", generatedReadme],
  ]) {
    const file = new URL(`../${path}`, import.meta.url);
    if (args[0] === "--check") {
      let current;
      try { current = await readFile(file, "utf8"); } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      if (current?.replaceAll("\r\n", "\n") !== generated) {
        console.error(`Stale generated guidance: ${path}. Run npm run skill:generate.`);
        process.exitCode = 1;
      }
    } else {
      await mkdir(new URL(".", file), { recursive: true });
      await writeFile(file, generated);
    }
  }
}
