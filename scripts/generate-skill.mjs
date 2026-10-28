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
  const groups = {
    entry: ["Search and show arbitrary entries", "Read"],
    user: ["Read accounts and group membership", "Read"],
    group: ["Read groups and their members", "Read"],
    computer: ["Read machine accounts and devices", "Read"],
    auth: ["Inspect authentication selection and status", "Read; --offline stays local"],
    server: ["Read rootDSE capabilities and flavor", "Read"],
    profile: ["List configured profiles without resolving secrets", "Local read"],
    config: ["Locate the configuration file", "Local read"],
    setup: ["Install or repair selected agent integrations", "Local write; --check reads"],
  };
  const table = ["| Group | Purpose | Read/write | Reference |", "| --- | --- | --- | --- |"];
  const leaves = ["| Command | Help summary |", "| --- | --- |"];
  const reference = ["# Command reference", "", "Generated from executable help by `npm run skill:generate`; do not edit by hand.", "", "Contents: [Command index](#command-index) · [Read examples and output](#read-examples-and-output).", ""];
  reference.push(...COMMANDS.map(command => `- [${command}](#${command.replaceAll(" ", "-")})`), "", "## Command index", "");
  const seen = new Set();
  const help = [];
  for (const command of COMMANDS) {
    const result = await run([...command.split(" "), "--help"], {
      openDirectory: async () => { throw new Error("Help must never connect"); },
    });
    if (result.exitCode !== 0) throw new Error(`Cannot generate help for ${command}`);
    const lines = result.stdout.split("\n");
    const summary = lines[0].startsWith(command) ? lines[1] : lines[0];
    const anchor = command.replaceAll(" ", "-");
    leaves.push(`| [\`${command}\`](#${anchor}) | ${summary.replaceAll("|", "\\|")} |`);
    const group = command.split(" ")[0];
    if (!seen.has(group)) {
      const [purpose, access] = groups[group];
      table.push(`| \`${group}\` | ${purpose} | ${access} | [Commands](docs/commands.md#${anchor}) |`);
      seen.add(group);
    }
    help.push(`## ${command}`, "", "```text", result.stdout.trimEnd(), "```", "");
  }
  reference.push(...leaves, "", "## Read examples and output", "",
    "With a configured profile, replace synthetic identifiers with entries from your directory:", "", "```sh",
    "ldap-axi group members engineering --profile work --fields name,dn --max-rows 25",
    'ldap-axi entry search --profile work --filter "(objectClass=person)" --attributes cn,mail --max-rows 25',
    "ldap-axi computer list --profile work --limit 10", "ldap-axi server --profile work", "```", "",
    "Lists read one page by default; use `--all --max-rows 2000` for a longer bounded read.",
    "Inspect `count`, `partial`, `incomplete`, `stop_reason`, and membership `method`/`transitive` before treating results as complete.",
    "Referrals are reported without being chased; resumable cursors are unsupported.",
    "Unknown flags fail before connecting.",
    "See [output and exit codes](../README.md#output-and-exit-codes) for the output contract.", "", ...help);
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
