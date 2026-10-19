# Agent setup

`ldap-axi setup --app <claude|codex|opencode> --hook --skill` installs both integrations for one explicitly selected agent.
Either `--hook` or `--skill` works independently.
Append `--check` to inspect without writing; exit 1 means a selected integration is missing or stale.
Rerunning setup repairs owned configuration and preserves unrelated settings.
It never connects to a directory.

| Agent | Default root | Installed files | Host requirement |
| --- | --- | --- | --- |
| Claude Code | `~/.claude` (`CLAUDE_CONFIG_DIR` override) | `settings.json` SessionStart hook; `skills/ldap-axi/SKILL.md` | Exec-form command hooks with `command` and `args` |
| Codex | `~/.codex` (`CODEX_HOME` override) | `hooks.json` SessionStart hook; `config.toml` enables `features.hooks`; `skills/ldap-axi/SKILL.md` | Native hooks support; review and trust the hook in Codex |
| OpenCode | `$XDG_CONFIG_HOME/opencode` or `~/.config/opencode` (`OPENCODE_CONFIG_DIR` override) | `plugins/ldap-axi.js`; `skills/ldap-axi/SKILL.md` | `experimental.chat.system.transform` and Bun subprocess support |

Hooks run `ldap-axi --session-start` to provide offline connection state and command discovery.
The OpenCode plugin limits execution to five seconds and output to 8 KiB.
Setup does not bypass host trust or administrator policy.
It selects a verified PATH executable when possible and otherwise records an absolute executable path.
Rerun setup after moving or reinstalling ldap-axi.

## Removal

There is no setup uninstall command.
Remove only the `ldap-axi offline home` SessionStart entry from Claude's `settings.json` or Codex's `hooks.json`, preserving other hooks.
For OpenCode, remove the managed `plugins/ldap-axi.js` file.
Remove `skills/ldap-axi/SKILL.md` in the selected agent root to uninstall the setup-managed skill.
Leave Codex's shared `features.hooks` setting enabled if other hooks use it.
For skills installed with `npx skills add`, use that installer's removal workflow.
