---
name: setup
description: >-
  Set up Package Guard's project state after the plugin is installed:
  /package-guard:setup. Seeds the vetted/declined records, the CLAUDE.md
  Packages section and the .gitignore lines, and migrates an older file-based
  install. Run once per project. Use only when the user asks to set up Package Guard.
disable-model-invocation: true
---

# Package Guard project setup

The plugin already guards every project. Without setup, nothing is
pre-approved and every new package needs your approval; setup adds the
per-project files that make the guard useful to a team.

## What it writes

In the project root, nothing else, nothing outside it:

- `.claude/package-guard/vetted.json` and `declined.json`, empty, only if absent.
  Existing approvals are never touched.
- `.claude/package-guard/reports/.gitignore`.
- a `## Packages` section in `CLAUDE.md` (created if missing).
- machine-local state lines in `.gitignore`.

It copies no hooks. If the project has the older file-based install
(`.claude/hooks/package_guard/` or guard hook entries in `.claude/settings.json`),
setup removes those entries and the copied code so the hooks do not run twice,
and keeps `vetted.json` and `declined.json`.

## Steps

The installer must run through the plugin's own runner, on Python 3.11, and the
guard refuses a guard-installer command that Claude runs itself. So the user runs
it, with Claude Code's `!` prefix (bash mode). Claude Code substitutes the plugin
path below; `<project>` is the absolute path of the project root, which is the
directory Claude Code was started in. Write it out in full before showing a command.

1. Tell the user, in two or three lines, what the section above says. If unsure
   whether the project has the file-based install, ask them to run this (it
   changes nothing) and read the output:

   ```
   ! sh "${CLAUDE_PLUGIN_ROOT}/scripts/pg-run" "${CLAUDE_PLUGIN_ROOT}/install.py" 1 --plugin --check "<project>"
   ```

   Ask whether to go ahead. Do not suggest the setup command before they say yes.
2. On yes, show them exactly this one command to run themselves:

   ```
   ! sh "${CLAUDE_PLUGIN_ROOT}/scripts/pg-run" "${CLAUDE_PLUGIN_ROOT}/install.py" 1 --plugin "<project>"
   ```

3. When they paste its output back, tell them to commit the files it lists so
   teammates share the approvals, and, if it removed an old install, to
   restart Claude Code so the old hooks unload.

If it says no runner was found, the user needs uv once and then a restart; the
SessionStart message already says how. Do not run the installer from the Bash
tool, do not use the system `python3` (on macOS it is 3.9), and do not edit
these files by hand instead.
