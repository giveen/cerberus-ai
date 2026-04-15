<todos title="Cerberus AI Rebrand And Clean Break" rule="Review steps frequently throughout the conversation and DO NOT stop between steps unless they explicitly require it.">
- [x] audit-identity-occurrences: Audit user-facing and documentary uses of CAI, Cybersecurity AI, and visible Cerebro branding while preserving structural package paths, runtime directories, and environment variable identifiers. 🔴
  _Broad CAI matches are mostly imports, .cai paths, or config names. Visible Cerebro strings also need conversion for a coherent brand._
- [-] update-branding-files: Update dashboard header, CLI and REPL user-facing strings, branding regression tests, README, and project metadata to use Cerberus AI branding. 🔴
  _Target app/app.py, src/cai/cli.py, src/cai/repl/ui/*.py, src/cai/repl/commands/help.py, tests/cli/test_branding_regression.py, pyproject.toml, and README.md. Preserve src/cai imports and CEREBRO_* runtime identifiers unless only shown to the user._
- [ ] create-license-and-gitignore: Create an MIT LICENSE file, normalize .gitignore, and ensure workspaces/.gitkeep is present under the requested ignore rules. 🔴
  _Keep workspaces/* ignored while preserving workspaces/.gitkeep._
- [ ] reinitialize-git-history: Delete the current .git directory, initialize a fresh repository, stage files under the new ignore rules, and create the genesis commit. 🔴
  _Destructive step requested by user. Defer until content edits and validation are complete._
- [ ] connect-and-push-remote: Add the new GitHub remote and push the fresh main branch to the cerberus-ai repository. 🔴
  _May be blocked by credentials or remote permissions. Report exact blocker if push fails._
- [ ] summarize-scrubbed-files: Provide a concise summary of the identity scrub and list the files updated during the Cerberus AI transition. 🟡
  _Final response should summarize content edits and git/reset/push outcome._
</todos>

<!-- Auto-generated todo section -->
<!-- Add your custom Copilot instructions below -->
