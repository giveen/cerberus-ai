---
name: commit-and-push
description: "Stage all changes, analyze git diff to generate a meaningful commit message, commit, and push to the current branch. Use when you want a one-command workflow to finalize and share your work with an auto-generated summary that reflects what actually changed."
argument-hint: "Optional override message, for example: 'refactor auth module' or 'fix typo in docs' (if omitted, auto-generates from diff)"
---

# Commit and Push Workflow

Automate the entire commit-to-push pipeline: stage changes, intelligently summarize them, commit, and push to the current branch in one invocation.

## When to Use

- You have working code changes and want to commit them with a meaningful message automatically generated from the diff
- You want to avoid manually crafting commit messages while keeping them concise and accurate
- You're ready to share your work and push immediately after committing
- You want a one-step workflow instead of running git add → git commit → git push manually

## Required Outcome

The skill will:

1. **Stage all changes** via `git add -A`
2. **Analyze the git diff** to extract what changed (files, functions, features, bugfixes)
3. **Generate a concise commit message** following conventional commit style (e.g., `feat: add session grid`, `fix: handle edge case in auth`, `refactor: simplify state model`)
4. **Commit with the generated message** (or your override if provided)
5. **Push to the current branch** immediately after commit
6. **Report success** with summary of files changed and the commit message

## Workflow Steps

### 1. Prepare Your Changes

Before invoking the skill:
- Ensure your working directory is clean of untracked files you don't want to commit (or use `.gitignore` to exclude them)
- Have meaningful changes staged or unstaged—the skill will stage everything and commit it
- Verify you're on the branch you want to push to

### 2. Invoke the Skill

Use one of these forms:

**Auto-generate commit message from diff:**
```
/commit-and-push
```

**Override with your own message:**
```
/commit-and-push refactor: simplify event handler logic
```

### 3. Verify Output

The skill will report:
- Number of files changed
- The commit message used
- Git push confirmation with branch name
- Any errors or warnings during push

## Commit Message Strategy

The skill analyzes the diff to categorize changes:

| Category | Pattern | Example Message |
|----------|---------|-----------------|
| New files | Multiple new `.py` or `.ts` files | `feat: add memory persistence layer` |
| Feature | Function/class additions, new capabilities | `feat: implement redis caching` |
| Bug fix | Fixes to existing logic or error handling | `fix: resolve race condition in async handler` |
| Refactor | Code reorganization, no logic change | `refactor: extract common validation logic` |
| Chore | Config, deps, tooling, comments | `chore: update playwright config` |
| Docs | README, documentation, examples | `docs: update API quickstart guide` |
| Test | New tests or test fixes | `test: add coverage for edge cases` |

The generated message will include:
- A prefix (feat/fix/refactor/etc.)
- A concise subject line (50 chars or less)
- Optional body describing the key changes (if the diff is substantial)

## Manual Override

If the auto-generated message doesn't fit your intent, provide your message as an argument:

```
/commit-and-push fix: correct typo in README
```

This bypasses diff analysis and commits with your exact message.

## Prerequisites

- Git repository is initialized
- You have uncommitted changes or untracked files you want to commit
- You have push permissions to the current branch
- GitHub credentials/SSH key is configured (for remote push)

## Common Scenarios

### Scenario: Small bugfix to single file

```
(edit README.md)
/commit-and-push
→ git add -A
→ Analyzing: 1 file changed (README.md)
→ Commit message: "fix: correct installation instructions"
→ Pushed to main
```

### Scenario: Multi-file refactor

```
(move files, update imports)
/commit-and-push
→ git add -A
→ Analyzing: 5 files changed (3 moved, 2 modified)
→ Commit message: "refactor: reorganize auth modules"
→ Pushed to feature/auth-redesign
```

### Scenario: Override auto-generated message

```
(various edits)
/commit-and-push docs: update architecture diagrams
→ git add -A
→ Using your message: "docs: update architecture diagrams"
→ Pushed to main
```

## Edge Cases

**No changes to commit:**
- If working directory is clean, the skill will report no changes and skip commit/push

**Conflicting remote changes:**
- If remote has new commits on your branch, push will fail with a merge message
- You'll need to pull, resolve conflicts, and re-run the skill

**Large diffs:**
- If diff is > 10K lines, the skill may generate a more general message to avoid context overload
- Use a manual override to be more specific in this case

## Limitations

- The skill does not perform merge conflict resolution
- The skill commits **all** changes (git add -A); use `.gitignore` to exclude files
- The skill assumes a linear history; if your branch has diverged significantly, it will fail on push
- Conventional commit style is enforced; custom formats are not supported (use override for non-standard messages)

## Related Workflows

Consider these skills or workflows for related tasks:

- **Create-pull-request skill** – After pushing, open a PR with auto-generated title from your commit
- **Branch management** – If you need to create or switch branches before committing
- **Diff review** – If you want to review changes before committing (run outside this skill)
