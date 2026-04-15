---
name: github-copilot-starter
description: 'Set up complete GitHub Copilot configuration for a new or lightly customized project based on technology stack. Use for bootstrapping .github/copilot-instructions.md, stack-specific .instructions.md files, reusable skills, custom agents, and an optional Coding Agent workflow with awesome-copilot research and attribution.'
argument-hint: 'Optional stack summary, for example: Next.js app with Postgres, Playwright, strict standards, GitHub Actions'
---

# GitHub Copilot Starter

Set up a production-ready GitHub Copilot configuration for a project by inspecting the stack, researching awesome-copilot first, and creating a coherent `.github/` customization set.

Use this skill for the initial Copilot setup pass. It is not for implementing application features.

For source selection and attribution rules, review [awesome-copilot patterns](./references/awesome-copilot-patterns.md). For the required file set, templates, and workflow skeleton, review [output contract](./references/output-contract.md).

## When to Use

- A repository needs its first `.github/copilot-instructions.md`.
- A new project needs language instructions, reusable skills, and custom agents aligned to its stack.
- A team wants a shared Copilot baseline with traceable attribution back to awesome-copilot.
- An existing repository has partial Copilot configuration and needs a structured rebuild.

## Required Inputs

Collect these before writing files if they are not already provided:

- Primary language and framework
- Project type
- Additional technologies
- Development style
- Whether the repository uses GitHub Actions

If the repository already contains code, inspect the actual workspace and treat repository reality as the source of truth.

## Minimum Deliverable

Create these files unless the repository already has a better project-specific equivalent:

- `.github/copilot-instructions.md`
- `.github/instructions/{primaryLanguage}.instructions.md`
- `.github/instructions/testing.instructions.md`
- `.github/instructions/documentation.instructions.md`
- `.github/instructions/security.instructions.md`
- `.github/instructions/performance.instructions.md`
- `.github/instructions/code-review.instructions.md`
- `.github/skills/setup-component/SKILL.md`
- `.github/skills/write-tests/SKILL.md`
- `.github/skills/code-review/SKILL.md`
- `.github/skills/refactor-code/SKILL.md`
- `.github/skills/generate-docs/SKILL.md`
- `.github/skills/debug-issue/SKILL.md`
- `.github/agents/software-engineer.agent.md`
- `.github/agents/architect.agent.md`
- `.github/agents/reviewer.agent.md`
- `.github/agents/debugger.agent.md`

Create `.github/workflows/copilot-setup-steps.yml` only when the user confirms GitHub Actions is used.

## Procedure

### 1. Gather project facts

- Ask for the five required inputs in one short batch if needed.
- If the repository already exists, inspect the stack, test tooling, linting, docs layout, and CI files before drafting anything.
- Prefer repository evidence over assumptions.

### 2. Research awesome-copilot first

- Fetch the docs pages and directory listings defined in [awesome-copilot patterns](./references/awesome-copilot-patterns.md).
- Identify the strongest exact matches for the stack across instructions, agents, and skills.
- Keep a source ledger for every adapted file so attribution comments stay accurate.
- Reuse proven patterns when they exist. Create original material only for gaps.

### 3. Plan the file set before writing

- Map each required file to one of three strategies: exact awesome-copilot match, combined matches, or custom fallback.
- Keep `.github/copilot-instructions.md` short and central. It should link to detailed instructions instead of duplicating them.
- For polyglot projects, create the required primary-language instruction first and add secondary-language instructions only when the stack genuinely needs them.
- If `.github/` already exists, refine or merge instead of overwriting blindly.

### 4. Write repository-wide instructions

- Draft `.github/copilot-instructions.md` using the structure in [output contract](./references/output-contract.md).
- Describe project overview, tech stack, conventions, and workflow in repository terms.
- Link to the detailed instruction files using relative Markdown links.

### 5. Write instruction files

- Adapt awesome-copilot instruction files when available and add attribution comments at the top.
- If no strong source exists, write simple high-level guidelines only.
- Keep `.instructions.md` files free of code snippets, detailed implementation recipes, and boilerplate templates.
- Cover naming, structure, error handling, testing expectations, docs standards, security, performance, and code review expectations.

### 6. Write reusable skills

- Create the six required skills as small, discoverable workflows.
- Use keyword-rich descriptions so the right skill is easy to load.
- Keep each skill focused on one repeatable task and aligned to the project stack and conventions.
- Reuse existing validation and documentation patterns where they exist.

### 7. Write custom agents

- Create the four required agent files with the exact filenames in the deliverable list.
- For each role, fetch the best awesome-copilot source first. Use the most specific stack match when one exists; otherwise use a generic fallback.
- Preserve the fixed local filenames even when adapting from a differently named source agent.
- Add attribution comments for every adapted agent file.

### 8. Add the Coding Agent workflow when applicable

- Skip the workflow entirely if GitHub Actions is not used.
- If included, the workflow job name must be `copilot-setup-steps`.
- Keep the workflow minimal: runtime setup, dependency installation, and basic lint, test, or build commands.
- Do not add databases, service containers, custom scripts, deployment logic, or large matrices unless the user explicitly asks for them.

### 9. Validate before finishing

Check all of the following:

- Required files exist in the correct directories.
- YAML frontmatter is present and syntactically valid where required.
- Descriptions are specific enough for discovery.
- `.github/copilot-instructions.md` links to the detailed instruction files.
- Instruction files are guidance, not code dumps.
- Skills and agents match the project stack and naming intent.
- Attribution comments are present wherever awesome-copilot content was adapted.
- The optional workflow uses the exact job name and simple structure required.

### 10. Deliver the setup

After authoring, provide:

- A short summary of what was created
- Any ambiguities or weak spots worth refining
- Example prompts for using the new skills and agents
- VS Code setup and verification steps
- Sensible follow-on customizations

## Decision Points

### If required project information is missing

- Ask only for the five required inputs.
- Do not guess the GitHub Actions answer.

### If awesome-copilot has an exact match

- Start from that file and adapt it to the repository.
- Preserve good structure and terminology, then trim irrelevant sections.

### If only partial matches exist

- Combine a language or framework file with one or two cross-cutting files.
- Reconcile conflicting guidance instead of pasting incompatible sections together.

### If no solid match exists

- Create a concise custom file that states principles, structure, naming, testing, documentation, security, and performance expectations.
- Keep it shorter than an adapted file, not longer.

### If the project is frontend-heavy

- Prioritize framework instructions, testing guidance, accessibility, performance, and reviewer or debugger agents with runtime UI focus.

### If the project is backend-heavy

- Prioritize API, data, security, performance, and operational guidance.

### If the project is a library or SDK

- Emphasize public API stability, versioning, examples, documentation quality, and testing of supported surfaces.

### If the project already contains Copilot files

- Treat existing files as inputs to refine, not clutter to duplicate.
- Preserve intentional repository-specific guidance that is better than a generic template.

## Quality Bar

A strong result gives the repository:

- one clear always-on instruction hub
- detailed but non-redundant instruction files
- six discoverable skills that map to routine work
- four agents that are specialized enough to be useful
- an optional Coding Agent workflow that is minimal and correct
- explicit attribution for adapted awesome-copilot material

If the result feels like a pile of copied templates, it is too shallow. If it invents rules that ignore the actual stack or repository structure, it is wrong.