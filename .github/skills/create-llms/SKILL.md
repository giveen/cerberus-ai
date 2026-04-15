---
name: create-llms
description: 'Create or refresh a repository-root llms.txt file from the current workspace structure. Use for llms.txt generation, llmstxt.org format compliance, repository documentation curation, selecting high-value files for LLM navigation, and validating relative links and Optional sections.'
argument-hint: 'Optional scope or focus, for example: current repo, docs-heavy repo, package-first repo, or refresh existing llms.txt'
---

# Create llms.txt

Create a repository-root llms.txt file that follows the official llms.txt specification at https://llmstxt.org/ and helps an LLM understand the project quickly.

This skill is for generating the file itself, not for creating a generic docs index. The output must be concise, valid Markdown, easy for humans to skim, and structured for deterministic parsing.

## When to Use

- The repository does not have an llms.txt file yet.
- The repository structure or docs changed and llms.txt needs to be refreshed.
- You need an LLM-friendly entry point that prioritizes the most important docs, specs, setup files, and examples.
- You want a curated navigation file instead of exposing the whole repository tree.

## Required Outcome

Produce a single file at repository root named llms.txt with this exact high-level structure, in this order:

1. One H1 containing the project or repository name.
2. One short blockquote summary describing the repository purpose and scope.
3. Optional plain Markdown details before any H2 sections. Do not add headings in this area.
4. Zero or more H2 sections containing Markdown bullet lists of links.

Each listed item must use this pattern:

`- [Descriptive name](path/to/file-or-url): Brief explanation of why this file matters`

The Optional section has special meaning in the spec. Use it only for secondary context that can be skipped when a shorter LLM context is needed.

## Procedure

### 1. Read the spec first

- Review https://llmstxt.org/ before drafting.
- Preserve the required section ordering.
- Prefer clear Markdown over ad hoc formatting.
- Remember that the H1 is the only strictly required section, but the summary blockquote is strongly recommended.

### 2. Analyze the repository from the current workspace state

- Inspect the actual checked-out repository, not assumptions from the default branch and not stale documentation.
- Identify the project type, primary audience, and main workflows.
- Catalog high-value files and directories.
- Prefer current source-of-truth files over generated output, images, binaries, logs, or temporary artifacts.

Start with these discovery targets:

- Root documentation: README.md, INSTALL.md, WHATS-NEW.md, CONTRIBUTING.md, CHANGELOG.md, LICENSE files
- Project metadata: pyproject.toml, package.json, Cargo.toml, go.mod, mkdocs.yml, Makefile
- Documentation directories: docs/, spec/, specs/, examples/, guides/, api/, design/
- Source layout: src/, app/, packages/, services/, libraries/
- Tests and usage examples: tests/, examples/, demo apps, sample configs
- Operational and deployment material: dockerized/, docker-compose files, ci/, .github/workflows/

### 3. Summarize the repository purpose

Write a tight summary that answers:

- What this repository is
- Who it is for
- What the main capabilities or surfaces are
- What kinds of files an LLM should read first

If helpful, add a short detail block after the summary with plain Markdown bullets or paragraphs covering:

- Major subsystems
- Important terminology
- Any special cautions about generated or missing documentation

Do not introduce an H2 until that short context block is finished.

### 4. Curate files instead of dumping the tree

Select files that help an LLM answer practical questions about the repository.

Include files that:

- Explain project purpose and installation
- Define architecture, APIs, interfaces, or specifications
- Show important workflows or examples
- Clarify testing, development, deployment, or operations
- Represent major subsystems when no dedicated docs exist

Exclude files that are mostly noise for orientation:

- Build artifacts
- Generated caches or logs
- Large binary assets and screenshots unless they are uniquely important
- Redundant files that say the same thing as a better canonical document
- Temporary or local-only scratch files
- Entire directories represented only by low-signal implementation details

### 5. Organize sections for LLM navigation

Use a small number of useful H2 sections. Common choices:

- Documentation
- Architecture
- Specifications
- Examples
- Configuration
- Testing
- Operations
- Optional

Not every repository needs every section. Omit empty categories.

### 6. Prefer relative links for repository files

- Use relative paths from repository root.
- Verify every linked file exists in the current workspace.
- If linking an external canonical reference is necessary, keep it rare and explain why it matters.
- Do not fabricate missing docs just because the repository once had them.

### 7. Validate before finishing

Check all of the following:

- The file is named llms.txt and saved at repository root.
- The H1 appears once and comes first.
- The blockquote summary is short and informative.
- No headings appear between the summary/details block and the first H2 section except the H2 itself.
- Every H2 section contains a Markdown list.
- Every link is valid.
- Descriptions are concise and specific.
- Optional is used only for secondary or skippable context.

## Decision Points

### If the repository has strong top-level docs

- Prioritize README, install/setup docs, architecture docs, and example guides.
- Use source files only to represent subsystems that lack documentation.

### If the repository is source-heavy and doc-light

- Use project metadata plus a few representative entry points from src/.
- Prefer files that define public interfaces, CLI entrypoints, orchestration layers, or core abstractions.
- Avoid listing many sibling implementation files when one package entrypoint is enough.

### If the repository is a monorepo or multi-surface project

- Start with the top-level README and root build/config files.
- Then include one or two canonical docs or entrypoints per major area.
- Do not flatten the entire monorepo into one giant list.

### If there is an existing llms.txt

- Read it, keep useful structure, and refresh stale links or vague descriptions.
- Preserve what is already effective unless the spec or repository changed enough to justify a rewrite.

## CAI Repository Notes

For this repository, usually inspect these paths early before drafting:

- README.md for project purpose, positioning, and major workflows
- INSTALL.md for setup guidance
- pyproject.toml for packaging and dependency shape
- mkdocs.yml for documentation structure hints
- src/cai/ for the main package layout
- tests/README.md and selected tests for usage and validation signals
- dockerized/ and ci/ for deployment and automation context
- docs/ if it exists in the current worktree

Be careful not to confuse runtime application material under src/cai/skills/ with VS Code customization skills under .github/skills/.

If docs/ is missing in the current workspace, omit it instead of linking to deleted paths.

## Quality Bar

The finished llms.txt should let an LLM quickly answer:

- What is this project?
- Where should I start reading?
- Where are the architecture and setup docs?
- Where are the important examples or tests?
- Which files are optional if context is tight?

If the file feels like a raw sitemap, it is too broad. If it omits setup, architecture, and representative entry points, it is too shallow.