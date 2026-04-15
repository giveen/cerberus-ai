---
name: create-readme
description: 'Create or rewrite a repository README.md from the current workspace. Use for open source README authoring, GitHub landing page refreshes, concise project overviews, setup and quickstart documentation, README rewrites from repo structure, and adapting polished sample README patterns without overusing badges or emojis.'
argument-hint: 'Optional focus or audience, for example: refresh existing README, developer-first README, concise OSS landing page, or app/project overview'
---

# Create README

Create a root README.md that is appealing, informative, concise, and grounded in the actual repository state.

This skill is for writing the README itself, not for documenting every file in the repository and not for copying a generic template unchanged.

## When to Use

- The project needs its first README.md.
- The existing README is outdated, bloated, too marketing-heavy, or hard to skim.
- The repository needs a clearer GitHub landing page for contributors and users.
- You need a README written from the actual codebase structure, setup flow, and project capabilities.

## Required Outcome

Produce a README.md that:

- Explains what the project is in the first screenful.
- Helps a new reader get started quickly.
- Uses GitHub Flavored Markdown.
- Uses GitHub admonition syntax when it improves clarity.
- Stays concise and avoids padding.
- Uses a project logo or icon in the header if one is available and appropriate.
- Does not add dedicated sections for LICENSE, CONTRIBUTING, CHANGELOG, or similar material that already belongs in separate files.

## Style Targets

Follow these style principles:

- Prefer crisp, high-signal sections over long narrative prose.
- Use a polished open source tone: clear, concrete, and useful.
- Keep emojis minimal.
- Use badges sparingly. Keep only the ones that help scanning.
- Favor short feature bullets, direct setup steps, and practical quickstart commands.
- Link to dedicated docs instead of duplicating entire manuals inside the README.

For inspiration patterns, review [README patterns](./references/inspiration-patterns.md).

## Procedure

### 1. Audit the repository before writing

- Inspect the full repository and workspace structure.
- Read the current README.md if it exists, but treat it as source material, not as a fixed template.
- Identify the project type: library, framework, CLI, application, service, sample collection, or monorepo.
- Determine the primary audience: users, developers, contributors, operators, or a mix.

Start with these files and directories when available:

- README.md
- INSTALL.md
- WHATS-NEW.md
- pyproject.toml, package.json, Cargo.toml, go.mod, or equivalent project metadata
- mkdocs.yml, docs/, doc site config, or architecture docs
- src/, app/, packages/, services/, tools/, tests/, examples/
- dockerized/, devcontainer config, CI workflows, and sample environment files
- media/, docs/assets/, public/, or similar locations for logos and screenshots

### 2. Extract the core project story

Capture the minimum set of facts a reader needs immediately:

- What the project does
- Why someone would use it
- Who it is for
- What makes it distinctive
- How to install or run it first

If the repository is complex, summarize major subsystems in one short section instead of expanding every module.

### 3. Decide the README structure

Use only sections that add value. Common useful sections are:

- Header with name, logo, and restrained badges
- Overview
- Key features
- Getting started or installation
- Quickstart or usage
- Architecture or project structure
- Documentation or further reading
- Troubleshooting or support

Omit sections that would only repeat standalone files.

### 4. Build the header intentionally

- If a logo or icon exists, use it in the header.
- Keep the title and one-sentence positioning statement near the top.
- If using badges, keep them short and relevant.
- Avoid large noisy badge walls unless the repository already depends on them for discovery.

### 5. Write the README from scratch

- Reuse facts, not stale phrasing.
- Prefer short paragraphs and flat bullet lists.
- Keep setup instructions executable and scoped to the supported paths in the repo.
- Use admonitions for important warnings, notes, or quick guidance where they improve scanning.
- Link to deeper docs for advanced material.

### 6. Validate content against the repository

Before finishing, verify:

- Referenced files and directories exist.
- Commands align with the actual tooling in the repo.
- Links are valid.
- The header asset path is correct.
- The README does not claim unsupported features.
- The first screen tells the reader what the project is and how to begin.

## Decision Points

### If a README already exists

- Mine it for accurate facts, links, and assets.
- Remove redundancy, weak framing, and outdated sections.
- Rewrite rather than patching sentence-by-sentence if the structure is poor.

### If the repository has a strong docs site

- Keep the README focused on overview and getting started.
- Link out to dedicated docs for deep reference, architecture, and extended tutorials.

### If the repository is a framework or platform

- Emphasize use cases, major capabilities, and the quickest path to first success.
- Avoid drowning the header in research, marketing, or long comparison material.

### If the repository is a sample or template

- Lead with what it demonstrates, prerequisites, and how to run it locally.
- Include deploy or environment variants only when they are clearly supported.

### If there is a usable logo or icon

- Prefer a small clean header treatment.
- Use one primary visual, not several banners or animated assets unless the repository clearly benefits from them.

### If there is no suitable logo or icon

- Use a text-only header.
- Do not invent decorative assets.

## CAI Repository Notes

For this repository, inspect these paths early:

- README.md for current positioning and sections that may need to be simplified
- INSTALL.md for setup guidance
- WHATS-NEW.md for recent capability changes worth reflecting indirectly
- pyproject.toml for packaging and dependencies
- mkdocs.yml for documentation structure hints
- src/cai/ for the actual product surface
- tests/README.md and representative tests for usage patterns
- dockerized/ for container and deployment flows
- media/cai.png and media/cai-banner.svg for possible header visuals

The current CAI README is large and heavily promotional. A strong rewrite should preserve important facts while becoming easier to scan and quicker to trust.

## Quality Bar

The finished README should let a new reader answer these questions quickly:

- What is this project?
- Why would I use it?
- How do I install or run it?
- Where do I go next for deeper docs?

If the README feels like a changelog, marketing page, or docs dump, it is off target.

If it omits setup, quickstart, and clear positioning, it is incomplete.