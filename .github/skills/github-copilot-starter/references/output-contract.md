# Output Contract

This note defines the minimum file set, content boundaries, and validation rules for the generated GitHub Copilot configuration.

## Minimum Directory Structure

```text
project-root/
├── .github/
│   ├── copilot-instructions.md
│   ├── instructions/
│   │   ├── [language].instructions.md
│   │   ├── testing.instructions.md
│   │   ├── documentation.instructions.md
│   │   ├── security.instructions.md
│   │   ├── performance.instructions.md
│   │   └── code-review.instructions.md
│   ├── skills/
│   │   ├── setup-component/
│   │   │   └── SKILL.md
│   │   ├── write-tests/
│   │   │   └── SKILL.md
│   │   ├── code-review/
│   │   │   └── SKILL.md
│   │   ├── refactor-code/
│   │   │   └── SKILL.md
│   │   ├── generate-docs/
│   │   │   └── SKILL.md
│   │   └── debug-issue/
│   │       └── SKILL.md
│   ├── agents/
│   │   ├── software-engineer.agent.md
│   │   ├── architect.agent.md
│   │   ├── reviewer.agent.md
│   │   └── debugger.agent.md
│   └── workflows/
│       └── copilot-setup-steps.yml
```

Create the workflow only when GitHub Actions is in use.

## Main Repository Instructions

The root `.github/copilot-instructions.md` should follow this outline:

```md
# {Project Name} - Copilot Instructions

## Project Overview
Brief description of the project and what it is for.

## Tech Stack
Primary language, framework, and important dependencies.

## Conventions
- Naming
- Structure
- Error handling

## Workflow
- PR conventions
- Branch naming
- Commit style
- Links to detailed instruction files
```

Keep this file central and concise. Push specific standards into `.github/instructions/`.

## Instruction File Template

Use YAML frontmatter and keep the body high-level.

```md
---
applyTo: "**/*.{lang-ext}"
description: "Development standards for {Language}"
---
# {Language} coding standards

Apply the repository-wide guidance from `../copilot-instructions.md`.

## General Guidelines
- Follow the established patterns
- Prefer clear, readable code
- Use idiomatic language practices
- Keep modules focused
```

### Allowed in `.instructions.md`

- High-level principles
- Naming and structure conventions
- Testing expectations
- Documentation requirements
- Security and performance guidance

### Forbidden in `.instructions.md`

- Code examples or snippets
- Detailed implementation recipes
- Test cases or concrete test code
- Boilerplate templates
- Import lists or dependency dumps

## Required Skill Topics

Create these six local skills and tailor them to the stack:

- `setup-component`: scaffold a new component, module, service, or feature slice
- `write-tests`: add or update tests using the repo's testing stack
- `code-review`: review code with findings-first output and project standards
- `refactor-code`: perform safe structural refactors without changing behavior
- `generate-docs`: create or refresh README, API docs, or internal docs
- `debug-issue`: reproduce, analyze, fix, validate, and summarize bugs

Each skill should:

- have keyword-rich frontmatter
- ask for missing inputs when needed
- follow repository patterns
- include a short requirements section

## Agent Fallback Template

If no strong awesome-copilot agent exists for a role, use a concise fallback structure like this and adapt the body to the role:

```md
---
description: Generate an implementation plan for new features or refactoring existing code.
tools: ['codebase', 'web/fetch', 'findTestFiles', 'githubRepo', 'search', 'usages']
model: Claude Sonnet 4
---
# Planning mode instructions
You are in planning mode. Your task is to generate an implementation plan for a new feature or for refactoring existing code.
Don't make any code edits, just generate a plan.
```

Only include tool or model metadata when the target Copilot environment supports it.

## Workflow Contract

If GitHub Actions is enabled, the workflow must use this exact outer structure:

```yaml
name: "Copilot Setup Steps"
on:
  workflow_dispatch:
  push:
    paths:
      - .github/workflows/copilot-setup-steps.yml
  pull_request:
    paths:
      - .github/workflows/copilot-setup-steps.yml
jobs:
  copilot-setup-steps:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Checkout code
        uses: actions/checkout@v5
```

### Include only

- Runtime setup
- Dependency installation
- Basic linting when standard for the stack
- Basic test execution
- Standard build commands when they are cheap and expected

### Avoid

- Service containers or databases
- Multi-environment matrices
- Custom scripts or complex logic
- Deployment steps
- Advanced infrastructure setup

## Final Handoff

After authoring, the response should include:

1. What the setup created
2. How to use the new skills and agents
3. How to customize the files further
4. How to verify the configuration works in VS Code

## Validation Checklist

- All required authored markdown files have valid frontmatter where required.
- Descriptions are meaningful enough for discovery.
- File references between `.github` documents are correct.
- Instructions are specific but not bloated.
- Skills and agents are aligned to the actual stack.
- Security, performance, testing, and documentation are all covered.
- Attribution comments are present wherever awesome-copilot content was adapted.
- The optional workflow uses the exact job name `copilot-setup-steps`.