# Awesome-Copilot Patterns

Use this note when invoking the skill so the setup is grounded in real awesome-copilot patterns instead of guessed file formats.

## Mandatory Research Order

Fetch these pages first, in this order:

1. `https://github.com/github/awesome-copilot/blob/main/docs/README.instructions.md`
2. `https://github.com/github/awesome-copilot/blob/main/docs/README.agents.md`
3. `https://github.com/github/awesome-copilot/blob/main/docs/README.skills.md`
4. `https://github.com/github/awesome-copilot/tree/main/instructions`
5. `https://github.com/github/awesome-copilot/tree/main/agents`
6. `https://github.com/github/awesome-copilot/tree/main/skills`

Only start authoring after this pass is complete.

## Source Selection Rules

- Prefer exact technology matches first.
- If the stack spans multiple concerns, combine one primary technology file with a small number of cross-cutting sources.
- Prefer repo-native existing files over remote examples when the repository already has strong conventions.
- Do not fabricate framework-specific guidance when awesome-copilot or the repository already provides better material.
- Keep a source ledger so every adapted instruction or agent file can carry the correct attribution comment.

## Common Instruction Candidates

These are frequent starting points, not a mandatory list.

### Language and framework

- `csharp.instructions.md`
- `go.instructions.md`
- `nextjs.instructions.md`
- `nestjs.instructions.md`
- `springboot.instructions.md`
- `quarkus.instructions.md`
- `nodejs-javascript-vitest.instructions.md`
- `rust.instructions.md`
- `ruby-on-rails.instructions.md`
- `wordpress.instructions.md`

### Cross-cutting

- `security-and-owasp.instructions.md`
- `performance-optimization.instructions.md`
- `code-review-generic.instructions.md`
- `markdown-gfm.instructions.md`
- `github-actions-ci-cd-best-practices.instructions.md`
- `containerization-docker-best-practices.instructions.md`
- `a11y.instructions.md`
- `update-docs-on-code-change.instructions.md`

## Common Agent Candidates By Role

Create the local files with these exact names:

- `software-engineer.agent.md`
- `architect.agent.md`
- `reviewer.agent.md`
- `debugger.agent.md`

Map each role to the best available source agent.

### Software engineer

- Prefer stack experts such as `expert-react-frontend-engineer.agent.md`, `expert-nextjs-developer.agent.md`, `expert-dotnet-software-engineer.agent.md`, `laravel-expert-agent.agent.md`, or similar.
- Use `software-engineer-agent-v1.agent.md` when no better stack expert exists.

### Architect

- Prefer `project-architecture-planner.agent.md` or a strong stack-specific architect.
- Use `arch.agent.md` when a general architecture agent is needed.

### Reviewer

- Prefer `gem-reviewer.agent.md`, `se-security-reviewer.agent.md`, or another review-oriented agent that matches the stack and risk profile.
- If the project is compliance or security heavy, bias toward a reviewer with stronger audit language.

### Debugger

- Prefer stack-specific debugging or runtime investigation agents when available.
- Use `debug.agent.md` as the generic fallback.

## Common Skill Candidates

These are useful references when shaping the six required local skills:

- `github-copilot-starter`
- `copilot-instructions-blueprint-generator`
- `create-agentsmd`
- `readme-blueprint-generator`
- `suggest-awesome-github-copilot-instructions`
- `suggest-awesome-github-copilot-agents`
- `suggest-awesome-github-copilot-skills`

Use them for structure and scope, not for blind copying.

## Attribution Rules

Add attribution comments whenever content is adapted from awesome-copilot.

### Instructions

```md
<!-- Based on/Inspired by: https://github.com/github/awesome-copilot/blob/main/instructions/[filename].instructions.md -->
```

If combining sources:

```md
<!-- Inspired by: https://github.com/github/awesome-copilot/blob/main/instructions/[first].instructions.md -->
<!-- and: https://github.com/github/awesome-copilot/blob/main/instructions/[second].instructions.md -->
```

### Agents

```md
<!-- Based on/Inspired by: https://github.com/github/awesome-copilot/blob/main/agents/[filename].agent.md -->
```

## What To Avoid

- Do not skip the research pass.
- Do not copy large remote files unchanged when only part of them applies.
- Do not create `.instructions.md` files filled with code examples, templates, or framework boilerplate.
- Do not add MCP or tool metadata to agents unless the target Copilot environment actually supports and needs it.
- Do not create a workflow unless the user confirmed GitHub Actions is used.