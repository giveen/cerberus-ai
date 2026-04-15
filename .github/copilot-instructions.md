<todos title="Dockerfile multistage kali runtime" rule="Review steps frequently throughout the conversation and DO NOT stop between steps unless they explicitly require it.">
- [x] inspect-current-docker-build: Inspect the active dockerized Dockerfile, compose targets, and prior repo notes to confirm the current stage layout and constraints before editing. 🔴
  _Confirmed the compose services still target `frontend` and `runtime`, the active worktree uses the older four-stage Dockerfile shape, and prior notes about `unzip` plus Kali package conflicts still applied._
- [x] refactor-dockerfile-stages: Refactor dockerized/Dockerfile into base, builder, frontend, and runtime stages with a Reflex frontend build and kalilinux/kali-rolling runtime. 🔴
  _Rewrote the Dockerfile so `base` stays on `python:3.12-slim`, `builder` handles Node 20 and `reflex export`, `frontend` copies only the exported frontend plus minimal app/runtime pieces, and `runtime` stays on Kali with the requested meta-packages and tini entrypoint._
- [x] verify-docker-targets: Validate the frontend and runtime targets, including entrypoint wiring and expected security tools in PATH. 🔴
  _Validated with direct `docker build --target frontend` and `docker build --target runtime`, `docker inspect` for the tini entrypoint, and runtime probes for `nmap`, `msfconsole`, and `sqlmap`; `nmap --version` required a privileged run, which matches the compose runtime configuration._
- [x] run-compose-stack-validation: Bring up the full docker compose runtime profile stack and verify the dashboard and Kali runtime services together in the live compose environment. 🔴
  _`docker compose -f dockerized/docker-compose.yml --profile runtime up -d --build` now leaves both `cerberus-dashboard` and `cerberus` up, Playwright reaches the dashboard with HTTP 200, and runtime probes inside the live `cerberus` container confirm the CLI plus `nmap`, `msfconsole`, and `sqlmap` are available together._
- [ ] refactor-ui-components-presentational: Refactor UI components into presentational modules. 🟡
  _Existing follow-up from the dashboard redesign work._
- [ ] add-playwright-layout-tests: Add Playwright E2E tests for layouts covering 0-4 sessions. 🟡
  _Existing follow-up from the dashboard redesign work._
- [ ] update-build-export-docs-and-ci: Update build/export docs and CI for reflex export validation. 🟡
  _Existing follow-up from the dashboard redesign work._
</todos>

<!-- Auto-generated todo section -->
<!-- Add your custom Copilot instructions below -->
