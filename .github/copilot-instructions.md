<todos title="Rebuild docker and push changes" rule="Review steps frequently throughout the conversation and DO NOT stop between steps unless they explicitly require it.">
- [x] inspect-docker-and-git-state: Inspect docker compose files, repo state, and any existing notes needed before rebuild and push. 🔴
  _Canonical compose path is dockerized/docker-compose.yml with --profile runtime. Found and fixed a cerberus.util package shadowing issue blocking Reflex export in Docker._
- [x] rebuild-and-launch-docker: Rebuild the dockerized stack and launch it, then verify the services start successfully. 🔴
  _`docker compose -f ./dockerized/docker-compose.yml --profile runtime up -d --build` succeeded. Verified `cerberus-dashboard` and `cerberus` are healthy and `curl -I http://localhost:8000/` returns 200._
- [-] commit-and-push-worktree: Commit all requested changes with a clear message and push to the current branch. 🔴
  _Worktree includes code changes plus new tracked files and generated .cerberus artifacts. Proceeding to stage, commit, and push current state on main._
</todos>

<!-- Auto-generated todo section -->
<!-- Add your custom Copilot instructions below -->
