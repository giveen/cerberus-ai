Installation — Full Setup
=========================

Follow these steps to install the project in editable mode with all runtime extras (browser, crawler, vault, voice, viz), install Playwright browsers, and build the local Cyber‑Vault knowledge index.

# create + activate venv (optional but recommended)
python -m venv .venv
source .venv/bin/activate

# editable install with all runtime extras
pip install -e ".[browser,crawler,vault,voice,viz]"

# install Playwright browser binaries (required for the browser tool)
python -m playwright install chromium

# build the local Cyber-Vault (downloads indexes/models)
python scripts/ingest_vault.py
# or to incrementally sync later:
# bash scripts/vault_sync.sh

Notes
-----
- The `browser` extra installs the Playwright Python package; the browser runtime (Chromium) is installed by the `playwright install` command above.
- The `vault` extra pulls in ChromaDB and sentence-transformers; building the Cyber-Vault will download additional model artifacts and may require a network connection and sufficient disk space.
- If you want developer tooling (linters, test runners, docs tools), install the `dev` dependencies listed in `pyproject.toml` separately.

Troubleshooting
---------------
- If pip fails to resolve an extra, ensure you are using a modern pip (>=23) and an activated virtual environment.
- Playwright requires an extra step to install browser binaries (`python -m playwright install chromium`).


Recommended Local LLM:
HauhauCS/wen3.5-27B-Uncensored-HauhauCS-Aggressive-Q4_K_M for primary model
Qwen/Qwen2.5-Coder-1.5B-Instruct for support model