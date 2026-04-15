# --- STAGE 1: Base ---
FROM python:3.12-slim AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    CERBERUS_WORKSPACE_ROOT=/workspace/workspaces

WORKDIR /workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    tini \
    && rm -rf /var/lib/apt/lists/*

COPY dockerized/entrypoint.sh /usr/local/bin/cerberus-entrypoint
RUN chmod +x /usr/local/bin/cerberus-entrypoint


# --- STAGE 2: Builder ---
FROM base AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gnupg \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN python -m pip install --no-cache-dir .
RUN reflex export --frontend-only --no-zip


# --- STAGE 3: Frontend ---
FROM base AS frontend

RUN apt-get update && apt-get install -y --no-install-recommends \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /workspace/rxconfig.py /workspace/rxconfig.py
COPY --from=builder /workspace/cerberus_dashboard /workspace/cerberus_dashboard
COPY --from=builder /workspace/.web /workspace/.web

EXPOSE 8000 8001

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/cerberus-entrypoint"]
CMD ["reflex", "run", "--env", "prod", "--backend-host", "0.0.0.0", "--frontend-port", "8000", "--backend-port", "8001"]


# --- STAGE 4: Runtime ---
FROM kalilinux/kali-rolling AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    CERBERUS_WORKSPACE_ROOT=/workspace/workspaces

WORKDIR /workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    kali-linux-headless \
    kali-tools-top10 \
    python3 \
    python3-pip \
    tini \
    && rm -rf /var/lib/apt/lists/*

COPY . .
COPY dockerized/entrypoint.sh /usr/local/bin/cerberus-entrypoint

RUN chmod +x /usr/local/bin/cerberus-entrypoint \
    && python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel \
    && python3 -m pip install --no-cache-dir --ignore-installed . \
    && command -v nmap \
    && command -v msfconsole \
    && command -v sqlmap

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/cerberus-entrypoint"]