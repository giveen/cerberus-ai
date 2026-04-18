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
    ldap-utils \
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

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /workspace/rxconfig.py /workspace/rxconfig.py
COPY --from=builder /workspace/cerberus_reflex /workspace/cerberus_reflex
COPY --from=builder /workspace/src/cerberus/dashboard /workspace/src/cerberus/dashboard
COPY --from=builder /workspace/.web /workspace/.web

EXPOSE 8000 8001

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/cerberus-entrypoint"]
CMD ["reflex", "run", "--env", "prod", "--backend-host", "0.0.0.0", "--frontend-port", "8000", "--backend-port", "8001"]


# --- STAGE 4: Runtime ---
FROM kalilinux/kali-rolling AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    CERBERUS_WORKSPACE_ROOT=/workspace/workspaces \
    CERBERUS_MCP_AUTOLOAD_ENABLED=1 \
    CERBERUS_MCP_BOOTSTRAP_ROOT=/opt/cerberus-mcp \
    VIRTUAL_ENV=/opt/cerberus-venv \
    PATH="/opt/cerberus-venv/bin:$PATH"

WORKDIR /workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    docker.io \
    git \
    gnupg \
    kali-linux-headless \
    kali-tools-top10 \
    python3 \
    python3-pip \
    python3-venv \
    tshark \
    tini \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
        x86_64) docker_arch="x86_64" ;; \
        aarch64) docker_arch="aarch64" ;; \
        *) echo "Unsupported arch for Docker CLI: $arch"; exit 1 ;; \
    esac; \
    curl -fsSL "https://download.docker.com/linux/static/stable/${docker_arch}/docker-27.5.1.tgz" -o /tmp/docker.tgz; \
    tar -xzf /tmp/docker.tgz -C /tmp; \
    mv /tmp/docker/docker /usr/local/bin/docker; \
    chmod +x /usr/local/bin/docker; \
    rm -rf /tmp/docker /tmp/docker.tgz

COPY . .
COPY dockerized/entrypoint.sh /usr/local/bin/cerberus-entrypoint

RUN chmod +x /usr/local/bin/cerberus-entrypoint \
    && python3 -m venv "$VIRTUAL_ENV" \
    && "$VIRTUAL_ENV/bin/python" -m pip install --no-cache-dir --upgrade pip setuptools wheel \
    && "$VIRTUAL_ENV/bin/python" -m pip install --no-cache-dir . \
    && "$VIRTUAL_ENV/bin/python" -m cerberus.mcp_bootstrap --prepare-supported \
    && pip install --no-cache-dir playwright beautifulsoup4 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* /var/cache/apt/archives/partial/* \
    && playwright install chromium \
    && command -v docker \
    && command -v nmap \
    && command -v node \
    && command -v msfconsole \
    && command -v sqlmap

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/cerberus-entrypoint"]