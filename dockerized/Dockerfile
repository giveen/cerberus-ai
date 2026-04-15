FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Fix Kali GPG Keys
RUN apt-get update --allow-insecure-repositories && \
    apt-get install -y --no-install-recommends --allow-unauthenticated kali-archive-keyring && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Core system + Python
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-dev python3-venv \
        nodejs npm \
        curl wget git ca-certificates \
        iputils-ping nmap net-tools dnsutils netcat-openbsd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Some Debian/Kali node packages expose `nodejs` without `node`.
RUN if [ ! -x /usr/bin/node ] && [ -x /usr/bin/nodejs ]; then ln -s /usr/bin/nodejs /usr/bin/node; fi

# Install kali-linux-headless (brings most pentesting tools + dependencies)
# This includes: nmap, nikto, dirb, gobuster, sqlmap, netcat, ssh, etc.
RUN apt-get update && \
    echo "console-setup console-setup/variant select Latin1 and Latin5 - western Europe and Turkic languages" | debconf-set-selections && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        kali-linux-headless \
        seclists \
        burpsuite \
        default-jre \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Metasploit
 RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && \
     chmod 755 /tmp/msfinstall && \
     /tmp/msfinstall && \
     rm /tmp/msfinstall

# Playwright dependency install can fail if the Metasploit apt source is left in a broken state.
RUN rm -f /etc/apt/sources.list.d/metasploit-framework.list /usr/share/keyrings/metasploit-framework.gpg || true

# FIX: pip system-packages warning
RUN mkdir -p /root/.pip && \
    echo "[global]" > /root/.pip/pip.conf && \
    echo "break-system-packages = true" >> /root/.pip/pip.conf



WORKDIR /opt/cai

# Copy local repository source so the container runs workspace code.
COPY . /opt/cai-src

# Install local Cerebro code + browser dependencies in an isolated venv
RUN python3 -m venv /opt/cai/.venv && \
    /opt/cai/.venv/bin/pip install --upgrade pip && \
    /opt/cai/.venv/bin/pip install -e "/opt/cai-src[browser]" playwright "litellm<1.83,>=1.68.0" "mcp>=1.27.0" && \
    /opt/cai/.venv/bin/python -m playwright install --with-deps chromium

# .env Template (overwritten if .env file present in logs)
RUN echo 'OPENAI_API_KEY="sk-1234"' > /opt/cai/.env && \
    echo 'ANTHROPIC_API_KEY=""' >> /opt/cai/.env && \
    echo 'DEEPSEEK_API_KEY=""' >> /opt/cai/.env && \
    echo 'OLLAMA_API_BASE=""' >> /opt/cai/.env && \
    echo 'PROMPT_TOOLKIT_NO_CPR=1' >> /opt/cai/.env && \
    echo 'CEREBRO_STREAM=false' >> /opt/cai/.env

#  logs directory
RUN mkdir -p /opt/cai/logs

# Startup Script
RUN echo '#!/bin/bash' > /opt/cai/start.sh && \
    echo 'if [ -f /config/.env ]; then' >> /opt/cai/start.sh && \
    echo '  echo "Loading .env from /config/.env"' >> /opt/cai/start.sh && \
    echo '  cp /config/.env /opt/cai/.env' >> /opt/cai/start.sh && \
    echo 'elif [ -d /config/.env ]; then' >> /opt/cai/start.sh && \
    echo '  for candidate in /config/.env/.env /config/.env/*.env /config/.env/*; do' >> /opt/cai/start.sh && \
    echo '    if [ -f "$candidate" ]; then' >> /opt/cai/start.sh && \
    echo '      echo "Loading .env from $candidate"' >> /opt/cai/start.sh && \
    echo '      cp "$candidate" /opt/cai/.env' >> /opt/cai/start.sh && \
    echo '      break' >> /opt/cai/start.sh && \
    echo '    fi' >> /opt/cai/start.sh && \
    echo '  done' >> /opt/cai/start.sh && \
    echo 'fi' >> /opt/cai/start.sh && \
    echo 'if [ -f /opt/cai/.env ]; then' >> /opt/cai/start.sh && \
    echo '  set -a' >> /opt/cai/start.sh && \
    echo '  . /opt/cai/.env' >> /opt/cai/start.sh && \
    echo '  set +a' >> /opt/cai/start.sh && \
    echo 'fi' >> /opt/cai/start.sh && \
    echo 'if [ -z "${CEREBRO_API_KEY:-}" ] && [ -n "${ALIAS_API_KEY:-}" ]; then export CEREBRO_API_KEY="$ALIAS_API_KEY"; fi' >> /opt/cai/start.sh && \
    echo 'if [ -z "${OPENAI_API_KEY:-}" ] && [ -n "${CEREBRO_API_KEY:-}" ]; then export OPENAI_API_KEY="$CEREBRO_API_KEY"; fi' >> /opt/cai/start.sh && \
    echo 'if [ -n "${CEREBRO_API_BASE:-}" ]; then export OPENAI_BASE_URL="$CEREBRO_API_BASE"; fi' >> /opt/cai/start.sh && \
    echo 'if [ -z "${CEREBRO_MODEL:-}" ] && [ -n "${CAI_MODEL:-}" ]; then export CEREBRO_MODEL="$CAI_MODEL"; fi' >> /opt/cai/start.sh && \
    echo 'if [ -z "${CEREBRO_MODEL:-}" ]; then export CEREBRO_MODEL="Qwen3.5-27B-Aggressive-Q4_K_M"; fi' >> /opt/cai/start.sh && \
    echo 'if [ -z "${CEREBRO_SUPPORT_MODEL:-}" ]; then export CEREBRO_SUPPORT_MODEL="Qwen2.5-Coder-1.5B-Q4_K_M"; fi' >> /opt/cai/start.sh && \
    echo 'if [ -z "${CAI_MODEL:-}" ]; then export CAI_MODEL="$CEREBRO_MODEL"; fi' >> /opt/cai/start.sh && \
    echo 'if [ -z "${OPENAI_API_KEY:-}" ] && [ -z "${CEREBRO_API_KEY:-}" ]; then echo "Warning: no API key configured (set CEREBRO_API_KEY, OPENAI_API_KEY, or ALIAS_API_KEY)."; fi' >> /opt/cai/start.sh && \
    echo 'cd /opt/cai' >> /opt/cai/start.sh && \
    echo 'if [ "${CEREBRO_WEB,,}" = "true" ] || [ "$CEREBRO_WEB" = "1" ]; then' >> /opt/cai/start.sh && \
    echo '  echo "CEREBRO_WEB is no longer supported in dockerized/. Use the repository-root Dockerfile or docker-compose.yml for the Reflex dashboard." >&2' >> /opt/cai/start.sh && \
    echo '  exit 1' >> /opt/cai/start.sh && \
    echo 'fi' >> /opt/cai/start.sh && \
    echo 'exec /opt/cai/.venv/bin/cai "$@"' >> /opt/cai/start.sh && \
    chmod +x /opt/cai/start.sh

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /opt/cai/.venv/bin/python -c "import cai; print('OK')" || exit 1

ENTRYPOINT ["/opt/cai/start.sh"]
CMD []