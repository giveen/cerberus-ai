import os

import reflex as rx
from reflex.constants import StateManagerMode

try:
    from reflex.plugins.sitemap import SitemapPlugin
except Exception:  # pragma: no cover - optional plugin import across Reflex versions.
    SitemapPlugin = None


REDIS_URL = os.getenv("REDIS_URL", "").strip() or os.getenv("REFLEX_REDIS_URL", "").strip()


config = rx.Config(
    app_name="cerberus_reflex",
    frontend_port=8000,
    backend_port=8001,
    redis_url=REDIS_URL or None,
    state_manager_mode=StateManagerMode.REDIS if REDIS_URL else StateManagerMode.DISK,
    show_built_with_reflex=False,
    disable_plugins=[SitemapPlugin] if SitemapPlugin is not None else [],
)