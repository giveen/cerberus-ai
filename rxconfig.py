import reflex as rx
from reflex.plugins.sitemap import SitemapPlugin


config = rx.Config(
    app_name="app",
    frontend_port=3000,
    backend_port=8000,
    disable_plugins=[SitemapPlugin],
)