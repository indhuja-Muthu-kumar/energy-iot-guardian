import os

from app import create_app

if os.getenv("FLASK_ENV", "").strip().lower() != "production":
    raise RuntimeError(
        "The WSGI entry point requires FLASK_ENV=production. "
        "Use the Flask CLI for local development."
    )

app = create_app()
