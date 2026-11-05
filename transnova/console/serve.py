"""uvicorn console.serve:app. Fails at startup, by setting name, when configuration is missing."""

from .app import create_app

app = create_app()
