"""Entrada compatível para ``uvicorn api:app``."""

from api_modules.app import app, create_app

__all__ = ["app", "create_app"]
