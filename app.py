"""Compatibility ASGI entry point for the Flask API."""

from starlette.middleware.wsgi import WSGIMiddleware

from backend.app import app as flask_app

app = WSGIMiddleware(flask_app)
