"""WSGI entrypoint for production web servers."""

from hashcrush import create_app

app = create_app()
