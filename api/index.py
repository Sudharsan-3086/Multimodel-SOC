"""
api/index.py
-------------
Vercel Functions ASGI entrypoint.

Vercel's Python runtime (`@vercel/python`) auto-detects an ASGI-compatible
`app` object exported from this module and serves it directly - no WSGI
adapter or Mangum handler needed for FastAPI/Starlette apps. All routes
defined on the shared `main.app` (including /api/health, /api/investigate,
/api/graph/query) are available unchanged in serverless mode.

This module intentionally contains no route logic of its own: the single
source of truth for the API surface is `main.py`, imported here so local
(`uvicorn main:app`) and serverless (Vercel) execution stay in lockstep.
"""

import os
import sys

# Ensure the project root is importable when Vercel packages this file in
# isolation (its build step includes the repo root, but we defend against
# alternate bundling layouts defensively).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app  # noqa: E402  (re-exported for Vercel's ASGI detection)

# Vercel looks for a top-level `app` (ASGI) or `handler` callable.
__all__ = ["app"]
