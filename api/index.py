"""
TrustShield Vercel Serverless Entrypoint
Exports the ASGI FastAPI application for Vercel serverless execution.
"""

import sys
from pathlib import Path

# Ensure project root is on sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend.app.main import app  # noqa: E402
