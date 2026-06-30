"""
main.py — BSAAP FastAPI application entry point.

Run with:
    uvicorn main:app --reload --port 8000

Or directly:
    python main.py
"""

import uvicorn
from bsaap.api.endpoints import app  # noqa: F401 — app is exported for uvicorn


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
    )
