"""Serve the built React application from the API process (single-origin deployment).

Used on hosts that run one web service (for example Render's free tier). Same-origin hosting
means the SameSite=Strict refresh cookie works and no CORS is needed. In development the Vite
server is used instead, and in Docker Compose nginx serves the files.
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles


def mount_frontend(app: FastAPI, directory: str, api_prefix: str) -> bool:
    root = Path(directory).resolve()
    index = root / "index.html"
    if not index.is_file():
        return False
    if (root / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=root / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        if full_path.startswith(api_prefix.strip("/")):
            raise HTTPException(status_code=404, detail="Not found")
        candidate = (root / full_path).resolve()
        # Serve real top-level files (favicon, robots.txt); never anything outside the folder.
        if full_path and candidate.is_file() and candidate.is_relative_to(root):
            return FileResponse(candidate)
        return FileResponse(index, headers={"Cache-Control": "no-cache"})

    return True
