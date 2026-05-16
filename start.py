import os, subprocess, sys
port = os.environ.get("PORT", "8080")
workers = os.environ.get("WEB_CONCURRENCY", "2")
sys.exit(subprocess.call([
    "uvicorn", "app.main:app",
    "--host", "0.0.0.0",
    "--port", port,
    "--workers", workers,
]))
