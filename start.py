import os, subprocess, sys
port = os.environ.get("PORT", "8080")
sys.exit(subprocess.call([
    "uvicorn", "app.main:app",
    "--host", "0.0.0.0",
    "--port", port,
    "--workers", "4",
]))
