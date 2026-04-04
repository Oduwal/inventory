"""
Database Backup Script for Inventory Keeper
============================================
Creates a timestamped backup of your PostgreSQL database.

Usage:
  - Manual:   python backup_database.py
  - Railway:  Add as a cron job or run via Railway CLI

Backups are stored in the 'backups/' folder with timestamps.
Keeps the last 7 backups and deletes older ones automatically.

For PostgreSQL (production):  Uses pg_dump via DATABASE_URL
For SQLite (local dev):       Copies the .db file
"""

import os
import sys
import shutil
import subprocess
import logging
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("backup")

BACKUP_DIR = Path(__file__).parent / "backups"
MAX_BACKUPS = 7  # Keep last 7 backups

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./inventory.db")


def backup_sqlite():
    """Copy the SQLite file with a timestamp."""
    db_path = Path(__file__).parent / "inventory.db"
    if not db_path.exists():
        log.warning("SQLite file not found at %s — nothing to back up.", db_path)
        return None

    BACKUP_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    dest = BACKUP_DIR / f"inventory_backup_{ts}.db"
    shutil.copy2(db_path, dest)
    log.info("SQLite backup saved: %s (%.1f MB)", dest.name, dest.stat().st_size / 1024 / 1024)
    return dest


def backup_postgres():
    """Use pg_dump to create a compressed SQL backup."""
    BACKUP_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    dest = BACKUP_DIR / f"inventory_backup_{ts}.sql.gz"

    # pg_dump reads DATABASE_URL via the connection string
    # Convert sqlalchemy URL format to psql format if needed
    db_url = DATABASE_URL
    if db_url.startswith("postgresql+psycopg2://"):
        db_url = db_url.replace("postgresql+psycopg2://", "postgresql://", 1)

    try:
        # pg_dump → gzip pipeline
        dump_proc = subprocess.Popen(
            ["pg_dump", "--no-owner", "--no-acl", db_url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        import gzip
        with gzip.open(dest, "wb") as f:
            while True:
                chunk = dump_proc.stdout.read(65536)
                if not chunk:
                    break
                f.write(chunk)

        dump_proc.wait()
        if dump_proc.returncode != 0:
            stderr = dump_proc.stderr.read().decode()
            log.error("pg_dump failed: %s", stderr)
            dest.unlink(missing_ok=True)
            return None

        log.info("PostgreSQL backup saved: %s (%.1f MB)", dest.name, dest.stat().st_size / 1024 / 1024)
        return dest

    except FileNotFoundError:
        log.error("pg_dump not found. Install postgresql-client to enable backups.")
        return None
    except Exception as e:
        log.error("Backup failed: %s", e)
        dest.unlink(missing_ok=True)
        return None


def cleanup_old_backups():
    """Delete old backups, keeping only the most recent MAX_BACKUPS."""
    if not BACKUP_DIR.exists():
        return
    backups = sorted(BACKUP_DIR.glob("inventory_backup_*"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in backups[MAX_BACKUPS:]:
        old.unlink()
        log.info("Deleted old backup: %s", old.name)


def run_backup():
    """Run the appropriate backup method based on DATABASE_URL."""
    log.info("Starting database backup...")

    if DATABASE_URL.startswith("sqlite"):
        result = backup_sqlite()
    else:
        result = backup_postgres()

    if result:
        cleanup_old_backups()
        log.info("Backup complete.")
    else:
        log.error("Backup failed.")
        sys.exit(1)


if __name__ == "__main__":
    run_backup()
