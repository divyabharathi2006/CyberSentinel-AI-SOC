from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.engine import URL, make_url

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import create_app, db  # noqa: E402


def _reserve_backup_path(backup_dir: Path, extension: str) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    suffix = 0
    while True:
        collision_suffix = f"-{suffix}" if suffix else ""
        destination = backup_dir / f"cybersentinel-{timestamp}{collision_suffix}.{extension}"
        try:
            descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            suffix += 1
            continue
        os.close(descriptor)
        return destination


def _backup_database(database_url: str, backup_dir: Path) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True)
    url = make_url(database_url)
    if url.get_backend_name() == "sqlite":
        database_path = Path(url.database or "")
        if not database_path.is_absolute():
            database_path = ROOT / database_path
        if not database_path.is_file():
            raise RuntimeError(f"SQLite database does not exist: {database_path}")
        destination = _reserve_backup_path(backup_dir, "sqlite")
        try:
            with sqlite3.connect(database_path) as source, sqlite3.connect(destination) as target:
                source.backup(target)
                integrity = target.execute("PRAGMA integrity_check").fetchone()
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        if not integrity or integrity[0] != "ok":
            destination.unlink(missing_ok=True)
            raise RuntimeError(f"SQLite backup failed integrity check: {integrity}")
        return destination

    if url.get_backend_name() != "postgresql":
        raise RuntimeError("Safe reset supports only SQLite and PostgreSQL databases")
    pg_dump = shutil.which("pg_dump")
    if not pg_dump:
        raise RuntimeError("pg_dump is required to back up PostgreSQL; no data was changed")
    destination = _reserve_backup_path(backup_dir, "dump")
    command = [pg_dump, "--format=custom", "--no-owner", "--file", str(destination)]
    environment = None
    if isinstance(url, URL):
        query = dict(url.query)
        password = url.password
        if password:
            environment = os.environ.copy()
            environment["PGPASSWORD"] = password
        host = url.host
        port = url.port
        username = url.username
        database = url.database
        if host:
            command.extend(["--host", host])
        if port:
            command.extend(["--port", str(port)])
        if username:
            command.extend(["--username", username])
        if database:
            command.extend(["--dbname", database])
        for name in ("sslmode", "sslcert", "sslkey", "sslrootcert"):
            if name in query:
                command.extend(["--" + name.replace("_", "-"), str(query[name])])
    result = subprocess.run(command, check=False, capture_output=True, text=True, env=environment)
    if result.returncode:
        destination.unlink(missing_ok=True)
        raise RuntimeError(f"pg_dump failed; no data was changed: {result.stderr.strip()}")
    pg_restore = shutil.which("pg_restore")
    if not pg_restore:
        destination.unlink(missing_ok=True)
        raise RuntimeError("pg_restore is required to verify the PostgreSQL backup; no data was changed")
    verification = subprocess.run(
        [pg_restore, "--list", str(destination)],
        check=False,
        capture_output=True,
        text=True,
    )
    if verification.returncode or not verification.stdout.strip():
        destination.unlink(missing_ok=True)
        raise RuntimeError(
            f"PostgreSQL backup verification failed; no data was changed: {verification.stderr.strip()}"
        )
    return destination


def _clear_database(include_users: bool, include_audit: bool) -> list[str]:
    protected = set()
    if not include_users:
        protected.add("users")
    if not include_audit:
        protected.add("audit_logs")
    deleted = []
    with db.engine.begin() as connection:
        for table in reversed(db.metadata.sorted_tables):
            if table.name in protected:
                continue
            connection.execute(table.delete())
            deleted.append(table.name)
    return deleted


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Back up the configured CyberSentinel database, then clear SOC data."
    )
    parser.add_argument(
        "--backup-dir",
        type=Path,
        default=ROOT / "backups",
        help="directory for the required restoreable database backup (default: ./backups)",
    )
    parser.add_argument(
        "--include-users",
        action="store_true",
        help="also delete users; requires reseeding an administrator before login",
    )
    parser.add_argument(
        "--include-audit",
        action="store_true",
        help="also delete the audit trail",
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="required acknowledgement that database records will be permanently deleted",
    )
    args = parser.parse_args()
    if not args.confirm:
        parser.error("refusing to reset without --confirm; no data was changed")
    if args.include_users and not args.include_audit:
        parser.error("--include-users requires --include-audit to preserve audit foreign-key integrity")

    app = create_app()
    with app.app_context():
        backup = _backup_database(app.config["SQLALCHEMY_DATABASE_URI"], args.backup_dir)
        print(f"Database backup completed: {backup}")
        deleted_tables = _clear_database(args.include_users, args.include_audit)
        print("Cleared tables: " + ", ".join(deleted_tables))
        preserved = []
        if not args.include_users:
            preserved.append("users")
        if not args.include_audit:
            preserved.append("audit_logs")
        if preserved:
            print("Preserved tables: " + ", ".join(preserved))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
