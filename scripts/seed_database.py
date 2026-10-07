from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import create_app, db
from app.models.user import ROLES, User


def main() -> int:
    username = os.environ.get("CYBERSENTINEL_ADMIN_USERNAME", "").strip()
    email = os.environ.get("CYBERSENTINEL_ADMIN_EMAIL", "").strip().lower()
    password = os.environ.get("CYBERSENTINEL_ADMIN_PASSWORD", "")
    if not username or not email or not password:
        raise SystemExit("Set CYBERSENTINEL_ADMIN_USERNAME, CYBERSENTINEL_ADMIN_EMAIL, and CYBERSENTINEL_ADMIN_PASSWORD before running.")
    app = create_app()
    with app.app_context():
        db.create_all()
        if User.query.filter((User.username == username) | (User.email == email)).first():
            raise SystemExit("An account with that username or email already exists.")
        user = User(username=username, email=email, role="Admin")
        if user.role not in ROLES:
            raise SystemExit("Invalid role configuration.")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        print(f"Created administrator account {username!r}. The password was not printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
