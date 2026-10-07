from __future__ import annotations

import os

from app import create_app, socketio

app = create_app()


if __name__ == "__main__":
    socketio.run(
        app,
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true",
        allow_unsafe_werkzeug=True,
    )
