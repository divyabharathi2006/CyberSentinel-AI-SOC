from flask import request
from flask_socketio import disconnect
from flask_jwt_extended import decode_token
from flask_jwt_extended.exceptions import JWTExtendedException

from app import db, socketio
from app.models.user import User


@socketio.on("connect", namespace="/soc")
def authenticate_socket(auth=None):
    token = auth.get("token") if isinstance(auth, dict) else request.args.get("token")
    if not token:
        disconnect()
        return False
    try:
        claims = decode_token(token)
        user_id = int(claims["sub"])
    except (ValueError, TypeError, KeyError, JWTExtendedException):
        disconnect()
        return False
    if not db.session.get(User, user_id):
        disconnect()
        return False
