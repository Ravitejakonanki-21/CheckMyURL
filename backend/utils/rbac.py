from functools import wraps
from typing import Iterable, Callable

from flask import jsonify
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity


def roles_required(allowed_roles: Iterable[str]) -> Callable:
    """
    Decorator enforcing that the caller has one of the allowed roles.
    Relies on a `role` claim embedded in the JWT at login time.
    """
    allowed = set(allowed_roles)

    def decorator(fn: Callable):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            role = claims.get("role")
            if role not in allowed:
                return jsonify({"error": "forbidden", "reason": "insufficient_role"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def current_user_identity() -> str:
    return get_jwt_identity()

