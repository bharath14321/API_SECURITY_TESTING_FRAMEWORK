"""
Deliberately vulnerable target API for the API Security Testing Framework.

Toggle VULNERABLE_MODE (env var, default "true") to switch between:
  - an intentionally insecure configuration seeding real OWASP API
    Security Top 10 (2023) findings, and
  - a hardened configuration on the *same* routes, with the correct
    authorization/validation logic applied.

This is what lets you demo: vulnerable -> scanner flags it -> flip the
flag (or read the diff) -> scanner confirms clean.

ETHICS: only ever run this against yourself, locally. Never point any
part of this framework at a system you do not own or have explicit
written authorization to test.
"""
import os
import time
import base64
import json
from collections import defaultdict, deque
from functools import wraps

import jwt
from flask import Flask, request, jsonify, g

from models import db, init_db

VULNERABLE_MODE = os.getenv("VULNERABLE_MODE", "true").lower() == "true"

# Intentionally weak secret, used ONLY in vulnerable mode, so the JWT
# weak-secret brute-force attack (scanner/modules/jwt_attacks.py) is
# demonstrable against a realistic mistake (hardcoded/guessable secret).
WEAK_SECRET = "supersecret123"
STRONG_SECRET = os.getenv("JWT_SECRET", os.urandom(32).hex())
JWT_SECRET = WEAK_SECRET if VULNERABLE_MODE else STRONG_SECRET
JWT_ALG = "HS256"

app = Flask(__name__)
app.config["DEBUG"] = VULNERABLE_MODE  # API8:2023 - verbose stack traces when vulnerable

init_db()

# ---------------------------------------------------------------------------
# API4:2023 - simple in-memory rate limiter (secure mode only).
# Keyed on request.remote_addr on purpose: trusting client-supplied
# X-Forwarded-For/X-Real-IP headers without a trusted reverse proxy in
# front of you is itself a vulnerability, so the "fixed" version does
# NOT trust them. This is what the header-spoofing bypass test in
# rate_limit_tester.py is checking.
# ---------------------------------------------------------------------------
LOGIN_ATTEMPTS = defaultdict(deque)
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_ATTEMPTS = 10


def is_rate_limited(key):
    now = time.time()
    attempts = LOGIN_ATTEMPTS[key]
    while attempts and now - attempts[0] > RATE_LIMIT_WINDOW_SECONDS:
        attempts.popleft()
    attempts.append(now)
    return len(attempts) > RATE_LIMIT_MAX_ATTEMPTS


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def issue_token(user):
    payload = {
        "sub": user.id,
        "username": user.username,
        "is_admin": user.is_admin,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def _b64url_decode(segment):
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_token(token):
    """
    In VULNERABLE_MODE this mimics a common real-world bug: a custom
    decode path that trusts the 'alg' header from the token itself and
    accepts 'none' as a valid, unsigned algorithm (API2:2023).

    In secure mode the algorithm is pinned server-side and a signature
    is always required, regardless of what the token's header claims.
    """
    if VULNERABLE_MODE:
        header = json.loads(_b64url_decode(token.split(".")[0]))
        alg = header.get("alg", "HS256")
        signature_segment = token.split(".")[2]
        # Accept both the classic alg=none forgery AND any token whose
        # signature segment was simply stripped, regardless of what the
        # header claims. This mirrors a real-world bug class: custom
        # decode code that special-cases "no signature" without
        # actually requiring one.
        if alg.lower() == "none" or signature_segment == "":
            payload_segment = token.split(".")[1]
            return json.loads(_b64url_decode(payload_segment))
        return jwt.decode(token, JWT_SECRET, algorithms=[alg])
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])


def auth_required(admin_only=False):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            authz = request.headers.get("Authorization", "")
            if not authz.startswith("Bearer "):
                return jsonify({"error": "missing bearer token"}), 401
            token = authz.split(" ", 1)[1]
            try:
                payload = decode_token(token)
            except Exception as e:
                msg = f"invalid token: {e}" if VULNERABLE_MODE else "invalid token"
                return jsonify({"error": msg}), 401
            g.user_id = payload.get("sub")
            g.is_admin = payload.get("is_admin", False)
            # API5:2023 - in vulnerable mode there is deliberately no
            # server-side role check, only the client-supplied JWT claim.
            if admin_only and not VULNERABLE_MODE and not g.is_admin:
                return jsonify({"error": "forbidden"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.route("/api/login", methods=["POST"])
def login():
    # API4:2023 - deliberately unthrottled in vulnerable mode.
    if not VULNERABLE_MODE and is_rate_limited(request.remote_addr):
        return jsonify({"error": "too many requests"}), 429

    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    user = db.find_user_by_username(username)
    if not user or not user.check_password(password):
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"token": issue_token(user), "user_id": user.id})


# ---------------------------------------------------------------------------
# API1:2023 BOLA - object access without ownership check
# ---------------------------------------------------------------------------
@app.route("/api/accounts/<int:account_id>")
@auth_required()
def get_account(account_id):
    account = db.get_user(account_id)
    if account is None:
        return jsonify({"error": "not found"}), 404
    if not VULNERABLE_MODE and account.id != g.user_id:
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"id": account.id, "username": account.username, "balance": account.balance})


@app.route("/api/orders/<int:order_id>")
@auth_required()
def get_order(order_id):
    order = db.get_order(order_id)
    if order is None:
        return jsonify({"error": "not found"}), 404
    if not VULNERABLE_MODE and order.user_id != g.user_id:
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"id": order.id, "user_id": order.user_id, "item": order.item, "amount": order.amount})


# ---------------------------------------------------------------------------
# API3:2023 Broken object property level authorization - mass assignment
# ---------------------------------------------------------------------------
ALLOWED_PATCH_FIELDS = {"username", "email"}


@app.route("/api/users/<int:user_id>", methods=["PATCH"])
@auth_required()
def patch_user(user_id):
    if not VULNERABLE_MODE and user_id != g.user_id:
        return jsonify({"error": "forbidden"}), 403
    user = db.get_user(user_id)
    if user is None:
        return jsonify({"error": "not found"}), 404

    data = request.get_json(force=True, silent=True) or {}
    # Vulnerable: bind every client-supplied field straight onto the model.
    # Fixed: only ever apply an explicit allow-list of writable fields.
    field_names = data.keys() if VULNERABLE_MODE else (data.keys() & ALLOWED_PATCH_FIELDS)
    for field_name in field_names:
        if hasattr(user, field_name):
            setattr(user, field_name, data[field_name])
    db.save_user(user)
    return jsonify({"id": user.id, "username": user.username, "is_admin": user.is_admin, "email": user.email})


# ---------------------------------------------------------------------------
# API5:2023 Broken function level authorization
# ---------------------------------------------------------------------------
@app.route("/admin/users")
@auth_required(admin_only=True)
def admin_list_users():
    return jsonify([{"id": u.id, "username": u.username, "is_admin": u.is_admin} for u in db.list_users()])


# ---------------------------------------------------------------------------
# OpenAPI spec - drives the scanner's OpenAPI fuzzing engine (Phase 4)
# ---------------------------------------------------------------------------
@app.route("/openapi.json")
def openapi_spec():
    spec_path = os.path.join(os.path.dirname(__file__), "openapi.json")
    with open(spec_path) as f:
        return jsonify(json.load(f))


@app.route("/health")
def health():
    return jsonify({"status": "ok", "vulnerable_mode": VULNERABLE_MODE})


# ---------------------------------------------------------------------------
# API8:2023 Security misconfiguration - security headers
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(response):
    if not VULNERABLE_MODE:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
    # In vulnerable mode these headers are deliberately omitted.
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=VULNERABLE_MODE, threaded=True)
