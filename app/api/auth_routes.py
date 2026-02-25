"""
Auth API endpoints - login, logout, signup, validate, me, password change.
Consumed by all apps in the Amphoraxe ecosystem.
"""

from datetime import datetime
from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel, EmailStr

from app.auth.password import hash_password, verify_password
from app.auth.session import (
    create_session, delete_session, get_token_from_request,
    get_user_by_session, get_user_app_access, get_user_feature_permissions,
    COOKIE_NAME, get_current_user,
)
from app.auth.audit import log_audit
from app.db.connections import get_db
from app.rate_limit import (
    check_login_rate_limit, record_login_attempt, clear_login_attempts,
    check_signup_rate_limit, record_signup_attempt,
)
from app.email import notify_admin_new_signup
from app.config import SESSION_DURATION_DAYS, IS_PRODUCTION
from app.logging_config import log_access, log_security, get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["Auth API"])


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _set_auth_cookie(response, token: str):
    """Set the cross-domain auth cookie"""
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        domain=".amphoraxe.ca",
        path="/",
        httponly=True,
        secure=IS_PRODUCTION,
        samesite="lax",
        max_age=SESSION_DURATION_DAYS * 86400,
    )


def _clear_auth_cookie(response):
    """Clear the auth cookie"""
    response.delete_cookie(
        key=COOKIE_NAME,
        domain=".amphoraxe.ca",
        path="/",
    )


# --- Request/Response Models ---

class LoginRequest(BaseModel):
    email: str
    password: str


class SignupRequest(BaseModel):
    email: str
    password: str
    name: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


# --- Endpoints ---

@router.post("/login")
async def login(request: Request, body: LoginRequest):
    from fastapi.responses import JSONResponse

    ip = _get_client_ip(request)

    # Rate limit
    allowed, wait_seconds = check_login_rate_limit(ip)
    if not allowed:
        log_security("LOGIN_RATE_LIMITED", f"email={body.email}", ip_address=ip)
        raise HTTPException(status_code=429, detail=f"Too many login attempts. Try again in {wait_seconds} seconds.")

    record_login_attempt(ip)

    # Look up user
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (body.email.lower().strip(),))
        user = cursor.fetchone()

    if not user:
        log_security("LOGIN_FAILED", f"email={body.email} (not found)", ip_address=ip)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user = dict(user)

    if not user["is_active"]:
        log_security("LOGIN_FAILED", f"email={body.email} (inactive)", ip_address=ip)
        raise HTTPException(status_code=401, detail="Account is deactivated")

    if not user["is_approved"]:
        log_security("LOGIN_FAILED", f"email={body.email} (not approved)", ip_address=ip)
        raise HTTPException(status_code=401, detail="Account is pending approval")

    if not verify_password(body.password, user["password_hash"]):
        log_security("LOGIN_FAILED", f"email={body.email} (bad password)", ip_address=ip)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Create session
    user_agent = request.headers.get("User-Agent", "")
    token = create_session(user["id"], ip_address=ip, user_agent=user_agent)

    # Update last_login
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", (datetime.utcnow(), user["id"]))
        conn.commit()

    clear_login_attempts(ip)

    log_access("LOGIN_SUCCESS", f"user_id={user['id']} email={user['email']}", user_id=user["id"], ip_address=ip)
    log_audit(user["id"], "login", ip_address=ip)

    # Build response
    app_access = get_user_app_access(user["id"])

    response = JSONResponse({
        "ok": True,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "is_admin": bool(user["is_admin"]),
        },
        "apps": app_access,
    })
    _set_auth_cookie(response, token)
    return response


@router.post("/logout")
async def logout(request: Request):
    from fastapi.responses import JSONResponse

    token = get_token_from_request(request)
    if token:
        delete_session(token)

    response = JSONResponse({"ok": True})
    _clear_auth_cookie(response)
    return response


@router.post("/signup")
async def signup(request: Request, body: SignupRequest):
    ip = _get_client_ip(request)

    allowed, wait_seconds = check_signup_rate_limit(ip)
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Too many signup attempts. Try again in {wait_seconds} seconds.")

    record_signup_attempt(ip)

    if len(body.password) < 12:
        raise HTTPException(status_code=422, detail="Password must be at least 12 characters")

    email = body.email.lower().strip()
    name = body.name.strip()

    if not email or not name:
        raise HTTPException(status_code=422, detail="Email and name are required")

    # Check duplicate
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="An account with this email already exists")

    password_hash = hash_password(body.password)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (email, password_hash, name, is_admin, is_active, is_approved)
            VALUES (?, ?, ?, 0, 1, 0)
        """, (email, password_hash, name))
        user_id = cursor.lastrowid
        conn.commit()

    log_access("SIGNUP", f"user_id={user_id} email={email}", user_id=user_id, ip_address=ip)
    log_audit(user_id, "signup", details=f"name={name}, email={email}", ip_address=ip)

    # Notify admin
    notify_admin_new_signup(name, email, user_id)

    return {"ok": True, "message": "Account created. Pending admin approval."}


@router.get("/validate")
async def validate(request: Request):
    """Validate a token and return user info + app permissions.
    Used by other apps to verify the amp_auth cookie."""
    token = get_token_from_request(request)
    user = get_user_by_session(token)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    # Get app_slug from query param (optional, for app-scoped permissions)
    app_slug = request.query_params.get("app")

    result = {
        "ok": True,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "is_admin": bool(user["is_admin"]),
            "is_approved": bool(user["is_approved"]),
        },
        "apps": get_user_app_access(user["id"]),
    }

    if app_slug:
        result["features"] = get_user_feature_permissions(user["id"], app_slug)

    return result


@router.get("/me")
async def me(request: Request):
    """Current user profile with all app access."""
    token = get_token_from_request(request)
    user = get_user_by_session(token)

    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    app_access = get_user_app_access(user["id"])

    # Get full app details for accessible apps
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM apps WHERE is_active = 1 ORDER BY display_order")
        all_apps = [dict(row) for row in cursor.fetchall()]

    apps_detail = []
    for app in all_apps:
        # Skip admin-only apps for non-admins
        if app["admin_only"] and not user["is_admin"]:
            continue
        apps_detail.append({
            "slug": app["slug"],
            "name": app["name"],
            "description": app["description"],
            "main_url": app["main_url"],
            "icon": app["icon"],
            "has_access": app["slug"] in app_access,
        })

    # Get user's groups
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT g.id, g.name, g.icon FROM groups g
            JOIN user_groups ug ON g.id = ug.group_id
            WHERE ug.user_id = ?
        """, (user["id"],))
        groups = [dict(row) for row in cursor.fetchall()]

    return {
        "ok": True,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "is_admin": bool(user["is_admin"]),
        },
        "apps": apps_detail,
        "groups": groups,
    }


@router.post("/password")
async def change_password(request: Request, body: PasswordChangeRequest,
                          user: dict = Depends(get_current_user)):
    ip = _get_client_ip(request)

    if len(body.new_password) < 12:
        raise HTTPException(status_code=422, detail="Password must be at least 12 characters")

    # Verify current password
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],))
        row = cursor.fetchone()

    if not row or not verify_password(body.current_password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    new_hash = hash_password(body.new_password)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user["id"]))
        conn.commit()

    log_access("PASSWORD_CHANGED", f"user_id={user['id']}", user_id=user["id"], ip_address=ip)
    log_audit(user["id"], "password_change", ip_address=ip)

    return {"ok": True, "message": "Password updated successfully"}
