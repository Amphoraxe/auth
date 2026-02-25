"""
Central session management - token creation, validation, and user retrieval.
Sessions use opaque tokens stored in SQLite, validated via the auth API.
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Request, HTTPException, status, Depends

from app.config import SESSION_DURATION_DAYS
from app.db.connections import get_db
from app.logging_config import get_logger

logger = get_logger(__name__)

# Cookie name shared across all amphoraxe.ca subdomains
COOKIE_NAME = "amp_auth"


def create_session(user_id: int, ip_address: str = None, user_agent: str = None) -> str:
    """Create a new session token for user"""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=SESSION_DURATION_DAYS)

    with get_db() as conn:
        cursor = conn.cursor()
        # Clean up expired sessions for this user
        cursor.execute("DELETE FROM sessions WHERE user_id = ? AND expires_at < ?",
                       (user_id, datetime.utcnow()))
        # Create new session
        cursor.execute("""
            INSERT INTO sessions (user_id, token, expires_at, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, token, expires_at, ip_address, user_agent))
        conn.commit()

    logger.info(f"Session created for user_id={user_id}, valid for {SESSION_DURATION_DAYS} days")
    return token


def get_user_by_session(token: str) -> Optional[dict]:
    """Get user from session token"""
    if not token:
        return None

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.* FROM users u
            JOIN sessions s ON u.id = s.user_id
            WHERE s.token = ? AND s.expires_at > ? AND u.is_active = 1
        """, (token, datetime.utcnow()))
        row = cursor.fetchone()
        if row:
            return dict(row)

    return None


def delete_session(token: str) -> bool:
    """Delete a session by token"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        return cursor.rowcount > 0


def delete_all_user_sessions(user_id: int) -> int:
    """Delete all sessions for a user (force logout everywhere)"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.commit()
        return cursor.rowcount


def get_token_from_request(request: Request) -> Optional[str]:
    """Extract auth token from request (cookie or Authorization header)"""
    # Check cookie first
    token = request.cookies.get(COOKIE_NAME)
    if token:
        return token
    # Check Authorization header (for API clients)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def get_user_app_access(user_id: int) -> list:
    """Get list of app slugs the user can access"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Check if user is admin
        cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
        user_row = cursor.fetchone()
        if not user_row:
            return []
        if user_row["is_admin"]:
            cursor.execute("SELECT slug FROM apps WHERE is_active = 1")
            return [row["slug"] for row in cursor.fetchall()]

        # Get explicit user-level access
        cursor.execute("""
            SELECT a.slug, ua.has_access
            FROM user_app_access ua
            JOIN apps a ON ua.app_id = a.id
            WHERE ua.user_id = ? AND a.is_active = 1
        """, (user_id,))
        user_access = {row["slug"]: bool(row["has_access"]) for row in cursor.fetchall()}

        # Get group-level access for apps not in user_access
        cursor.execute("""
            SELECT DISTINCT a.slug
            FROM group_app_access ga
            JOIN apps a ON ga.app_id = a.id
            JOIN user_groups ug ON ga.group_id = ug.group_id
            WHERE ug.user_id = ? AND ga.has_access = 1 AND a.is_active = 1
        """, (user_id,))
        group_apps = {row["slug"] for row in cursor.fetchall()}

        accessible = []
        # Apps with explicit user access = 1
        for slug, has in user_access.items():
            if has:
                accessible.append(slug)
        # Apps from groups, unless explicitly denied at user level
        for slug in group_apps:
            if slug not in user_access:
                accessible.append(slug)

        return accessible


def get_user_feature_permissions(user_id: int, app_slug: str) -> dict:
    """Get feature permissions for a user in a specific app context"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Check admin
        cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
        user_row = cursor.fetchone()
        if not user_row:
            return {}
        if user_row["is_admin"]:
            return {"_admin": True}

        # Get app_id
        cursor.execute("SELECT id FROM apps WHERE slug = ?", (app_slug,))
        app_row = cursor.fetchone()
        if not app_row:
            return {}
        app_id = app_row["id"]

        # Get features from groups
        cursor.execute("""
            SELECT fp.feature_name, fp.can_read, fp.can_write, fp.can_delete, fp.can_execute
            FROM feature_permissions fp
            JOIN user_groups ug ON fp.group_id = ug.group_id
            WHERE ug.user_id = ? AND fp.app_id = ?
        """, (user_id, app_id))

        features = {}
        for row in cursor.fetchall():
            name = row["feature_name"]
            if name not in features:
                features[name] = {"read": False, "write": False, "delete": False, "execute": False}
            # Union permissions across groups
            if row["can_read"]:
                features[name]["read"] = True
            if row["can_write"]:
                features[name]["write"] = True
            if row["can_delete"]:
                features[name]["delete"] = True
            if row["can_execute"]:
                features[name]["execute"] = True

        return features


async def get_current_user(request: Request) -> dict:
    """Dependency: require authenticated user"""
    token = get_token_from_request(request)
    user = get_user_by_session(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    return user


async def get_current_user_optional(request: Request) -> Optional[dict]:
    """Dependency: get current user if authenticated"""
    token = get_token_from_request(request)
    return get_user_by_session(token)


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    """Dependency: require admin privileges"""
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
