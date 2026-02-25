"""
Admin API - User management endpoints.
"""

from datetime import datetime
from fastapi import APIRouter, Request, HTTPException, Depends, Query
from pydantic import BaseModel
from typing import Optional

from app.auth.session import require_admin, delete_all_user_sessions
from app.auth.password import hash_password
from app.auth.audit import log_audit
from app.db.connections import get_db
from app.email import notify_user_approved, notify_user_declined
from app.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/users", tags=["Admin - Users"])


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class CreateUserRequest(BaseModel):
    email: str
    password: str
    name: str
    is_admin: bool = False
    is_approved: bool = True


class UpdateUserRequest(BaseModel):
    name: Optional[str] = None
    is_admin: Optional[bool] = None
    is_active: Optional[bool] = None
    is_approved: Optional[bool] = None


class UserGroupsRequest(BaseModel):
    group_ids: list[int]


class UserAppAccessRequest(BaseModel):
    app_id: int
    has_access: bool


@router.get("")
async def list_users(
    request: Request,
    status: Optional[str] = Query(None, pattern="^(pending|active|inactive)$"),
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    admin: dict = Depends(require_admin),
):
    with get_db() as conn:
        cursor = conn.cursor()

        where_clauses = []
        params = []

        if status == "pending":
            where_clauses.append("u.is_approved = 0 AND u.is_active = 1")
        elif status == "active":
            where_clauses.append("u.is_approved = 1 AND u.is_active = 1")
        elif status == "inactive":
            where_clauses.append("u.is_active = 0")

        if search:
            where_clauses.append("(u.email LIKE ? OR u.name LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])

        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

        # Count
        cursor.execute(f"SELECT COUNT(*) as cnt FROM users u WHERE {where_sql}", params)
        total = cursor.fetchone()["cnt"]

        # Fetch
        offset = (page - 1) * per_page
        cursor.execute(f"""
            SELECT u.id, u.email, u.name, u.is_admin, u.is_active, u.is_approved, u.created_at, u.last_login
            FROM users u
            WHERE {where_sql}
            ORDER BY u.created_at DESC
            LIMIT ? OFFSET ?
        """, params + [per_page, offset])

        users = []
        for row in cursor.fetchall():
            user = dict(row)
            # Get groups for each user
            cursor.execute("""
                SELECT g.id, g.name FROM groups g
                JOIN user_groups ug ON g.id = ug.group_id
                WHERE ug.user_id = ?
            """, (user["id"],))
            user["groups"] = [dict(g) for g in cursor.fetchall()]
            users.append(user)

    return {
        "users": users,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
    }


@router.post("")
async def create_user(request: Request, body: CreateUserRequest,
                      admin: dict = Depends(require_admin)):
    ip = _get_client_ip(request)

    email = body.email.lower().strip()
    if len(body.password) < 12:
        raise HTTPException(status_code=422, detail="Password must be at least 12 characters")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email already exists")

    password_hash = hash_password(body.password)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (email, password_hash, name, is_admin, is_active, is_approved)
            VALUES (?, ?, ?, ?, 1, ?)
        """, (email, password_hash, body.name.strip(), int(body.is_admin), int(body.is_approved)))
        user_id = cursor.lastrowid
        conn.commit()

    log_audit(admin["id"], "create_user", resource_type="user", resource_id=user_id,
              details=f"email={email}", ip_address=ip)

    return {"ok": True, "user_id": user_id}


@router.get("/{user_id}")
async def get_user(user_id: int, admin: dict = Depends(require_admin)):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, email, name, is_admin, is_active, is_approved, created_at, last_login
            FROM users WHERE id = ?
        """, (user_id,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user = dict(user)

        # Groups
        cursor.execute("""
            SELECT g.id, g.name, g.icon FROM groups g
            JOIN user_groups ug ON g.id = ug.group_id
            WHERE ug.user_id = ?
        """, (user_id,))
        user["groups"] = [dict(g) for g in cursor.fetchall()]

        # App access
        cursor.execute("""
            SELECT a.slug, a.name, ua.has_access FROM user_app_access ua
            JOIN apps a ON ua.app_id = a.id
            WHERE ua.user_id = ?
        """, (user_id,))
        user["app_access"] = [dict(a) for a in cursor.fetchall()]

    return user


@router.post("/{user_id}")
async def update_user(user_id: int, request: Request, body: UpdateUserRequest,
                      admin: dict = Depends(require_admin)):
    ip = _get_client_ip(request)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user = dict(user)

        updates = []
        params = []
        if body.name is not None:
            updates.append("name = ?")
            params.append(body.name.strip())
        if body.is_admin is not None:
            updates.append("is_admin = ?")
            params.append(int(body.is_admin))
        if body.is_active is not None:
            updates.append("is_active = ?")
            params.append(int(body.is_active))
            if not body.is_active:
                delete_all_user_sessions(user_id)
        if body.is_approved is not None:
            updates.append("is_approved = ?")
            params.append(int(body.is_approved))
            # Send notification on approval/decline
            if body.is_approved and not user["is_approved"]:
                notify_user_approved(user["email"], user["name"])
            elif not body.is_approved and user["is_approved"]:
                notify_user_declined(user["email"], user["name"])

        if not updates:
            raise HTTPException(status_code=422, detail="No fields to update")

        params.append(user_id)
        cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()

    log_audit(admin["id"], "update_user", resource_type="user", resource_id=user_id,
              details=str(body.model_dump(exclude_none=True)), ip_address=ip)

    return {"ok": True}


@router.delete("/{user_id}")
async def delete_user(user_id: int, request: Request,
                      admin: dict = Depends(require_admin)):
    ip = _get_client_ip(request)

    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="User not found")
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()

    log_audit(admin["id"], "delete_user", resource_type="user", resource_id=user_id, ip_address=ip)

    return {"ok": True}


@router.post("/{user_id}/groups")
async def set_user_groups(user_id: int, request: Request, body: UserGroupsRequest,
                          admin: dict = Depends(require_admin)):
    ip = _get_client_ip(request)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="User not found")

        # Replace all memberships
        cursor.execute("DELETE FROM user_groups WHERE user_id = ?", (user_id,))
        for group_id in body.group_ids:
            cursor.execute("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)",
                           (user_id, group_id))
        conn.commit()

    log_audit(admin["id"], "set_user_groups", resource_type="user", resource_id=user_id,
              details=f"groups={body.group_ids}", ip_address=ip)

    return {"ok": True}


@router.post("/{user_id}/apps")
async def set_user_app_access(user_id: int, request: Request, body: UserAppAccessRequest,
                               admin: dict = Depends(require_admin)):
    ip = _get_client_ip(request)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="User not found")

        cursor.execute("""
            INSERT INTO user_app_access (user_id, app_id, has_access, granted_by)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id, app_id) DO UPDATE SET has_access = ?, granted_by = ?
        """, (user_id, body.app_id, int(body.has_access), admin["id"],
              int(body.has_access), admin["id"]))
        conn.commit()

    log_audit(admin["id"], "set_user_app_access", resource_type="user", resource_id=user_id,
              details=f"app_id={body.app_id}, has_access={body.has_access}", ip_address=ip)

    return {"ok": True}


@router.delete("/{user_id}/apps/{app_id}")
async def remove_user_app_override(user_id: int, app_id: int, request: Request,
                                    admin: dict = Depends(require_admin)):
    """Remove a user-level app access override (falls back to group rules)"""
    ip = _get_client_ip(request)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM user_app_access WHERE user_id = ? AND app_id = ?",
                       (user_id, app_id))
        conn.commit()

    log_audit(admin["id"], "remove_user_app_override", resource_type="user", resource_id=user_id,
              details=f"app_id={app_id}", ip_address=ip)

    return {"ok": True}
