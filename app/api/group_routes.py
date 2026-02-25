"""
Admin API - Group management endpoints.
"""

from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional

from app.auth.session import require_admin
from app.auth.audit import log_audit
from app.db.connections import get_db
from app.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/groups", tags=["Admin - Groups"])


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class CreateGroupRequest(BaseModel):
    name: str
    description: Optional[str] = None
    icon: str = "GRP"


class UpdateGroupRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    icon: Optional[str] = None


class GroupAppAccessRequest(BaseModel):
    app_id: int
    has_access: bool


class FeaturePermissionRequest(BaseModel):
    app_id: int
    feature_name: str
    can_read: bool = False
    can_write: bool = False
    can_delete: bool = False
    can_execute: bool = False


@router.get("")
async def list_groups(admin: dict = Depends(require_admin)):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT g.*, COUNT(ug.user_id) as member_count
            FROM groups g
            LEFT JOIN user_groups ug ON g.id = ug.group_id
            GROUP BY g.id
            ORDER BY g.name
        """)
        groups = [dict(row) for row in cursor.fetchall()]

    return {"groups": groups}


@router.post("")
async def create_group(request: Request, body: CreateGroupRequest,
                       admin: dict = Depends(require_admin)):
    ip = _get_client_ip(request)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM groups WHERE name = ?", (body.name.strip(),))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Group name already exists")

        cursor.execute("""
            INSERT INTO groups (name, description, icon) VALUES (?, ?, ?)
        """, (body.name.strip(), body.description, body.icon))
        group_id = cursor.lastrowid
        conn.commit()

    log_audit(admin["id"], "create_group", resource_type="group", resource_id=group_id,
              details=f"name={body.name}", ip_address=ip)

    return {"ok": True, "group_id": group_id}


@router.get("/{group_id}")
async def get_group(group_id: int, admin: dict = Depends(require_admin)):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM groups WHERE id = ?", (group_id,))
        group = cursor.fetchone()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        group = dict(group)

        # Members
        cursor.execute("""
            SELECT u.id, u.email, u.name FROM users u
            JOIN user_groups ug ON u.id = ug.user_id
            WHERE ug.group_id = ?
        """, (group_id,))
        group["members"] = [dict(m) for m in cursor.fetchall()]

        # App access
        cursor.execute("""
            SELECT a.id, a.slug, a.name, ga.has_access FROM group_app_access ga
            JOIN apps a ON ga.app_id = a.id
            WHERE ga.group_id = ?
        """, (group_id,))
        group["app_access"] = [dict(a) for a in cursor.fetchall()]

        # Feature permissions
        cursor.execute("""
            SELECT fp.*, a.slug as app_slug, a.name as app_name
            FROM feature_permissions fp
            JOIN apps a ON fp.app_id = a.id
            WHERE fp.group_id = ?
        """, (group_id,))
        group["feature_permissions"] = [dict(fp) for fp in cursor.fetchall()]

    return group


@router.put("/{group_id}")
async def update_group(group_id: int, request: Request, body: UpdateGroupRequest,
                       admin: dict = Depends(require_admin)):
    ip = _get_client_ip(request)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM groups WHERE id = ?", (group_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Group not found")

        updates = []
        params = []
        if body.name is not None:
            updates.append("name = ?")
            params.append(body.name.strip())
        if body.description is not None:
            updates.append("description = ?")
            params.append(body.description)
        if body.icon is not None:
            updates.append("icon = ?")
            params.append(body.icon)

        if not updates:
            raise HTTPException(status_code=422, detail="No fields to update")

        params.append(group_id)
        cursor.execute(f"UPDATE groups SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()

    log_audit(admin["id"], "update_group", resource_type="group", resource_id=group_id,
              details=str(body.model_dump(exclude_none=True)), ip_address=ip)

    return {"ok": True}


@router.delete("/{group_id}")
async def delete_group(group_id: int, request: Request,
                       admin: dict = Depends(require_admin)):
    ip = _get_client_ip(request)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM groups WHERE id = ?", (group_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Group not found")
        cursor.execute("DELETE FROM groups WHERE id = ?", (group_id,))
        conn.commit()

    log_audit(admin["id"], "delete_group", resource_type="group", resource_id=group_id, ip_address=ip)

    return {"ok": True}


@router.post("/{group_id}/apps")
async def set_group_app_access(group_id: int, request: Request, body: GroupAppAccessRequest,
                                admin: dict = Depends(require_admin)):
    ip = _get_client_ip(request)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO group_app_access (group_id, app_id, has_access)
            VALUES (?, ?, ?)
            ON CONFLICT(group_id, app_id) DO UPDATE SET has_access = ?
        """, (group_id, body.app_id, int(body.has_access), int(body.has_access)))
        conn.commit()

    log_audit(admin["id"], "set_group_app_access", resource_type="group", resource_id=group_id,
              details=f"app_id={body.app_id}, has_access={body.has_access}", ip_address=ip)

    return {"ok": True}


@router.get("/{group_id}/permissions")
async def get_group_permissions(group_id: int, admin: dict = Depends(require_admin)):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM groups WHERE id = ?", (group_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Group not found")

        cursor.execute("""
            SELECT fp.*, a.slug as app_slug, a.name as app_name
            FROM feature_permissions fp
            JOIN apps a ON fp.app_id = a.id
            WHERE fp.group_id = ?
            ORDER BY a.name, fp.feature_name
        """, (group_id,))
        permissions = [dict(fp) for fp in cursor.fetchall()]

    return {"permissions": permissions}


@router.put("/{group_id}/permissions")
async def set_group_permission(group_id: int, request: Request, body: FeaturePermissionRequest,
                                admin: dict = Depends(require_admin)):
    ip = _get_client_ip(request)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO feature_permissions (group_id, app_id, feature_name, can_read, can_write, can_delete, can_execute)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(group_id, app_id, feature_name) DO UPDATE SET
                can_read = ?, can_write = ?, can_delete = ?, can_execute = ?
        """, (group_id, body.app_id, body.feature_name,
              int(body.can_read), int(body.can_write), int(body.can_delete), int(body.can_execute),
              int(body.can_read), int(body.can_write), int(body.can_delete), int(body.can_execute)))
        conn.commit()

    log_audit(admin["id"], "set_feature_permission", resource_type="group", resource_id=group_id,
              details=f"app_id={body.app_id}, feature={body.feature_name}", ip_address=ip)

    return {"ok": True}
