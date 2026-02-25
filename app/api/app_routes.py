"""
Admin API - App registry management endpoints.
"""

from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional

from app.auth.session import require_admin
from app.auth.audit import log_audit
from app.db.connections import get_db
from app.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/apps", tags=["Admin - Apps"])


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class CreateAppRequest(BaseModel):
    slug: str
    name: str
    description: Optional[str] = None
    main_url: Optional[str] = None
    dev_url: Optional[str] = None
    main_port: Optional[int] = None
    dev_port: Optional[int] = None
    icon: Optional[str] = None
    requires_auth: bool = True
    admin_only: bool = False
    display_order: int = 0


class UpdateAppRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    main_url: Optional[str] = None
    dev_url: Optional[str] = None
    main_port: Optional[int] = None
    dev_port: Optional[int] = None
    icon: Optional[str] = None
    is_active: Optional[bool] = None
    requires_auth: Optional[bool] = None
    admin_only: Optional[bool] = None
    display_order: Optional[int] = None


@router.get("")
async def list_apps(admin: dict = Depends(require_admin)):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM apps ORDER BY display_order, name")
        apps = [dict(row) for row in cursor.fetchall()]

    return {"apps": apps}


@router.post("")
async def create_app(request: Request, body: CreateAppRequest,
                     admin: dict = Depends(require_admin)):
    ip = _get_client_ip(request)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM apps WHERE slug = ?", (body.slug,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="App slug already exists")

        cursor.execute("""
            INSERT INTO apps (slug, name, description, main_url, dev_url, main_port, dev_port,
                              icon, requires_auth, admin_only, display_order)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (body.slug, body.name, body.description, body.main_url, body.dev_url,
              body.main_port, body.dev_port, body.icon, int(body.requires_auth),
              int(body.admin_only), body.display_order))
        app_id = cursor.lastrowid
        conn.commit()

    log_audit(admin["id"], "create_app", resource_type="app", resource_id=app_id,
              details=f"slug={body.slug}", ip_address=ip)

    return {"ok": True, "app_id": app_id}


@router.put("/{app_id}")
async def update_app(app_id: int, request: Request, body: UpdateAppRequest,
                     admin: dict = Depends(require_admin)):
    ip = _get_client_ip(request)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM apps WHERE id = ?", (app_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="App not found")

        updates = []
        params = []
        for field, value in body.model_dump(exclude_none=True).items():
            if isinstance(value, bool):
                value = int(value)
            updates.append(f"{field} = ?")
            params.append(value)

        if not updates:
            raise HTTPException(status_code=422, detail="No fields to update")

        params.append(app_id)
        cursor.execute(f"UPDATE apps SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()

    log_audit(admin["id"], "update_app", resource_type="app", resource_id=app_id,
              details=str(body.model_dump(exclude_none=True)), ip_address=ip)

    return {"ok": True}
