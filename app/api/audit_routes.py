"""
Admin API - Audit log query endpoints.
"""

from fastapi import APIRouter, Depends, Query
from typing import Optional

from app.auth.session import require_admin
from app.db.connections import get_db

router = APIRouter(prefix="/api/v1/audit", tags=["Admin - Audit"])


@router.get("")
async def query_audit_log(
    user_id: Optional[int] = None,
    app_slug: Optional[str] = None,
    action: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    admin: dict = Depends(require_admin),
):
    with get_db() as conn:
        cursor = conn.cursor()

        where_clauses = []
        params = []

        if user_id:
            where_clauses.append("a.user_id = ?")
            params.append(user_id)
        if app_slug:
            where_clauses.append("a.app_slug = ?")
            params.append(app_slug)
        if action:
            where_clauses.append("a.action LIKE ?")
            params.append(f"%{action}%")
        if date_from:
            where_clauses.append("a.created_at >= ?")
            params.append(date_from)
        if date_to:
            where_clauses.append("a.created_at <= ?")
            params.append(date_to)

        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

        # Count
        cursor.execute(f"SELECT COUNT(*) as cnt FROM audit_log a WHERE {where_sql}", params)
        total = cursor.fetchone()["cnt"]

        # Fetch with user info
        offset = (page - 1) * per_page
        cursor.execute(f"""
            SELECT a.*, u.email as user_email, u.name as user_name
            FROM audit_log a
            LEFT JOIN users u ON a.user_id = u.id
            WHERE {where_sql}
            ORDER BY a.created_at DESC
            LIMIT ? OFFSET ?
        """, params + [per_page, offset])

        entries = [dict(row) for row in cursor.fetchall()]

    return {
        "entries": entries,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
    }


@router.get("/stats")
async def audit_stats(admin: dict = Depends(require_admin)):
    with get_db() as conn:
        cursor = conn.cursor()

        # Active sessions
        cursor.execute("SELECT COUNT(*) as cnt FROM sessions WHERE expires_at > datetime('now')")
        active_sessions = cursor.fetchone()["cnt"]

        # Total users
        cursor.execute("SELECT COUNT(*) as cnt FROM users")
        total_users = cursor.fetchone()["cnt"]

        # Pending approvals
        cursor.execute("SELECT COUNT(*) as cnt FROM users WHERE is_approved = 0 AND is_active = 1")
        pending_approvals = cursor.fetchone()["cnt"]

        # Logins last 24h
        cursor.execute("""
            SELECT COUNT(*) as cnt FROM audit_log
            WHERE action = 'login' AND created_at > datetime('now', '-1 day')
        """)
        logins_24h = cursor.fetchone()["cnt"]

        # Active apps
        cursor.execute("SELECT COUNT(*) as cnt FROM apps WHERE is_active = 1")
        active_apps = cursor.fetchone()["cnt"]

        # Recent activity (last 10 entries)
        cursor.execute("""
            SELECT a.*, u.email as user_email
            FROM audit_log a
            LEFT JOIN users u ON a.user_id = u.id
            ORDER BY a.created_at DESC
            LIMIT 10
        """)
        recent_activity = [dict(row) for row in cursor.fetchall()]

    return {
        "active_sessions": active_sessions,
        "total_users": total_users,
        "pending_approvals": pending_approvals,
        "logins_24h": logins_24h,
        "active_apps": active_apps,
        "recent_activity": recent_activity,
    }
