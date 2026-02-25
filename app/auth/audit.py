"""
Audit logging - track user actions for compliance and security.
"""

from app.db.connections import get_db


def log_audit(user_id: int, action: str, app_slug: str = None,
              resource_type: str = None, resource_id: int = None,
              details: str = None, ip_address: str = None):
    """Log an audit event to the central audit table"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (user_id, app_slug, action, resource_type, resource_id, details, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, app_slug, action, resource_type, resource_id, details, ip_address))
        conn.commit()
