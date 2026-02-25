"""
Email notifications for Amphoraxe Auth Service.
"""

import html
import secrets
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Tuple
import logging

from app.config import (
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM,
    ADMIN_EMAIL, BASE_URL, ENVIRONMENT, is_email_configured
)
from app.db.connections import get_db

logger = logging.getLogger(__name__)

APPROVAL_TOKEN_EXPIRY_HOURS = 48


def create_approval_token(user_id: int, action: str) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=APPROVAL_TOKEN_EXPIRY_HOURS)
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO approval_tokens (token, user_id, action, expires_at)
            VALUES (?, ?, ?, ?)
        """, (token, user_id, action, expires_at))
        conn.commit()
    return token


def validate_approval_token(token: str) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.id, t.user_id, t.action, t.expires_at, t.used_at, u.name, u.email, u.is_approved
            FROM approval_tokens t
            JOIN users u ON t.user_id = u.id
            WHERE t.token = ?
        """, (token,))
        row = cursor.fetchone()
        if not row:
            return None, None, "Invalid or expired token"

        user_id = row["user_id"]
        action = row["action"]
        expires_at = row["expires_at"]
        used_at = row["used_at"]
        user_name = row["name"]
        is_approved = row["is_approved"]

        if used_at:
            return None, None, "This link has already been used"

        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)
        if datetime.utcnow() > expires_at:
            return None, None, "This link has expired"

        if action == "approve" and is_approved:
            return None, None, f"{user_name}'s account has already been approved"

        cursor.execute("""
            UPDATE approval_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL
        """, (datetime.utcnow(), user_id))
        conn.commit()

        return user_id, action, None


def send_email(to: str, subject: str, body_html: str, body_text: Optional[str] = None) -> bool:
    if not is_email_configured():
        logger.warning(f"[EMAIL] Not configured. Would send to {to}: {subject}")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = to
        if body_text:
            msg.attach(MIMEText(body_text, "plain"))
        msg.attach(MIMEText(body_html, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, to, msg.as_string())
        logger.info(f"[EMAIL] Sent to {to}: {subject}")
        return True
    except Exception as e:
        logger.error(f"[EMAIL] Failed to send to {to}: {e}")
        return False


def notify_admin_new_signup(user_name: str, user_email: str, user_id: int = None):
    safe_name = html.escape(user_name)
    safe_email = html.escape(user_email)

    env_label = "DEV" if ENVIRONMENT == "development" else "PROD"
    subject = f"[{env_label}] New Account Request: {safe_name}"

    approve_url = f"{BASE_URL}/admin/users"
    reject_url = f"{BASE_URL}/admin/users"
    has_tokens = False

    if user_id:
        try:
            approve_token = create_approval_token(user_id, "approve")
            reject_token = create_approval_token(user_id, "reject")
            approve_url = f"{BASE_URL}/auth/email-action/{approve_token}"
            reject_url = f"{BASE_URL}/auth/email-action/{reject_token}"
            has_tokens = True
        except Exception as e:
            logger.warning(f"Failed to create approval tokens: {e}")

    if has_tokens:
        buttons_html = f"""
        <div style="margin: 25px 0;">
            <a href="{approve_url}" style="display: inline-block; padding: 12px 24px; background: #16a34a; color: white; text-decoration: none; border-radius: 5px; margin-right: 10px; font-weight: 500;">Approve</a>
            <a href="{reject_url}" style="display: inline-block; padding: 12px 24px; background: #dc2626; color: white; text-decoration: none; border-radius: 5px; font-weight: 500;">Decline</a>
        </div>
        <p style="color: #888; font-size: 12px;">These links expire in {APPROVAL_TOKEN_EXPIRY_HOURS} hours. You can also <a href="{BASE_URL}/admin/users" style="color: #2563eb;">manage users in the admin panel</a>.</p>
        """
        buttons_text = f"Approve: {approve_url}\nDecline: {reject_url}\nLinks expire in {APPROVAL_TOKEN_EXPIRY_HOURS} hours."
    else:
        buttons_html = f'<p><a href="{BASE_URL}/admin/users" style="display: inline-block; padding: 10px 20px; background: #2563eb; color: white; text-decoration: none; border-radius: 5px;">Review Account Requests</a></p>'
        buttons_text = f"Review at: {BASE_URL}/admin/users"

    env_color = "#f59e0b" if ENVIRONMENT == "development" else "#16a34a"
    env_text = "Development" if ENVIRONMENT == "development" else "Production"

    body_html = f"""
    <html>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px;">
        <h2 style="color: #1d4ed8;">New Account Request <span style="font-size: 0.6em; padding: 4px 8px; background: {env_color}; color: white; border-radius: 4px; vertical-align: middle;">{env_text}</span></h2>
        <p>A new user has requested access to the Amphoraxe ecosystem:</p>
        <table style="margin: 20px 0; border-collapse: collapse;">
            <tr><td style="padding: 8px 15px; color: #666;">Name:</td><td style="padding: 8px 15px;"><strong>{safe_name}</strong></td></tr>
            <tr><td style="padding: 8px 15px; color: #666;">Email:</td><td style="padding: 8px 15px;"><strong>{safe_email}</strong></td></tr>
        </table>
        {buttons_html}
        <p style="color: #666; font-size: 14px; margin-top: 30px;">Amphoraxe Auth</p>
    </body>
    </html>
    """

    body_text = f"New Account Request [{env_text}]\n\nName: {user_name}\nEmail: {user_email}\n\n{buttons_text}"
    send_email(ADMIN_EMAIL, subject, body_html, body_text)


def notify_user_approved(user_email: str, user_name: str):
    safe_name = html.escape(user_name)
    from app.config import DEMO_URL
    body_html = f"""
    <html>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px;">
        <h2 style="color: #16a34a;">Account Approved!</h2>
        <p>Hi {safe_name},</p>
        <p>Your account has been approved. You can now log in and access your applications.</p>
        <p><a href="{DEMO_URL}" style="display: inline-block; padding: 10px 20px; background: #2563eb; color: white; text-decoration: none; border-radius: 5px;">Go to App Launcher</a></p>
        <p style="color: #666; font-size: 14px; margin-top: 30px;">Amphoraxe Auth</p>
    </body>
    </html>
    """
    body_text = f"Account Approved!\n\nHi {user_name},\n\nYour account has been approved. Log in at: {DEMO_URL}"
    send_email(user_email, "Your Amphoraxe Account is Approved", body_html, body_text)


def notify_user_declined(user_email: str, user_name: str):
    safe_name = html.escape(user_name)
    body_html = f"""
    <html>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px;">
        <h2 style="color: #dc2626;">Account Request Update</h2>
        <p>Hi {safe_name},</p>
        <p>Thank you for your interest. Unfortunately, we are unable to approve your account request at this time.</p>
        <p>If you believe this is an error, please contact the administrator.</p>
        <p style="color: #666; font-size: 14px; margin-top: 30px;">Amphoraxe Auth</p>
    </body>
    </html>
    """
    body_text = f"Account Request Update\n\nHi {user_name},\n\nUnfortunately, we are unable to approve your account request at this time."
    send_email(user_email, "Amphoraxe Account Request", body_html, body_text)
