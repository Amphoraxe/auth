"""
Amphoraxe Auth Service - Central authentication for the Amphoraxe ecosystem.
"""

import secrets
from pathlib import Path
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.config import (
    SECRET_KEY, SESSION_DURATION_DAYS, IS_PRODUCTION, CORS_ORIGINS,
    TEMPLATES_DIR, STATIC_DIR,
)
from app.csrf import CSRFMiddleware, get_csrf_token
from app.db.schema import init_db
from app.db.connections import get_db
from app.auth.session import (
    get_current_user, get_current_user_optional, require_admin,
    get_token_from_request, get_user_by_session, get_user_app_access,
    COOKIE_NAME,
)
from app.auth.audit import log_audit
from app.email import validate_approval_token, notify_user_approved, notify_user_declined
from app.api.auth_routes import router as auth_api_router
from app.api.user_routes import router as user_api_router
from app.api.group_routes import router as group_api_router
from app.api.app_routes import router as app_api_router
from app.api.audit_routes import router as audit_api_router
from app.logging_config import get_logger

logger = get_logger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Amphoraxe Auth Service starting up...")
    init_db()
    logger.info("Database initialized")
    yield
    logger.info("Amphoraxe Auth Service shutting down...")


app = FastAPI(
    title="Amphoraxe Auth",
    description="Central authentication service for the Amphoraxe ecosystem",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware (must be added before other middleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# CSRF protection (added first so it runs AFTER session middleware)
app.add_middleware(CSRFMiddleware)

# Session middleware
_session_secret = SECRET_KEY or secrets.token_hex(32)
if not SECRET_KEY and IS_PRODUCTION:
    logger.warning("AUTH_SECRET_KEY not set in production - using generated key")

app.add_middleware(
    SessionMiddleware,
    secret_key=_session_secret,
    max_age=SESSION_DURATION_DAYS * 86400,
    same_site="lax",
    https_only=IS_PRODUCTION,
)

# Static files
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals["csrf_token"] = get_csrf_token

# Include API routers
app.include_router(auth_api_router)
app.include_router(user_api_router)
app.include_router(group_api_router)
app.include_router(app_api_router)
app.include_router(audit_api_router)


# =============================================================================
# Health check
# =============================================================================

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "amphoraxe-auth",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
    }


# =============================================================================
# Email action (approve/decline from email link)
# =============================================================================

@app.get("/auth/email-action/{token}", response_class=HTMLResponse)
async def email_action(token: str, request: Request):
    user_id, action, error = validate_approval_token(token)

    if error:
        return templates.TemplateResponse("email_action.html", {
            "request": request,
            "success": False,
            "message": error,
        })

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            return templates.TemplateResponse("email_action.html", {
                "request": request,
                "success": False,
                "message": "User not found",
            })
        user = dict(user)

        if action == "approve":
            cursor.execute("UPDATE users SET is_approved = 1 WHERE id = ?", (user_id,))
            conn.commit()
            notify_user_approved(user["email"], user["name"])
            log_audit(None, "approve_user_email", resource_type="user", resource_id=user_id)
            message = f"{user['name']}'s account has been approved."
        elif action == "reject":
            cursor.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
            conn.commit()
            notify_user_declined(user["email"], user["name"])
            log_audit(None, "decline_user_email", resource_type="user", resource_id=user_id)
            message = f"{user['name']}'s account request has been declined."
        else:
            message = "Unknown action"

    return templates.TemplateResponse("email_action.html", {
        "request": request,
        "success": True,
        "message": message,
    })


# =============================================================================
# Fallback browser login page
# =============================================================================

@app.get("/auth/login", response_class=HTMLResponse)
async def login_page(request: Request):
    user = await get_current_user_optional(request)
    if user:
        return RedirectResponse(url="/admin/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/auth/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})


# =============================================================================
# Admin Console HTML Pages
# =============================================================================

@app.get("/admin/", response_class=HTMLResponse)
@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request, user: dict = Depends(get_current_user)):
    if not user.get("is_admin"):
        return RedirectResponse(url="/auth/login", status_code=302)
    return templates.TemplateResponse("admin/dashboard.html", {
        "request": request,
        "user": user,
        "page": "dashboard",
    })


@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users(request: Request, user: dict = Depends(get_current_user)):
    if not user.get("is_admin"):
        return RedirectResponse(url="/auth/login", status_code=302)
    return templates.TemplateResponse("admin/users.html", {
        "request": request,
        "user": user,
        "page": "users",
    })


@app.get("/admin/groups", response_class=HTMLResponse)
async def admin_groups(request: Request, user: dict = Depends(get_current_user)):
    if not user.get("is_admin"):
        return RedirectResponse(url="/auth/login", status_code=302)
    return templates.TemplateResponse("admin/groups.html", {
        "request": request,
        "user": user,
        "page": "groups",
    })


@app.get("/admin/access", response_class=HTMLResponse)
async def admin_access_matrix(request: Request, user: dict = Depends(get_current_user)):
    if not user.get("is_admin"):
        return RedirectResponse(url="/auth/login", status_code=302)
    return templates.TemplateResponse("admin/access.html", {
        "request": request,
        "user": user,
        "page": "access",
    })


@app.get("/admin/audit", response_class=HTMLResponse)
async def admin_audit(request: Request, user: dict = Depends(get_current_user)):
    if not user.get("is_admin"):
        return RedirectResponse(url="/auth/login", status_code=302)
    return templates.TemplateResponse("admin/audit.html", {
        "request": request,
        "user": user,
        "page": "audit",
    })


@app.get("/admin/settings", response_class=HTMLResponse)
async def admin_settings(request: Request, user: dict = Depends(get_current_user)):
    if not user.get("is_admin"):
        return RedirectResponse(url="/auth/login", status_code=302)
    return templates.TemplateResponse("admin/settings.html", {
        "request": request,
        "user": user,
        "page": "settings",
    })


# =============================================================================
# Root redirect
# =============================================================================

@app.get("/")
async def root(request: Request):
    user = await get_current_user_optional(request)
    if user and user.get("is_admin"):
        return RedirectResponse(url="/admin/", status_code=302)
    return RedirectResponse(url="/auth/login", status_code=302)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8300)
