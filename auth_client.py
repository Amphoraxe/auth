"""
Amphoraxe Auth Client - Lightweight module for validating auth cookies.

Drop this file into any Amphoraxe app (dbAMP, VC DataRoom, AMP LLMs, Tasker)
to validate the central amp_auth cookie against the auth service.

Usage:
    from auth_client import get_auth_user, require_auth_user

    # As a FastAPI dependency:
    @app.get("/protected")
    async def protected(user: dict = Depends(require_auth_user)):
        pass

    # Optional auth:
    @app.get("/")
    async def home(user: dict = Depends(get_auth_user_optional)):
        pass
"""

import time
import httpx
from typing import Optional
from fastapi import Request, HTTPException, status

# Auth service URL (localhost since all services run on the same machine)
AUTH_SERVICE_URL = "http://localhost:8300"
COOKIE_NAME = "amp_auth"

# In-process cache: token -> (user_dict, expiry_timestamp)
_cache: dict = {}
_CACHE_TTL = 30  # seconds
_CACHE_MAX = 1000


def _cleanup_cache():
    now = time.time()
    expired = [k for k, (_, exp) in _cache.items() if now > exp]
    for k in expired:
        del _cache[k]
    if len(_cache) > _CACHE_MAX:
        oldest = sorted(_cache.items(), key=lambda x: x[1][1])
        for k, _ in oldest[:len(_cache) - _CACHE_MAX]:
            del _cache[k]


def validate_token(token: str, app_slug: str = None) -> Optional[dict]:
    """Validate a session token against the central auth service.

    Returns user dict with app access info, or None if invalid.
    Results are cached for 30 seconds.
    """
    if not token:
        return None

    cache_key = f"{token}:{app_slug or ''}"
    now = time.time()

    # Check cache
    if cache_key in _cache:
        user, expiry = _cache[cache_key]
        if now < expiry:
            return user

    _cleanup_cache()

    # Call auth service
    try:
        params = {}
        if app_slug:
            params["app"] = app_slug
        response = httpx.get(
            f"{AUTH_SERVICE_URL}/api/v1/auth/validate",
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            timeout=5.0,
        )
        if response.status_code == 200:
            data = response.json()
            user = data.get("user")
            if user:
                user["apps"] = data.get("apps", [])
                user["features"] = data.get("features", {})
                _cache[cache_key] = (user, now + _CACHE_TTL)
                return user
    except httpx.RequestError:
        # Auth service unreachable - check cache even if expired
        if cache_key in _cache:
            return _cache[cache_key][0]
        return None

    return None


def get_token_from_request(request: Request) -> Optional[str]:
    """Extract amp_auth token from request cookie or Authorization header."""
    token = request.cookies.get(COOKIE_NAME)
    if token:
        return token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


async def get_auth_user(request: Request, app_slug: str = None) -> Optional[dict]:
    """Get the authenticated user from the central auth service, or None."""
    token = get_token_from_request(request)
    if not token:
        return None
    return validate_token(token, app_slug)


async def get_auth_user_optional(request: Request) -> Optional[dict]:
    """FastAPI dependency: returns user or None."""
    return await get_auth_user(request)


async def require_auth_user(request: Request) -> dict:
    """FastAPI dependency: requires authenticated user, raises 401 if not."""
    user = await get_auth_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return user


def has_app_access(user: dict, app_slug: str) -> bool:
    """Check if user has access to a specific app."""
    if user.get("is_admin"):
        return True
    return app_slug in user.get("apps", [])


def has_feature(user: dict, feature_name: str, action: str = "read") -> bool:
    """Check if user has a specific feature permission."""
    if user.get("is_admin") or user.get("features", {}).get("_admin"):
        return True
    feature = user.get("features", {}).get(feature_name, {})
    return feature.get(action, False)
