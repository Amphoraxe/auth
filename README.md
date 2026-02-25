# Amphoraxe Auth Service

Central authentication service for the Amphoraxe ecosystem. Provides unified login, user management, group-based access control, and audit logging for all Amphoraxe apps.

## Architecture

- **Framework**: FastAPI + SQLite (WAL mode)
- **Auth**: Opaque session tokens, domain-scoped cookie (`.amphoraxe.ca`)
- **Port**: 8300 (prod), 9300 (reserved for dev)
- **Admin console**: Jinja2 templates served at `/admin/*`
- **API**: JSON API at `/api/v1/*` consumed by all apps

## Quick Start

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Set initial admin
export AUTH_INITIAL_ADMIN_EMAIL=admin@amphoraxe.ca
export AUTH_INITIAL_ADMIN_PASSWORD=yourpassword123

# Run
uvicorn app.main:app --host 0.0.0.0 --port 8300
```

## App Integration

Copy `auth_client.py` into any Amphoraxe app to validate the `amp_auth` cookie:

```python
from auth_client import require_auth_user
from fastapi import Depends

@app.get("/protected")
async def protected(user: dict = Depends(require_auth_user)):
    pass
```

## API Endpoints

### Auth (`/api/v1/auth/`)
- `POST /login` - Authenticate, set cookie
- `POST /logout` - Clear session
- `POST /signup` - Register (pending approval)
- `GET /validate` - Validate token (used by other apps)
- `GET /me` - Current user + app access
- `POST /password` - Change password

### Admin (`/api/v1/`)
- `GET/POST /users` - User management
- `GET/POST/PUT/DELETE /groups` - Group management
- `GET/POST/PUT /apps` - App registry
- `GET /audit` - Audit log queries

## Deployment

LaunchDaemon plists:
- `com.ampauth.webapp` - uvicorn on port 8300
- `com.ampauth.autoupdate` - 30s git poll + restart

## User Migration

```bash
python migrate_users.py --dry-run  # preview
python migrate_users.py            # execute
```
