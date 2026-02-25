# Claude Code Settings - auth.amphoraxe.ca

## What This Is
Central authentication service for the Amphoraxe ecosystem. All apps (dbAMP, VC DataRoom, AMP LLM, Tasker) validate the `amp_auth` cookie against this service's `/api/v1/auth/validate` endpoint.

## Tech Stack
- FastAPI + SQLite (WAL mode) - same pattern as dbAMP and VC DataRoom
- Jinja2 templates for admin console
- Bcrypt password hashing (12 rounds)
- Domain-scoped cookies on `.amphoraxe.ca`

## Project Structure
- `app/main.py` - FastAPI app with CORS, CSRF, session middleware
- `app/config.py` - All config from `AUTH_*` env vars
- `app/auth/` - password.py, session.py, audit.py
- `app/api/` - auth_routes.py, user_routes.py, group_routes.py, app_routes.py, audit_routes.py
- `app/db/` - connections.py, schema.py (SQLite schema + seed data)
- `app/templates/` - Jinja2 templates (login, signup, admin console)
- `app/static/css/auth.css` - Dark theme admin console CSS
- `auth_client.py` - Standalone module to copy into other apps
- `migrate_users.py` - One-time migration from dbAMP/VC DataRoom

## Deployment
- Port 8300 (prod)
- LaunchDaemon: `com.ampauth.webapp`, `com.ampauth.autoupdate`
- Cloudflare tunnels: `auth.amphoraxe.ca` and `admin.amphoraxe.ca` -> localhost:8300

## Commit Preferences
- Do NOT include `Co-Authored-By` tags in commits

## Key Decisions
- Session tokens (not JWT) - instant revocation, matches existing pattern
- COLLATE NOCASE on email column - case-insensitive email matching
- CORS allows credentials from all `*.amphoraxe.ca` subdomains
- `auth_client.py` caches validation results for 30s to reduce auth API calls
- Admin-only apps hidden on demo.amphoraxe.ca unless user.is_admin
