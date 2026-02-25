"""
Central auth database schema and initialization.
"""

from app.db.connections import get_db
from app.logging_config import log_startup, get_logger
from app.config import INITIAL_ADMIN_EMAIL, INITIAL_ADMIN_PASSWORD

logger = get_logger(__name__)


SCHEMA_SQL = """
-- Users
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    is_approved INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- Sessions
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Groups
CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    icon TEXT DEFAULT 'GRP',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User-Group membership
CREATE TABLE IF NOT EXISTS user_groups (
    user_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, group_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
);

-- App registry
CREATE TABLE IF NOT EXISTS apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    main_url TEXT,
    dev_url TEXT,
    main_port INTEGER,
    dev_port INTEGER,
    icon TEXT,
    is_active INTEGER DEFAULT 1,
    requires_auth INTEGER DEFAULT 1,
    admin_only INTEGER DEFAULT 0,
    display_order INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Per-user app access overrides
CREATE TABLE IF NOT EXISTS user_app_access (
    user_id INTEGER NOT NULL,
    app_id INTEGER NOT NULL,
    has_access INTEGER DEFAULT 1,
    granted_by INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, app_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
);

-- Per-group app access
CREATE TABLE IF NOT EXISTS group_app_access (
    group_id INTEGER NOT NULL,
    app_id INTEGER NOT NULL,
    has_access INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (group_id, app_id),
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
    FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
);

-- Feature permissions per group per app
CREATE TABLE IF NOT EXISTS feature_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    app_id INTEGER NOT NULL,
    feature_name TEXT NOT NULL,
    can_read INTEGER DEFAULT 0,
    can_write INTEGER DEFAULT 0,
    can_delete INTEGER DEFAULT 0,
    can_execute INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
    FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE,
    UNIQUE(group_id, app_id, feature_name)
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    app_slug TEXT,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id INTEGER,
    details TEXT,
    ip_address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Email approval tokens
CREATE TABLE IF NOT EXISTS approval_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
"""


INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_user_groups_user ON user_groups(user_id);
CREATE INDEX IF NOT EXISTS idx_user_groups_group ON user_groups(group_id);
CREATE INDEX IF NOT EXISTS idx_apps_slug ON apps(slug);
CREATE INDEX IF NOT EXISTS idx_user_app_access_user ON user_app_access(user_id);
CREATE INDEX IF NOT EXISTS idx_user_app_access_app ON user_app_access(app_id);
CREATE INDEX IF NOT EXISTS idx_group_app_access_group ON group_app_access(group_id);
CREATE INDEX IF NOT EXISTS idx_group_app_access_app ON group_app_access(app_id);
CREATE INDEX IF NOT EXISTS idx_feature_permissions_group ON feature_permissions(group_id);
CREATE INDEX IF NOT EXISTS idx_feature_permissions_app ON feature_permissions(app_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_app ON audit_log(app_slug);
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_approval_tokens_token ON approval_tokens(token);
CREATE INDEX IF NOT EXISTS idx_approval_tokens_user ON approval_tokens(user_id);
"""


SEED_APPS = [
    ("dbamp", "dbAMP", "Antimicrobial peptide database platform", "https://dbamp.amphoraxe.ca", "https://dev-dbamp.amphoraxe.ca", 8200, 9200, "SCI", 0, 1),
    ("vc_dataroom", "VC DataRoom", "Investor data room platform", "https://vc-dataroom.amphoraxe.ca", "https://dev-vc-dataroom.amphoraxe.ca", 8100, 9100, "FIN", 0, 2),
    ("amp_llm", "AMP LLM", "AI language model platform", "https://amp-llm.amphoraxe.ca", None, 8000, 9000, "LLM", 0, 3),
    ("analytics", "Analytics", "Web analytics dashboard", "https://analytics.amphoraxe.ca", None, 3000, None, "ANL", 1, 4),
    ("admin", "Admin Console", "Ecosystem administration", "https://admin.amphoraxe.ca", None, 8300, 9300, "ADM", 1, 5),
    ("tasker", "Tasker", "Task and project management", "https://tasker.amphoraxe.ca", None, 8400, 9400, "TSK", 0, 6),
]


def init_db():
    """Initialize the database schema, indexes, and seed data."""
    log_startup("info", "Initializing auth database...")

    with get_db() as conn:
        cursor = conn.cursor()

        # Create tables
        cursor.executescript(SCHEMA_SQL)
        log_startup("info", "Schema created/verified")

        # Create indexes
        cursor.executescript(INDEXES_SQL)
        log_startup("info", "Indexes created/verified")

        # Seed apps if empty
        cursor.execute("SELECT COUNT(*) as cnt FROM apps")
        if cursor.fetchone()["cnt"] == 0:
            for app_data in SEED_APPS:
                cursor.execute("""
                    INSERT INTO apps (slug, name, description, main_url, dev_url, main_port, dev_port, icon, admin_only, display_order)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, app_data)
            log_startup("info", f"Seeded {len(SEED_APPS)} apps")

        # Create initial admin if configured and no users exist
        if INITIAL_ADMIN_EMAIL and INITIAL_ADMIN_PASSWORD:
            cursor.execute("SELECT COUNT(*) as cnt FROM users WHERE email = ?", (INITIAL_ADMIN_EMAIL,))
            if cursor.fetchone()["cnt"] == 0:
                from app.auth.password import hash_password
                password_hash = hash_password(INITIAL_ADMIN_PASSWORD)
                cursor.execute("""
                    INSERT INTO users (email, password_hash, name, is_admin, is_active, is_approved)
                    VALUES (?, ?, ?, 1, 1, 1)
                """, (INITIAL_ADMIN_EMAIL.lower().strip(), password_hash, "Admin"))
                log_startup("info", f"Created initial admin: {INITIAL_ADMIN_EMAIL}")

        conn.commit()

    log_startup("info", "Database initialization complete")
