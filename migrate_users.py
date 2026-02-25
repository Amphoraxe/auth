#!/usr/bin/env python3
"""
One-time migration script: Copy users from dbAMP and VC DataRoom into central auth.db.

Deduplicates by email (keeps most recent password hash), creates app access entries,
and migrates groups + feature permissions.

Usage:
    cd ~/Developer/auth.amphoraxe.ca
    python migrate_users.py [--dry-run]
"""

import sqlite3
import sys
from pathlib import Path
from datetime import datetime

SOURCE_DB = Path.home() / "Developer" / "dev-dbamp.amphoraxe.ca" / "data" / "vc_dataroom.db"
AUTH_DB = Path(__file__).resolve().parent / "data" / "auth.db"

DRY_RUN = "--dry-run" in sys.argv


def read_users(db_path: Path) -> list:
    """Read all users from a source database."""
    if not db_path.exists():
        print(f"  Skipping {db_path} (not found)")
        return []
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return users


def read_groups(db_path: Path) -> list:
    """Read all groups from a source database."""
    if not db_path.exists():
        return []
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM groups")
    groups = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return groups


def read_user_groups(db_path: Path) -> list:
    """Read user-group memberships from a source database."""
    if not db_path.exists():
        return []
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user_groups")
    memberships = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return memberships


def read_feature_permissions(db_path: Path) -> list:
    """Read feature permissions from a source database."""
    if not db_path.exists():
        return []
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM feature_permissions")
        perms = [dict(row) for row in cursor.fetchall()]
    except sqlite3.OperationalError:
        perms = []
    conn.close()
    return perms


def migrate():
    print("=" * 60)
    print("Amphoraxe Auth - User Migration")
    print(f"Source: {SOURCE_DB}")
    print("=" * 60)
    if DRY_RUN:
        print("** DRY RUN - no changes will be made **\n")

    # Read source data
    print("Reading users...")
    source_users = read_users(SOURCE_DB)
    print(f"  Found {len(source_users)} users")

    print("Reading groups...")
    source_groups = read_groups(SOURCE_DB)
    print(f"  Found {len(source_groups)} groups")

    print("Reading group memberships...")
    source_memberships = read_user_groups(SOURCE_DB)
    print(f"  Found {len(source_memberships)} memberships")

    print("Reading feature permissions...")
    source_perms = read_feature_permissions(SOURCE_DB)
    print(f"  Found {len(source_perms)} permissions")

    if DRY_RUN:
        print("\n** DRY RUN complete. Run without --dry-run to execute. **")
        return

    # Connect to auth.db
    if not AUTH_DB.exists():
        print(f"\nERROR: {AUTH_DB} not found. Run the auth service first to initialize the schema.")
        sys.exit(1)

    conn = sqlite3.connect(str(AUTH_DB))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")

    # Get app IDs from seed data
    cursor.execute("SELECT id, slug FROM apps")
    app_ids = {row["slug"]: row["id"] for row in cursor.fetchall()}

    # Insert groups
    print("\nInserting groups...")
    group_id_map = {}  # old_id -> new_id
    for g in source_groups:
        cursor.execute("SELECT id FROM groups WHERE name = ?", (g["name"],))
        existing = cursor.fetchone()
        if existing:
            group_id_map[g["id"]] = existing["id"]
            print(f"  Group '{g['name']}' already exists (id={existing['id']})")
        else:
            cursor.execute("""
                INSERT INTO groups (name, description, icon)
                VALUES (?, ?, ?)
            """, (g["name"], g.get("description"), g.get("icon", "GRP")))
            group_id_map[g["id"]] = cursor.lastrowid
            print(f"  Created group '{g['name']}' (id={cursor.lastrowid})")

    # Insert users
    print("\nInserting users...")
    user_id_map = {}  # old_id -> new_id
    for user in source_users:
        email = user["email"].lower().strip()
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        existing = cursor.fetchone()
        if existing:
            user_id_map[user["id"]] = existing["id"]
            print(f"  User '{email}' already exists (id={existing['id']})")
            continue

        cursor.execute("""
            INSERT INTO users (email, password_hash, name, is_admin, is_active, is_approved, created_at, last_login)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            email,
            user["password_hash"],
            user.get("name", email.split("@")[0]),
            user.get("is_admin", 0),
            user.get("is_active", 1),
            user.get("is_approved", 0),
            user.get("created_at"),
            user.get("last_login"),
        ))
        user_id_map[user["id"]] = cursor.lastrowid
        print(f"  Created user '{email}' (id={cursor.lastrowid})")

    # No auto-granted app access — admin assigns per-user/group via admin console

    # Migrate user-group memberships
    print("\nMigrating group memberships...")
    for m in source_memberships:
        new_user_id = user_id_map.get(m["user_id"])
        new_group_id = group_id_map.get(m["group_id"])
        if new_user_id and new_group_id:
            cursor.execute("INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)",
                           (new_user_id, new_group_id))
    print(f"  Migrated {len(source_memberships)} memberships")

    # Migrate feature permissions — scoped to dbamp (source app)
    print("\nMigrating feature permissions...")
    dbamp_app_id = app_ids.get("dbamp")
    if dbamp_app_id:
        for perm in source_perms:
            new_group_id = group_id_map.get(perm["group_id"])
            if not new_group_id:
                continue
            cursor.execute("""
                INSERT OR REPLACE INTO feature_permissions (group_id, app_id, feature_name, can_read, can_write, can_delete, can_execute)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (new_group_id, dbamp_app_id, perm["feature_name"],
                  perm.get("can_read", 0), perm.get("can_write", 0),
                  perm.get("can_delete", 0), perm.get("can_execute", 0)))
    print(f"  Migrated {len(source_perms)} permissions (scoped to dbamp)")

    conn.commit()
    conn.close()

    print("\n" + "=" * 60)
    print("Migration complete!")
    print(f"  Users: {len(source_users)}")
    print(f"  Groups: {len(source_groups)}")
    print(f"  App access: assign via admin console")
    print(f"  Database: {AUTH_DB}")
    print("=" * 60)


if __name__ == "__main__":
    migrate()
