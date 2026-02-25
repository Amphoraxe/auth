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

DBAMP_DB = Path.home() / "Developer" / "dbamp.amphoraxe.ca" / "data" / "vc_dataroom.db"
VC_DB = Path.home() / "Developer" / "vc_dataroom_main" / "data" / "vc_dataroom.db"
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
    print("=" * 60)
    if DRY_RUN:
        print("** DRY RUN - no changes will be made **\n")

    # Read source data
    print("Reading dbAMP users...")
    dbamp_users = read_users(DBAMP_DB)
    print(f"  Found {len(dbamp_users)} users")

    print("Reading VC DataRoom users...")
    vc_users = read_users(VC_DB)
    print(f"  Found {len(vc_users)} users")

    # Deduplicate by email - keep most recent (by last_login or created_at)
    merged = {}
    source_map = {}  # email -> set of source app slugs

    for user in dbamp_users:
        email = user["email"].lower().strip()
        source_map.setdefault(email, set()).add("dbamp")
        if email not in merged or (user.get("last_login") or "") > (merged[email].get("last_login") or ""):
            merged[email] = user

    for user in vc_users:
        email = user["email"].lower().strip()
        source_map.setdefault(email, set()).add("vc_dataroom")
        if email not in merged or (user.get("last_login") or "") > (merged[email].get("last_login") or ""):
            merged[email] = user

    print(f"\nDeduplicated to {len(merged)} unique users")

    # Read groups from both sources
    print("\nReading groups...")
    dbamp_groups = read_groups(DBAMP_DB)
    vc_groups = read_groups(VC_DB)
    print(f"  dbAMP: {len(dbamp_groups)} groups")
    print(f"  VC DataRoom: {len(vc_groups)} groups")

    # Merge groups by name
    merged_groups = {}
    for g in dbamp_groups + vc_groups:
        name = g["name"]
        if name not in merged_groups:
            merged_groups[name] = g

    print(f"  Merged to {len(merged_groups)} unique groups")

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

    # Insert groups
    print("\nInserting groups...")
    group_id_map = {}  # old_name -> new_id
    for name, g in merged_groups.items():
        cursor.execute("SELECT id FROM groups WHERE name = ?", (name,))
        existing = cursor.fetchone()
        if existing:
            group_id_map[name] = existing["id"]
            print(f"  Group '{name}' already exists (id={existing['id']})")
        else:
            cursor.execute("""
                INSERT INTO groups (name, description, icon)
                VALUES (?, ?, ?)
            """, (name, g.get("description"), g.get("icon", "GRP")))
            group_id_map[name] = cursor.lastrowid
            print(f"  Created group '{name}' (id={cursor.lastrowid})")

    # Get app IDs
    cursor.execute("SELECT id, slug FROM apps")
    app_ids = {row["slug"]: row["id"] for row in cursor.fetchall()}

    # Insert users
    print("\nInserting users...")
    user_id_map = {}  # old_email -> new_id
    for email, user in merged.items():
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        existing = cursor.fetchone()
        if existing:
            user_id_map[email] = existing["id"]
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
        user_id_map[email] = cursor.lastrowid
        print(f"  Created user '{email}' (id={cursor.lastrowid})")

    # Create app access entries
    print("\nCreating app access entries...")
    for email, app_slugs in source_map.items():
        user_id = user_id_map.get(email)
        if not user_id:
            continue
        for slug in app_slugs:
            app_id = app_ids.get(slug)
            if not app_id:
                continue
            cursor.execute("""
                INSERT OR IGNORE INTO user_app_access (user_id, app_id, has_access)
                VALUES (?, ?, 1)
            """, (user_id, app_id))
            print(f"  {email} -> {slug}")

    # Migrate user-group memberships
    print("\nMigrating group memberships...")
    # Build email->old_user_id maps for each source
    dbamp_id_to_email = {u["id"]: u["email"].lower().strip() for u in dbamp_users}
    vc_id_to_email = {u["id"]: u["email"].lower().strip() for u in vc_users}
    # Build old group_id -> group_name maps
    dbamp_gid_to_name = {g["id"]: g["name"] for g in dbamp_groups}
    vc_gid_to_name = {g["id"]: g["name"] for g in vc_groups}

    for membership in read_user_groups(DBAMP_DB):
        email = dbamp_id_to_email.get(membership["user_id"])
        group_name = dbamp_gid_to_name.get(membership["group_id"])
        if email and group_name:
            user_id = user_id_map.get(email)
            new_group_id = group_id_map.get(group_name)
            if user_id and new_group_id:
                cursor.execute("INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)",
                               (user_id, new_group_id))

    for membership in read_user_groups(VC_DB):
        email = vc_id_to_email.get(membership["user_id"])
        group_name = vc_gid_to_name.get(membership["group_id"])
        if email and group_name:
            user_id = user_id_map.get(email)
            new_group_id = group_id_map.get(group_name)
            if user_id and new_group_id:
                cursor.execute("INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)",
                               (user_id, new_group_id))

    print("  Done")

    # Migrate feature permissions (scoped to correct app)
    print("\nMigrating feature permissions...")
    for perm in read_feature_permissions(DBAMP_DB):
        group_name = dbamp_gid_to_name.get(perm["group_id"])
        if not group_name:
            continue
        new_group_id = group_id_map.get(group_name)
        if not new_group_id:
            continue
        dbamp_app_id = app_ids.get("dbamp")
        if not dbamp_app_id:
            continue
        cursor.execute("""
            INSERT OR REPLACE INTO feature_permissions (group_id, app_id, feature_name, can_read, can_write, can_delete, can_execute)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (new_group_id, dbamp_app_id, perm["feature_name"],
              perm.get("can_read", 0), perm.get("can_write", 0),
              perm.get("can_delete", 0), perm.get("can_execute", 0)))

    for perm in read_feature_permissions(VC_DB):
        group_name = vc_gid_to_name.get(perm["group_id"])
        if not group_name:
            continue
        new_group_id = group_id_map.get(group_name)
        if not new_group_id:
            continue
        vc_app_id = app_ids.get("vc_dataroom")
        if not vc_app_id:
            continue
        cursor.execute("""
            INSERT OR REPLACE INTO feature_permissions (group_id, app_id, feature_name, can_read, can_write, can_delete, can_execute)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (new_group_id, vc_app_id, perm["feature_name"],
              perm.get("can_read", 0), perm.get("can_write", 0),
              perm.get("can_delete", 0), perm.get("can_execute", 0)))

    print("  Done")

    conn.commit()
    conn.close()

    print("\n" + "=" * 60)
    print("Migration complete!")
    print(f"  Users: {len(merged)}")
    print(f"  Groups: {len(merged_groups)}")
    print(f"  Database: {AUTH_DB}")
    print("=" * 60)


if __name__ == "__main__":
    migrate()
