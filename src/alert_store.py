import csv
import hashlib
import os
import re
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime

from src.config import DB_PATH


# PBKDF2 configuration — 600k iterations as recommended by OWASP 2024
_PBKDF2_ITERATIONS = 600_000
_PBKDF2_HASH_NAME = "sha256"
_PBKDF2_DK_LEN = 32  # 256-bit derived key


ALERT_COLUMNS = ["Timestamp", "Type", "Source IP", "Location", "Details"]


def get_connection(db_path=DB_PATH):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ==========================================
# AUTHENTICATION & PASSWORD UTILITIES
# SECURITY: Uses PBKDF2-HMAC-SHA256 with 600k iterations (OWASP 2024)
# ==========================================
def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    """Generates a PBKDF2-HMAC-SHA256 derived key using a cryptographically secure random salt."""
    if not salt:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        _PBKDF2_HASH_NAME,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        _PBKDF2_ITERATIONS,
        dklen=_PBKDF2_DK_LEN,
    ).hex()
    return pwd_hash, salt


def verify_password(password: str, salt: str, hashed_password: str) -> bool:
    """Verifies a plain password against the stored salt and PBKDF2 hash."""
    pwd_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(pwd_hash, hashed_password)


def create_user(username: str, password: str, role: str, db_path=DB_PATH) -> bool:
    """Creates a new user account with hashed password and specific role."""
    init_db(db_path)
    pwd_hash, salt = hash_password(password)
    try:
        with closing(get_connection(db_path)) as conn:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, salt, role)
                VALUES (?, ?, ?, ?)
                """,
                (username.lower().strip(), pwd_hash, salt, role.upper().strip()),
            )
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Username already exists


def authenticate_user(username: str, password: str, db_path=DB_PATH) -> dict | None:
    """Authenticates a user and returns a dict with username and role, or None."""
    init_db(db_path)
    with closing(get_connection(db_path)) as conn:
        row = conn.execute(
            "SELECT username, password_hash, salt, role FROM users WHERE username = ?",
            (username.lower().strip(),),
        ).fetchone()
        
    if not row:
        return None
        
    if verify_password(password, row["salt"], row["password_hash"]):
        return {"username": row["username"], "role": row["role"]}
    return None


def create_session(username: str, db_path=DB_PATH) -> str:
    """Creates a session token for the user and stores it in the database."""
    init_db(db_path)
    token = secrets.token_hex(32)
    expires_at = datetime.fromtimestamp(datetime.now().timestamp() + 86400).strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_connection(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO sessions (token, username, expires_at)
            VALUES (?, ?, ?)
            """,
            (token, username.lower().strip(), expires_at),
        )
        conn.commit()
    return token


def get_session(token: str, db_path=DB_PATH) -> dict | None:
    """Retrieves session details if token is valid and not expired."""
    init_db(db_path)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_connection(db_path)) as conn:
        conn.execute("DELETE FROM sessions WHERE datetime(expires_at) < datetime(?)", (now,))
        conn.commit()
        
        row = conn.execute(
            """
            SELECT s.username, u.role FROM sessions s
            JOIN users u ON s.username = u.username
            WHERE s.token = ? AND datetime(s.expires_at) >= datetime(?)
            """,
            (token, now),
        ).fetchone()
        
    if row:
        return {"username": row["username"], "role": row["role"]}
    return None


def delete_session(token: str, db_path=DB_PATH):
    """Revokes / deletes an active session token."""
    init_db(db_path)
    with closing(get_connection(db_path)) as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()


# ==========================================
# ACTIVE IPS & REPUTATION UTILITIES
# ==========================================
def update_ip_reputation(ip: str, score_to_add: float, db_path=DB_PATH) -> bool:
    """Increments threat score and sets blocked = 1 if score >= 100. Returns blocked status."""
    init_db(db_path)
    if ip == "Unknown" or ip == "127.0.0.1" or ip == "Localhost":
        return False # Never block local debuggers
        
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_connection(db_path)) as conn:
        row = conn.execute("SELECT score, blocked FROM reputation WHERE ip = ?", (ip,)).fetchone()
        if row:
            new_score = float(row["score"]) + score_to_add
            blocked = 1 if new_score >= 100.0 else int(row["blocked"])
            conn.execute(
                """
                UPDATE reputation
                SET score = ?, blocked = ?, updated_at = ?
                WHERE ip = ?
                """,
                (new_score, blocked, now, ip),
            )
        else:
            blocked = 1 if score_to_add >= 100.0 else 0
            conn.execute(
                """
                INSERT INTO reputation (ip, score, blocked, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (ip, score_to_add, blocked, now),
            )
        conn.commit()
    return bool(blocked)


def is_ip_blocked(ip: str, db_path=DB_PATH) -> bool:
    """Returns True if the IP's reputation blocked column is marked active."""
    init_db(db_path)
    with closing(get_connection(db_path)) as conn:
        row = conn.execute("SELECT blocked FROM reputation WHERE ip = ?", (ip,)).fetchone()
    return bool(row["blocked"]) if row else False


def list_blocked_ips(db_path=DB_PATH) -> list:
    """Lists all blacklisted attackers in the database."""
    init_db(db_path)
    with closing(get_connection(db_path)) as conn:
        rows = conn.execute(
            """
            SELECT ip, score, updated_at
            FROM reputation
            WHERE blocked = 1
            ORDER BY score DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def unblock_ip(ip: str, db_path=DB_PATH):
    """Unblocks an IP and fully resets its reputation threat score to zero."""
    init_db(db_path)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_connection(db_path)) as conn:
        conn.execute(
            """
            UPDATE reputation
            SET score = 0, blocked = 0, updated_at = ?
            WHERE ip = ?
            """,
            (now, ip),
        )
        conn.commit()


def get_ip_reputation(ip: str, db_path=DB_PATH) -> dict:
    """Retrieves threat score and block status for a specific IP."""
    init_db(db_path)
    with closing(get_connection(db_path)) as conn:
        row = conn.execute("SELECT score, blocked, updated_at FROM reputation WHERE ip = ?", (ip,)).fetchone()
    if row:
        return {"ip": ip, "score": float(row["score"]), "blocked": bool(row["blocked"]), "updated_at": row["updated_at"]}
    return {"ip": ip, "score": 0.0, "blocked": False, "updated_at": None}


def list_all_reputations(db_path=DB_PATH) -> list:
    """Lists all recorded IP reputations."""
    init_db(db_path)
    with closing(get_connection(db_path)) as conn:
        rows = conn.execute("SELECT ip, score, blocked, updated_at FROM reputation ORDER BY score DESC LIMIT 100").fetchall()
    return [dict(row) for row in rows]


# ==========================================
# DATABASE INITIALIZATION & OPERATIONS
# ==========================================
def init_db(db_path=DB_PATH):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with closing(get_connection(db_path)) as conn:
        # 1. Active Alerts
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                location TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        # 2. Schema Migration: Add ai_report column dynamically if missing
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(alerts)")
        columns = {row[1] for row in cursor.fetchall()}
        if "ai_report" not in columns:
            cursor.execute("ALTER TABLE alerts ADD COLUMN ai_report TEXT")
            conn.commit()

        # 3. Legacy Migration Tables
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS legacy_csv_migrations (
                path TEXT PRIMARY KEY,
                size_bytes INTEGER NOT NULL,
                modified_at REAL NOT NULL,
                migrated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS legacy_csv_rows (
                row_key TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                imported_at TEXT NOT NULL
            )
            """
        )
        # 4. RBAC Users Table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        # 5. Session Tokens Table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
            )
            """
        )
        # 6. Active IPS Reputation Table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reputation (
                ip TEXT PRIMARY KEY,
                score REAL DEFAULT 0,
                blocked INTEGER DEFAULT 0,
                updated_at TEXT NOT NULL
            )
            """
        )
        # 7. Indexes
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(threat_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reputation_blocked ON reputation(blocked)")
        conn.commit()

    # Seed default user accounts if missing
    _seed_default_users(db_path)


def _seed_default_users(db_path):
    """Seed default Administrator and Analyst accounts if none exist in users table.
    
    NOTE: These are initial setup credentials. Change them immediately after
    first login via the administration interface.
    """
    with closing(get_connection(db_path)) as conn:
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            # Seed ADMIN (stronger default password)
            admin_pwd_hash, admin_salt = hash_password("LogSentry@Admin2026!")
            conn.execute(
                """
                INSERT INTO users (username, password_hash, salt, role)
                VALUES (?, ?, ?, ?)
                """,
                ("admin", admin_pwd_hash, admin_salt, "ADMIN"),
            )
            # Seed ANALYST (stronger default password)
            analyst_pwd_hash, analyst_salt = hash_password("LogSentry@Analyst2026!")
            conn.execute(
                """
                INSERT INTO users (username, password_hash, salt, role)
                VALUES (?, ?, ?, ?)
                """,
                ("analyst", analyst_pwd_hash, analyst_salt, "ANALYST"),
            )
            conn.commit()
            print("[SECURITY] Default accounts seeded. Change passwords after first login!")
            print("  admin    / LogSentry@Admin2026!")
            print("  analyst  / LogSentry@Analyst2026!")


def add_alert(threat_type, source_ip, location, details, timestamp=None, ai_report=None, db_path=DB_PATH):
    init_db(db_path)
    timestamp = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_connection(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO alerts (timestamp, threat_type, source_ip, location, details, ai_report)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (timestamp, threat_type, source_ip, location, details.strip(), ai_report),
        )
        conn.commit()


def list_alerts(limit=None, db_path=DB_PATH, newest_first=False):
    init_db(db_path)
    direction = "DESC" if newest_first else "ASC"
    query = """
        SELECT
            timestamp AS "Timestamp",
            threat_type AS "Type",
            source_ip AS "Source IP",
            location AS "Location",
            details AS "Details",
            ai_report AS "ai_report"
        FROM alerts
        ORDER BY datetime(timestamp) {direction}, id {direction}
    """.format(direction=direction)
    params = ()
    if limit is not None:
        query += " LIMIT ?"
        params = (int(limit),)

    with closing(get_connection(db_path)) as conn:
        return [dict(row) for row in conn.execute(query, params).fetchall()]


def migrate_legacy_csv(csv_path, db_path=DB_PATH):
    if not os.path.exists(csv_path):
        return 0

    init_db(db_path)
    stat = os.stat(csv_path)

    with closing(get_connection(db_path)) as conn:
        existing = conn.execute(
            """
            SELECT 1 FROM legacy_csv_migrations
            WHERE path = ? AND size_bytes = ? AND modified_at = ?
            """,
            (csv_path, stat.st_size, stat.st_mtime),
        ).fetchone()
        if existing:
            return 0

        inserted = 0
        with open(csv_path, newline="", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row_number, row in enumerate(reader, start=2):
                if not row or not any(row.values()):
                    continue
                values = tuple(row.get(column, "") for column in ALERT_COLUMNS)
                row_key = hashlib.sha256(
                    repr((row_number, values)).encode("utf-8")
                ).hexdigest()
                try:
                    conn.execute(
                        """
                        INSERT INTO legacy_csv_rows (row_key, path, imported_at)
                        VALUES (?, ?, ?)
                        """,
                        (
                            row_key,
                            csv_path,
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        ),
                    )
                except sqlite3.IntegrityError:
                    continue

                conn.execute(
                    """
                    INSERT INTO alerts (
                        timestamp, threat_type, source_ip, location, details
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    values,
                )
                inserted += 1

        conn.execute(
            """
            INSERT OR REPLACE INTO legacy_csv_migrations
                (path, size_bytes, modified_at, migrated_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                csv_path,
                stat.st_size,
                stat.st_mtime,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        conn.commit()
        return inserted
