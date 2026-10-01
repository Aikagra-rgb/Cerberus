import tempfile
import os
from pathlib import Path
import sqlite3
os.environ.setdefault('ADMIN_USERNAME', 'testadmin')
os.environ.setdefault('ADMIN_PASSWORD', 'TestPass123!')
from src.alert_store import init_db, hash_password
from contextlib import closing

with tempfile.TemporaryDirectory() as tmp_dir:
    db_path = str(Path(tmp_dir) / 'sentinel.db')
    init_db(db_path)
    
    # First, create a user using create_user logic
    pwd_hash, salt = hash_password('adminpass')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)',
        ('testuser', pwd_hash, salt, 'ADMIN')
    )
    conn.commit()
    print('First insert: OK')
    conn.close()
    
    # Now call init_db again (like create_user does)
    init_db(db_path)
    
    # Check if there are any open transactions or locks
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('PRAGMA integrity_check')
    print(f'Integrity check: {cursor.fetchone()}')
    cursor.execute('PRAGMA busy_timeout')
    print(f'busy_timeout: {cursor.fetchone()}')
    cursor.execute('PRAGMA journal_mode')
    print(f'journal_mode: {cursor.fetchone()}')
    conn.close()
    
    # Now try to insert same username again using a new connection
    pwd_hash2, salt2 = hash_password('otherpass')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)',
            ('testuser', pwd_hash2, salt2, 'ANALYST')
        )
        conn.commit()
        print('Second insert: SUCCESS (unexpected!)')
    except sqlite3.IntegrityError as e:
        print(f'Second insert: INTEGRITY ERROR (expected): {e}')
    conn.close()
    
    # Check final state
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users')
    print(f'Final users: {cursor.fetchall()}')
    conn.close()