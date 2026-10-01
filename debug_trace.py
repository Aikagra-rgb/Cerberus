import tempfile
import os
from pathlib import Path
import sqlite3
os.environ.setdefault('ADMIN_USERNAME', 'testadmin')
os.environ.setdefault('ADMIN_PASSWORD', 'TestPass123!')
from src.alert_store import init_db, hash_password

with tempfile.TemporaryDirectory() as tmp_dir:
    db_path = str(Path(tmp_dir) / 'sentinel.db')
    init_db(db_path)
    
    # First, create a user
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    pwd_hash, salt = hash_password('adminpass')
    cursor.execute(
        'INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)',
        ('testuser', pwd_hash, salt, 'ADMIN')
    )
    conn.commit()
    print('First insert: OK')
    conn.close()
    
    # Now call init_db again
    init_db(db_path)
    
    # Check the exact SQL being executed
    conn = sqlite3.connect(db_path)
    conn.set_trace_callback(lambda sql: print(f'SQL: {sql}'))
    cursor = conn.cursor()
    pwd_hash2, salt2 = hash_password('otherpass')
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