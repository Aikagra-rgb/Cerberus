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
    
    # First, create a user - trace everything
    conn1 = sqlite3.connect(db_path)
    conn1.set_trace_callback(lambda sql: print(f'CONN1: {sql}'))
    cursor1 = conn1.cursor()
    pwd_hash, salt = hash_password('adminpass')
    print('Executing first INSERT...')
    cursor1.execute(
        'INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)',
        ('testuser', pwd_hash, salt, 'ADMIN')
    )
    print('After execute, before commit')
    cursor1.execute('SELECT COUNT(*) FROM users WHERE username = "testuser"')
    print(f'Count in conn1 before commit: {cursor1.fetchone()}')
    conn1.commit()
    print('After commit')
    cursor1.execute('SELECT COUNT(*) FROM users WHERE username = "testuser"')
    print(f'Count in conn1 after commit: {cursor1.fetchone()}')
    conn1.close()
    print('conn1 closed')
    
    # Check from a new connection immediately
    conn2 = sqlite3.connect(db_path)
    conn2.set_trace_callback(lambda sql: print(f'CONN2: {sql}'))
    cursor2 = conn2.cursor()
    cursor2.execute('SELECT COUNT(*) FROM users WHERE username = "testuser"')
    print(f'Count in conn2 after conn1 closed: {cursor2.fetchone()}')
    conn2.close()
    
    # Now call init_db again
    init_db(db_path)
    
    # Check count
    conn3 = sqlite3.connect(db_path)
    cursor3 = conn3.cursor()
    cursor3.execute('SELECT COUNT(*) FROM users WHERE username = "testuser"')
    print(f'Count in conn3 after init_db: {cursor3.fetchone()}')
    conn3.close()
    
    # Now try second insert
    conn4 = sqlite3.connect(db_path)
    conn4.set_trace_callback(lambda sql: print(f'CONN4: {sql}'))
    cursor4 = conn4.cursor()
    pwd_hash2, salt2 = hash_password('otherpass')
    try:
        cursor4.execute(
            'INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)',
            ('testuser', pwd_hash2, salt2, 'ANALYST')
        )
        conn4.commit()
        print('Second insert: SUCCESS (unexpected!)')
    except sqlite3.IntegrityError as e:
        print(f'Second insert: INTEGRITY ERROR (expected): {e}')
    conn4.close()
    
    # Check final state
    conn5 = sqlite3.connect(db_path)
    cursor5 = conn5.cursor()
    cursor5.execute('SELECT rowid, username FROM users')
    for row in cursor5.fetchall():
        print(f'  rowid={row[0]}, username={row[1]}')
    conn5.close()