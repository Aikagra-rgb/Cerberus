import tempfile
import os
from pathlib import Path
import sqlite3
os.environ.setdefault('ADMIN_USERNAME', 'testadmin')
os.environ.setdefault('ADMIN_PASSWORD', 'TestPass123!')
from src.alert_store import init_db, get_connection
from contextlib import closing

with tempfile.TemporaryDirectory() as tmp_dir:
    db_path = str(Path(tmp_dir) / 'sentinel.db')
    init_db(db_path)
    
    # Check triggers
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='trigger'")
    for row in cursor.fetchall():
        print(f'Trigger: {row}')
    conn.close()
    
    # Check if there's something with the database after init_db
    # Let's check pragma settings
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('PRAGMA foreign_keys')
    print(f'foreign_keys: {cursor.fetchone()}')
    cursor.execute('PRAGMA ignore_check_constraints')
    print(f'ignore_check_constraints: {cursor.fetchone()}')
    cursor.execute('PRAGMA query_only')
    print(f'query_only: {cursor.fetchone()}')
    conn.close()