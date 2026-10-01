import tempfile
import os
from pathlib import Path
import sqlite3
os.environ.setdefault('ADMIN_USERNAME', 'testadmin')
os.environ.setdefault('ADMIN_PASSWORD', 'TestPass123!')
from src.alert_store import init_db

with tempfile.TemporaryDirectory() as tmp_dir:
    db_path = str(Path(tmp_dir) / 'sentinel.db')
    init_db(db_path)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('PRAGMA table_info(users)')
    for row in cursor.fetchall():
        print(row)
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'")
    print('Table schema:', cursor.fetchone())
    conn.close()