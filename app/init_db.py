import sqlite3
import os

DB_PATH = '/app/data/portal.db'

def init_db():
    os.makedirs('/app/data', exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'employee',
            failed_attempts INTEGER DEFAULT 0,
            locked INTEGER DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip_address TEXT,
            success INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    users = [
        (1, 'alice',   'password123',  'admin'),
        (2, 'bob',     'bobpass',      'employee'),
        (3, 'charlie', 'charliepass',  'employee'),
    ]
    cursor.executemany(
        "INSERT OR IGNORE INTO users (id, username, password, role) VALUES (?,?,?,?)",
        users
    )

    conn.commit()
    conn.close()
    print("[INIT] Database initialized.")

if __name__ == '__main__':
    init_db()
