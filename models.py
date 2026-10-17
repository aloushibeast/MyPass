import sqlite3
from contextlib import closing
from pathlib import Path

DB_PATH = Path("mypass.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with closing(get_connection()) as conn:
        cur = conn.cursor()

        # USERS table with security questions
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt BLOB NOT NULL,

                q1 TEXT NOT NULL,
                a1_hash TEXT NOT NULL,
                q2 TEXT NOT NULL,
                a2_hash TEXT NOT NULL,
                q3 TEXT NOT NULL,
                a3_hash TEXT NOT NULL
            );
            """
        )

        # VAULT items table stays the same
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                item_type TEXT NOT NULL,
                label TEXT NOT NULL,

                username_enc TEXT,
                password_enc TEXT,
                url_enc TEXT,

                card_number_enc TEXT,
                card_holder_enc TEXT,
                card_expiry TEXT,
                card_cvv_enc TEXT,

                identity_number_enc TEXT,
                identity_type TEXT,

                note_enc TEXT,

                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )

        conn.commit()
