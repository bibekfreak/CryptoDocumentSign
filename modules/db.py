# modules/db.py
import sqlite3

def init_db():
    conn = sqlite3.connect('pki_users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT NOT NULL,
                 email TEXT NOT NULL,
                 cert_path TEXT NOT NULL
             )''')
    conn.commit()
    conn.close()

def save_user(username, email, cert_path):
    conn = sqlite3.connect('pki_users.db')
    c = conn.cursor()
    c.execute("INSERT INTO users (username, email, cert_path) VALUES (?, ?, ?)",
              (username, email, cert_path))
    conn.commit()
    conn.close()

def get_user_by_cert(cert_path):
    conn = sqlite3.connect('pki_users.db')
    c = conn.cursor()
    c.execute("SELECT username, email FROM users WHERE cert_path = ?", (cert_path,))
    user = c.fetchone()
    conn.close()
    return {'username': user[0], 'email': user[1]} if user else None

