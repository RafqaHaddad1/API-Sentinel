import sqlite3
from flask import g
from settings import DB_PATH

DATABASE = str(DB_PATH)

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

def get_connection():
    try:
        return get_db()
    except RuntimeError:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        return conn

def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()
