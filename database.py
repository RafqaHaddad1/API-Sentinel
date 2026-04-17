import sqlite3
from flask import g

DATABASE = "sam_ads (1).db"

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  # allows dict-like access
    return g.db

def close_db(e=None):
    db = g.pop("db", None)

    if db is not None:
        db.close()