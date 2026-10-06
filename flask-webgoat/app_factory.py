"""Per-app glue for replay; not part of flask-webgoat.

flask_webgoat.create_app() takes no config and (re)creates ./database.db with one user, admin
(access_level 0). run.py adds response headers in an after_request hook, so the app replay uses is
run.py's app: create_app() reloads run.py to get a fresh one with the same hooks. init_app() adds two
normal test users for the attacker/victim roles and the data/ folder that /message writes into (the
repository does not ship it). The access level 1 for normal users is my choice; the app defines only 0
(admin) and checks `> 2` on /message.
"""
import importlib
import os
import sqlite3


def create_app(test_config=None):
    import run
    app = importlib.reload(run).app
    if test_config:
        app.config.update(test_config)
    return app


def init_app():
    import flask_webgoat
    os.makedirs("data", exist_ok=True)
    con = sqlite3.connect(flask_webgoat.DB_FILENAME)
    con.executemany("INSERT INTO user (id, username, password, access_level) VALUES (?, ?, ?, ?)",
                    [(2, "bob", "bob123", 1), (3, "alice", "alice123", 1)])
    con.commit()
    con.close()
