import sqlite3

import click
from flask import current_app, g

from .security import hash_password

ALLOWED_TABLES = {"products", "orders", "users", "reviews"}

SCHEMA = """
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS reviews;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    address TEXT,
    is_admin INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price INTEGER NOT NULL,
    image TEXT
);

CREATE TABLE orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    total INTEGER NOT NULL,
    message TEXT,
    note TEXT,
    status TEXT NOT NULL DEFAULT 'new'
);

CREATE TABLE reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    body TEXT NOT NULL
);
"""

SEED_USERS = [
    ("admin", "admin123", "admin@cakeshop.local", "Head office", 1),
    ("alice", "alice123", "alice@example.com", "Chilonzor 12, Tashkent", 0),
    ("bob", "bob123", "bob@example.com", "Yunusobod 4, Tashkent", 0),
]

SEED_PRODUCTS = [
    ("Napoleon", 180000, "napoleon.svg"),
    ("Medovik", 165000, "medovik.svg"),
    ("Red Velvet", 210000, "red_velvet.svg"),
    ("Chocolate Truffle", 230000, "chocolate.svg"),
]

SEED_ORDERS = [
    (2, 1, 1, 180000, "Happy birthday, Mom!", "Leave at the door"),
    (3, 3, 2, 420000, "Congrats on the new job", "Call before delivery"),
]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    db.executemany(
        "INSERT INTO users (username, password_hash, email, address, is_admin) VALUES (?, ?, ?, ?, ?)",
        [(u, hash_password(p), e, a, adm) for u, p, e, a, adm in SEED_USERS],
    )
    db.executemany("INSERT INTO products (name, price, image) VALUES (?, ?, ?)", SEED_PRODUCTS)
    db.executemany(
        "INSERT INTO orders (user_id, product_id, quantity, total, message, note) VALUES (?, ?, ?, ?, ?, ?)",
        SEED_ORDERS,
    )
    db.commit()


@click.command("init-db")
def init_db_command():
    init_db()
    click.echo("Database initialised with demo data.")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)


def search_products(term):
    db = get_db()
    query = f"SELECT id, name, price, image FROM products WHERE name LIKE '%{term}%'"
    return db.execute(query).fetchall()


def count_rows(table):
    if table not in ALLOWED_TABLES:
        raise ValueError(f"unknown table: {table}")
    return get_db().execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
