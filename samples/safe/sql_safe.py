"""
Sample: secure SQL (reference implementation).

Purpose: Show correct use of parameterized queries; scanner should report 0 issues.
Contrasts with: samples/sql_vulnerable.py
"""
import sqlite3


def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def get_product(product_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
    return cursor.fetchone()
