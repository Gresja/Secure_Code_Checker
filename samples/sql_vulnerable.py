"""
Sample: vulnerable SQL patterns (for testing only).

Purpose: Demonstrate SQL_INJECTION_RISK detections.
Expected: HIGH findings on string concatenation in queries.
Pair with: samples/safe/sql_safe.py (0 issues).
"""
def get_user(user_input):
    query = "SELECT * FROM users WHERE id = " + user_input
    return query

def get_product(product_id):
    query = "SELECT * FROM products WHERE id = " + str(product_id)
    return query
