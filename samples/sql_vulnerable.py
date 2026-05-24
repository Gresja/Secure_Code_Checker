def get_user(user_input):
    query = "SELECT * FROM users WHERE id = " + user_input
    return query

def get_product(product_id):
    query = "SELECT * FROM products WHERE id = " + str(product_id)
    return query
