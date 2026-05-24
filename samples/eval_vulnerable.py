"""
Sample: eval() and credentials (for testing only).

Purpose: Demonstrate EVAL_USAGE and HARDCODED_CREDENTIAL.
Expected: CRITICAL findings on eval and hardcoded secrets.
Pair with: samples/safe/eval_safe.py (0 issues).
"""
def calculate(user_input):
    result = eval(user_input)       # dangerous!
    return result

def run_command(cmd):
    output = eval("exec(" + cmd + ")")  # also dangerous!
    return output

password = "admin1234"
api_key = "sk-abc123xyz789"
secret = "mysecretkey"
db_password = "root123"

def connect():
    token = "Bearer eyJhbGciOiJIUzI1NiJ9"
    return token
