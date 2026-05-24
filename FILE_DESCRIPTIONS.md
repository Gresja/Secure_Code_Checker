# File descriptions (complete reference)

Every source file in this project includes a **module docstring** (or HTML comment) at the top describing its purpose. This document lists the same information in one place for reports and onboarding.

---

## Entry points

### `main.py`
- **Role:** CLI entry point  
- **Does:** Parses arguments with Click, runs `CodeAnalyzer` on one `.py` file, prints colored issues, optional `--output` for JSON/HTML  
- **Run:** `python main.py <file.py> [-v] [-o json|html|both]`

### `web_app.py`
- **Role:** Web entry point (Flask)  
- **Does:** Serves scan UI on port 5001; accepts paste or `.py` upload; returns HTML report inline  
- **Run:** `python web_app.py` → `http://127.0.0.1:5001`

---

## Core (`checker/`)

### `checker/__init__.py`
- **Role:** Package marker; exports `CodeAnalyzer`  
- **Does:** Documents package layout (parser, reporter, rules)

### `checker/parser.py`
- **Role:** Analysis engine  
- **Does:** `load_file` / `load_source`, `ast.parse`, `run_checks()` over all rules, `add_issue()` with line snippets

### `checker/reporter.py`
- **Role:** Reporting  
- **Does:** Risk score, severity summary, dynamic guidance, `save_json()` / `save_html()` / `build_report_data()`

---

## Rules (`checker/rules/`)

| File | Class | Rule ID | Severity |
|------|--------|---------|----------|
| `__init__.py` | (exports) | — | Registry of all checkers |
| `sql_injection.py` | SQLInjectionChecker | SQL_INJECTION_RISK | HIGH |
| `hardcoded_credentials.py` | HardcodedCredentialsChecker | HARDCODED_CREDENTIAL | CRITICAL |
| `unsafe_file.py` | UnsafeFileHandlingChecker | UNSAFE_FILE_HANDLING | MEDIUM |
| `eval_usage.py` | EvalUsageChecker | EVAL_USAGE | CRITICAL |
| `weak_hashing.py` | WeakHashingChecker | WEAK_HASHING_ALGORITHM | HIGH |
| `command_injection.py` | CommandInjectionChecker | COMMAND_INJECTION_RISK | CRITICAL |
| `insecure_deserialization.py` | InsecureDeserializationChecker | INSECURE_DESERIALIZATION | CRITICAL/HIGH |
| `insecure_randomness.py` | InsecureRandomnessChecker | INSECURE_RANDOMNESS | HIGH |
| `path_traversal.py` | PathTraversalChecker | PATH_TRAVERSAL | HIGH |

---

## Web UI

### `templates/index.html`
- **Role:** Front-end for web scanner  
- **Does:** Dark-themed form, results layout, tabs, Clear button, issue cards

---

## Generated output (not source)

| Path | Description |
|------|-------------|
| `reports/report.html` | Last HTML scan report (overwritten each run with `--output`) |
| `reports/report.json` | Last JSON scan report |

---

## Vulnerable samples (`samples/`)

| File | Intended findings | Topic |
|------|-------------------|--------|
| `sql_vulnerable.py` | SQL_INJECTION_RISK | String-built SQL |
| `credentials_vulnerable.py` | HARDCODED_CREDENTIAL | Inline secrets |
| `file_vulnerable.py` | UNSAFE_FILE_HANDLING | Bare `open()` |
| `file_ops_vulnerable.py` | UNSAFE_FILE_HANDLING | Multiple file patterns |
| `eval_vulnerable.py` | EVAL_USAGE, HARDCODED_CREDENTIAL | eval + secrets |
| `hashing_vulnerable.py` | WEAK_HASHING_ALGORITHM | MD5 / SHA1 |
| `command_injection_vulnerable.py` | COMMAND_INJECTION_RISK | os.system, shell=True |
| `deserialization_vulnerable.py` | INSECURE_DESERIALIZATION | pickle, yaml.load |
| `randomness_vulnerable.py` | INSECURE_RANDOMNESS | random for tokens |
| `path_traversal_vulnerable.py` | PATH_TRAVERSAL, UNSAFE_FILE_HANDLING | User paths |
| `config_vulnerable.py` | HARDCODED_CREDENTIAL | Config dicts / attrs |
| `web_app_vulnerable.py` | Multiple | Mini web-app anti-patterns |
| `mixed_vulnerable.py` | Multiple | Combined demo |

---

## Safe samples (`samples/safe/`)

| File | Expected issues | Topic |
|------|-----------------|--------|
| `sql_safe.py` | 0 | Parameterized queries |
| `credentials_safe.py` | 0 | `os.environ` |
| `file_safe.py` | 0 | `with open` |
| `eval_safe.py` | 0 | `ast.literal_eval` |
| `hashing_safe.py` | 0 | bcrypt + SHA-256 |
| `command_injection_safe.py` | 0 | subprocess list args |
| `deserialization_safe.py` | 0 | json / yaml.safe_load |
| `randomness_safe.py` | 0 | secrets module |
| `path_traversal_safe.py` | 0 | Path validation |
| `mixed_safe.py` | 0 | Combined secure patterns |

---

## Configuration

| File | Description |
|------|-------------|
| `requirements.txt` (root) | click, colorama, Flask |
| `secure_checker/requirements.txt` | Same dependencies for app folder |
| `README.md` | Full project documentation |
