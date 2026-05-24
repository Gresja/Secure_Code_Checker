# Secure Code Checker

A static security analyzer for **Python** source code. It parses files with Python’s Abstract Syntax Tree (AST), runs a set of security rules, and reports vulnerabilities with severity, explanations, and remediation guidance—via the **command line** or a **web interface**.

---

## Table of contents

1. [Overview](#overview)
2. [Features](#features)
3. [How it works](#how-it-works)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Security rules](#security-rules)
7. [Reports](#reports)
8. [Project structure (every file)](#project-structure-every-file)
9. [Sample files](#sample-files)
10. [Limitations](#limitations)

---

## Overview

Secure Code Checker helps developers and students find common insecure coding patterns before code is deployed. It does **not** execute the scanned code; analysis is read-only and based on AST pattern matching.

**Main goals:**

- Detect common Python security anti-patterns automatically  
- Classify findings by severity (Critical, High, Medium, Low)  
- Provide context-aware “why it matters” and “how to fix” guidance  
- Support terminal output, JSON/HTML reports, and a browser UI  

---

## Features

- **9 security rule categories** (SQL injection, credentials, files, eval, hashing, command injection, deserialization, randomness, path traversal)  
- **CLI** with colored terminal output and optional `--verbose` mode  
- **Web app** to paste code or upload `.py` files  
- **JSON and HTML reports** with risk score and severity summary  
- **Modular rules**—each check is a separate AST visitor class  
- **Sample library** of vulnerable and safe example files for testing and demos  

---

## How it works

```
User input (file path / paste / upload)
        │
        ▼
   main.py  or  web_app.py
        │
        ▼
   checker/parser.py  →  CodeAnalyzer
        │                  • load_file() / load_source()
        │                  • ast.parse()
        │                  • run_checks() → each rule visits AST
        ▼
   checker/rules/*.py  →  issue callbacks
        │
        ▼
   checker/reporter.py  →  enrich + score + format
        │
        ├── Terminal (main.py)
        ├── reports/report.json
        ├── reports/report.html
        └── Browser (templates/index.html)
```

Each rule extends `ast.NodeVisitor` and calls `add_issue()` when it finds a matching pattern. The reporter adds dynamic guidance and computes an overall risk level from weighted severity counts.

---

## Installation

From the repository root (recommended: use a virtual environment):

```bash
cd /path/to/Secure_Code_Checker
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Dependencies: **Click**, **colorama**, **Flask** (see root `requirements.txt`).

All commands below assume your working directory is **`secure_checker/`**:

```bash
cd secure_checker
```

---

## Usage

### Command line (CLI)

```bash
python main.py <path-to-file.py> [options]
```

| Option | Description |
|--------|-------------|
| `--verbose` / `-v` | Show file path for each issue |
| `--output html` / `-o html` | Save `reports/report.html` |
| `--output json` | Save `reports/report.json` |
| `--output both` | Save both reports |

**Examples:**

```bash
python main.py samples/sql_vulnerable.py
python main.py samples/mixed_vulnerable.py --verbose
python main.py samples/hashing_vulnerable.py --output both
python main.py samples/safe/sql_safe.py          # should report 0 issues
```

### Web interface

```bash
python web_app.py
```

Open in your browser:

```
http://127.0.0.1:5001
```

Use **Paste Code** or **Upload File** (.py only), then **Scan Code**. Results appear on the same page. Use **Clear** to reset the form.

> **Note:** Port `5001` is used because macOS often blocks port `5000`. Keep the terminal running while you use the web UI.

---

## Security rules

| Rule ID | Severity (typical) | What it detects |
|---------|-------------------|-----------------|
| `SQL_INJECTION_RISK` | High | SQL built with `+`, f-strings, `%`, or `.format()` |
| `HARDCODED_CREDENTIAL` | Critical | Secrets in variables, attributes, or dict keys |
| `UNSAFE_FILE_HANDLING` | Medium | `open()` not inside `with` or `try` |
| `EVAL_USAGE` | Critical | Calls to `eval()` |
| `WEAK_HASHING_ALGORITHM` | High | `hashlib.md5`, `sha1`, or `hashlib.new('md5'/'sha1')` |
| `COMMAND_INJECTION_RISK` | Critical | `os.system` / `os.popen` / `subprocess` with `shell=True` |
| `INSECURE_DESERIALIZATION` | Critical / High | `pickle.loads` / `yaml.load` without safe loader |
| `INSECURE_RANDOMNESS` | High | `random.*` for security-sensitive values |
| `PATH_TRAVERSAL` | High | User input used in file paths (`open`, `os.*`, joins) |

---

## Reports

When you use `--output`, files are written relative to your **current working directory**:

| File | Description |
|------|-------------|
| `reports/report.html` | Visual report: summary metrics, risk chip, per-issue cards |
| `reports/report.json` | Machine-readable: timestamps, severity summary, risk score, issues array |

Each scan **overwrites** the previous report files. Open HTML in any browser; use JSON for scripts or further processing.

---

## Project structure (every file)

### Repository root (`Secure_Code_Checker/`)

| File | Description |
|------|-------------|
| `requirements.txt` | Python dependencies for the project (`click`, `colorama`, `Flask`). Install with `pip install -r requirements.txt`. |
| `venv/` | Local virtual environment (optional; not part of source logic). |

---

### Application root (`secure_checker/`)

| File | Description |
|------|-------------|
| `README.md` | This documentation file. |
| `requirements.txt` | Duplicate/alternate dependency list for the `secure_checker` package folder (same packages as root). |
| `main.py` | **CLI entry point.** Uses Click to accept a file path, runs `CodeAnalyzer`, prints colored findings and summary counts, optionally calls `Reporter` for JSON/HTML. |
| `web_app.py` | **Flask web entry point.** Serves the scan UI on port `5001`, accepts pasted code or uploaded `.py` files, returns HTML results via `templates/index.html`. |
| `reports/report.html` | Generated HTML report (created when you use `--output html` or `both`; not hand-edited). |
| `reports/report.json` | Generated JSON report (created when you use `--output json` or `both`). |

---

### Core package (`checker/`)

| File | Description |
|------|-------------|
| `checker/__init__.py` | Marks `checker` as a Python package (may be empty). |
| `checker/parser.py` | **`CodeAnalyzer` class.** Loads source from disk or string, parses AST, registers all rule visitors, collects issues via `add_issue()`, attaches line snippets to each finding. |
| `checker/reporter.py` | **`Reporter` class.** Builds report data (severity counts, risk score, risk level), adds per-issue `why_this_matters` and `recommended_fix`, writes `reports/report.json` and `reports/report.html`. |

---

### Security rules (`checker/rules/`)

| File | Description |
|------|-------------|
| `checker/rules/__init__.py` | Exports all checker classes so `parser.py` can import them in one place. |
| `checker/rules/sql_injection.py` | **`SQLInjectionChecker`** — flags SQL string building via concatenation, f-strings, `%` formatting, and `.format()`. |
| `checker/rules/hardcoded_credentials.py` | **`HardcodedCredentialsChecker`** — flags string literals assigned to sensitive names or dict keys; optional secret-shaped values in dicts. |
| `checker/rules/unsafe_file.py` | **`UnsafeFileHandlingChecker`** — flags `open()` calls outside `with` or `try` blocks. |
| `checker/rules/eval_usage.py` | **`EvalUsageChecker`** — flags any `eval()` call. |
| `checker/rules/weak_hashing.py` | **`WeakHashingChecker`** — flags `hashlib.md5`, `hashlib.sha1`, and weak `hashlib.new(...)`. |
| `checker/rules/command_injection.py` | **`CommandInjectionChecker`** — flags `os.system`, `os.popen`, and `subprocess.*` with `shell=True`. |
| `checker/rules/insecure_deserialization.py` | **`InsecureDeserializationChecker`** — flags `pickle.loads`/`load` and unsafe `yaml.load` (allows `yaml.safe_load` / SafeLoader). |
| `checker/rules/insecure_randomness.py` | **`InsecureRandomnessChecker`** — flags `random` module usage for security-sensitive values. |
| `checker/rules/path_traversal.py` | **`PathTraversalChecker`** — tracks variables tainted by `input()` / request-like sources; flags path sinks (`open`, `os.remove`, `os.path.join`, etc.). |

---

### Web UI (`templates/`)

| File | Description |
|------|-------------|
| `templates/index.html` | Single-page UI: dark theme, paste/upload tabs, scan and clear buttons, summary metrics, and detailed finding cards (used by `web_app.py`). |

---

### Vulnerable samples (`samples/`)

Intentionally insecure code for testing and demonstrations. **Do not use in production.**

| File | Description |
|------|-------------|
| `samples/sql_vulnerable.py` | SQL injection via string concatenation. |
| `samples/credentials_vulnerable.py` | Hardcoded passwords, API keys, and tokens. |
| `samples/file_vulnerable.py` | Basic `open()` without context managers. |
| `samples/file_ops_vulnerable.py` | Multiple unsafe read/write/append patterns. |
| `samples/eval_vulnerable.py` | `eval()` plus embedded hardcoded credentials (multi-rule demo). |
| `samples/hashing_vulnerable.py` | MD5, SHA1, and `hashlib.new('md5')`. |
| `samples/command_injection_vulnerable.py` | `os.system`, `os.popen`, `subprocess` with `shell=True`. |
| `samples/deserialization_vulnerable.py` | `pickle` and unsafe `yaml.load` examples. |
| `samples/randomness_vulnerable.py` | `random` used for sessions, tokens, API keys, OTPs. |
| `samples/path_traversal_vulnerable.py` | User input in paths (`input()`, joins, `open`). |
| `samples/config_vulnerable.py` | Secrets at module level, in dicts, and on class attributes. |
| `samples/web_app_vulnerable.py` | Web-style patterns: SQL, credentials, weak hash, eval. |
| `samples/mixed_vulnerable.py` | Several vulnerability types in one script. |

---

### Safe samples (`samples/safe/`)

Secure alternatives; the scanner should report **0 issues** for these when run as-is.

| File | Description |
|------|-------------|
| `samples/safe/sql_safe.py` | Parameterized SQL with `?` placeholders. |
| `samples/safe/credentials_safe.py` | Secrets from `os.environ`. |
| `samples/safe/file_safe.py` | `with open(...)` and exception handling. |
| `samples/safe/eval_safe.py` | `ast.literal_eval` instead of `eval`. |
| `samples/safe/hashing_safe.py` | `bcrypt` for passwords, `sha256` for checksums. |
| `samples/safe/command_injection_safe.py` | `subprocess` with argument lists, no shell. |
| `samples/safe/deserialization_safe.py` | `json.loads` and `yaml.safe_load`. |
| `samples/safe/randomness_safe.py` | `secrets` module for tokens and IDs. |
| `samples/safe/path_traversal_safe.py` | `basename` + resolved path under a base directory. |
| `samples/safe/mixed_safe.py` | Combined secure patterns (clean multi-rule demo). |

---

## Sample files

**Compare vulnerable vs safe:**

```bash
python main.py samples/sql_vulnerable.py --output both
python main.py samples/safe/sql_safe.py
```

Use pairs with the same topic (e.g. `hashing_vulnerable.py` vs `safe/hashing_safe.py`) in reports or the web UI to show what the tool catches and what clean code looks like.

---

## Limitations

- **Python only** — scans a single `.py` file per run (no multi-file or directory scan in CLI/web by default).  
- **Static/heuristic** — pattern-based AST rules; false positives and false negatives are possible.  
- **Not a full SAST product** — suitable for education, demos, and lightweight local checks, not a replacement for enterprise security scanners.  
- **Reports path** — `reports/` is created relative to the directory from which you run the command.  

---

## Quick reference

| Task | Command |
|------|---------|
| Scan file (terminal) | `python main.py samples/mixed_vulnerable.py` |
| Save HTML + JSON | `python main.py samples/mixed_vulnerable.py -o both` |
| Open reports | `reports/report.html`, `reports/report.json` |
| Start web UI | `python web_app.py` → `http://127.0.0.1:5001` |

---

## License / academic use

If this project is part of a course or thesis, cite the purpose (static Python security analysis), the rule set, and the dual CLI/web interfaces. Sample files under `samples/` are provided for testing only.
