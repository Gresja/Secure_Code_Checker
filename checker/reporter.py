"""
reporter.py — Report generation and issue enrichment (Reporter).

Purpose:
    Turn raw issue lists into structured reports for CLI, JSON, HTML, and web UI.

What it does:
    - build_report_data(): severity counts, weighted risk score, risk level, enriched issues.
    - _get_dynamic_guidance(): per-issue "why this matters" and "recommended fix" from code context.
    - save_json(): write reports/report.json.
    - save_html(): write reports/report.html with styled finding cards.
"""
import json
import os
import re
from datetime import datetime
from html import escape

class Reporter:
    RULE_GUIDANCE = {
        "SQL_INJECTION_RISK": {
            "risk": "Attacker-controlled input can alter query logic and expose or modify data.",
            "fix": "Use parameterized queries and avoid building SQL with string concatenation."
        },
        "HARDCODED_CREDENTIAL": {
            "risk": "Secrets in source code can leak through repositories, logs, and backups.",
            "fix": "Move credentials to environment variables or a dedicated secrets manager."
        },
        "UNSAFE_FILE_HANDLING": {
            "risk": "Files may remain open and exceptions can cause unstable behavior.",
            "fix": "Use context managers (`with open(...)`) and handle expected exceptions."
        },
        "EVAL_USAGE": {
            "risk": "Untrusted data passed to eval can lead to arbitrary code execution.",
            "fix": "Use safer alternatives like `ast.literal_eval` or strict parsers."
        },
        "WEAK_HASHING_ALGORITHM": {
            "risk": "Weak hashes are vulnerable to collision attacks and should not protect sensitive data.",
            "fix": "Use stronger algorithms such as SHA-256/SHA-3, or password hashing libraries (bcrypt/argon2)."
        },
        "COMMAND_INJECTION_RISK": {
            "risk": "Shell commands can execute attacker-controlled input on the host system.",
            "fix": "Avoid shell=True and pass command arguments as a list after strict validation."
        },
        "INSECURE_DESERIALIZATION": {
            "risk": "Deserializing untrusted data can execute arbitrary code during the load process.",
            "fix": "Use safe formats like JSON for untrusted data, or yaml.safe_load() instead of yaml.load()."
        },
        "INSECURE_RANDOMNESS": {
            "risk": "The random module is not cryptographically secure and its output can be predicted by attackers.",
            "fix": "Use the 'secrets' module for tokens, keys, and session IDs (e.g. secrets.token_hex(32))."
        },
        "PATH_TRAVERSAL": {
            "risk": "User-controlled paths can escape the intended directory using sequences like '../../'.",
            "fix": "Sanitize with os.path.basename(), resolve the full path, and verify it starts with the allowed base directory."
        }
    }

    def __init__(self, issues, filepath):
        self.issues = issues
        self.filepath = filepath
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        os.makedirs("reports", exist_ok=True)

    def _severity_counts(self):
        severities = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        return {level: sum(1 for issue in self.issues if issue.get("severity") == level) for level in severities}

    def _severity_score(self, counts):
        weights = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1}
        return sum(counts[level] * weights[level] for level in weights)

    def _risk_level(self, score):
        if score >= 30:
            return "CRITICAL"
        if score >= 18:
            return "HIGH"
        if score >= 8:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "NONE"

    def _sorted_issues(self):
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return sorted(
            self.issues,
            key=lambda issue: (
                severity_order.get(issue.get("severity", "LOW"), 4),
                issue.get("line", 0)
            )
        )

    def _get_dynamic_guidance(self, issue):
        rule = issue.get("rule", "")
        code = (issue.get("code") or "").strip()
        description = (issue.get("description") or "").strip()
        guidance = self.RULE_GUIDANCE.get(
            rule,
            {
                "risk": "This pattern can increase security risk if not reviewed carefully.",
                "fix": "Review this finding and apply secure coding practices."
            }
        ).copy()

        if rule == "SQL_INJECTION_RISK":
            user_input_hint = "input(" in code or "request." in code or ".args" in code
            if user_input_hint:
                guidance["risk"] = (
                    "This query appears to include user-controlled input. "
                    "Attackers can inject SQL to bypass checks or extract data."
                )
            if "%" in code or ".format(" in code or "f\"" in code or "f'" in code:
                guidance["fix"] = (
                    "Replace string interpolation with placeholders and pass values separately "
                    "(for example: execute('SELECT ... WHERE id = %s', (user_id,)))."
                )

        elif rule == "HARDCODED_CREDENTIAL":
            variable_match = re.search(r"variable '([^']+)'", description)
            variable_name = variable_match.group(1) if variable_match else "credential variable"
            looks_token = any(token in variable_name.lower() for token in ("token", "api", "key", "secret"))
            if looks_token:
                guidance["risk"] = (
                    f"'{variable_name}' looks like an API secret. If leaked, it can allow unauthorized service access."
                )
                guidance["fix"] = (
                    f"Load '{variable_name}' from environment variables and rotate the current secret if it was committed."
                )
            else:
                guidance["risk"] = (
                    f"'{variable_name}' is hardcoded in source. Anyone with code access can reuse this credential."
                )

        elif rule == "UNSAFE_FILE_HANDLING":
            write_mode = any(mode in code for mode in ("'w'", "\"w\"", "'a'", "\"a\""))
            if write_mode:
                guidance["risk"] = (
                    "This write operation can fail mid-execution and leave partial data if errors are not handled."
                )
            if "encoding=" not in code:
                guidance["fix"] = (
                    "Use `with open(path, mode, encoding='utf-8') as f:` and wrap risky operations in try/except "
                    "to handle filesystem and permission errors."
                )

        elif rule == "EVAL_USAGE":
            if "input(" in code:
                guidance["risk"] = (
                    "Directly evaluating `input()` allows arbitrary code execution from user-provided text."
                )
            if "[" in code or "{" in code:
                guidance["fix"] = (
                    "If you only parse literals (lists/dicts/numbers), replace `eval` with `ast.literal_eval`."
                )

        elif rule == "WEAK_HASHING_ALGORITHM":
            algo = "SHA1" if "sha1" in code.lower() or "sha-1" in code.lower() else "MD5"
            guidance["risk"] = (
                f"{algo} is cryptographically weak and can be abused via collisions in integrity checks."
            )
            if "password" in code.lower() or "passwd" in code.lower():
                guidance["fix"] = (
                    "For passwords, use `bcrypt` or `argon2` (not general-purpose hashes). "
                    "For file/message integrity, prefer `hashlib.sha256`."
                )

        elif rule == "INSECURE_DESERIALIZATION":
            if "pickle" in code:
                guidance["risk"] = (
                    "pickle can execute arbitrary Python code when loading malicious data — "
                    "even from seemingly trusted sources."
                )
                guidance["fix"] = (
                    "Replace pickle with JSON (json.dumps/loads) for data exchange. "
                    "If pickle is necessary, only load data you generated yourself."
                )
            elif "yaml" in code:
                guidance["risk"] = (
                    "yaml.load() without SafeLoader can instantiate arbitrary Python objects "
                    "embedded in the YAML document."
                )
                guidance["fix"] = (
                    "Replace yaml.load(data, Loader=...) with yaml.safe_load(data) "
                    "which only allows simple types."
                )

        elif rule == "INSECURE_RANDOMNESS":
            if "token" in code or "session" in code or "key" in code:
                guidance["risk"] = (
                    "A predictable random value used as a token or key can be forged by an attacker."
                )
            guidance["fix"] = (
                "Use secrets.token_hex(32) for hex tokens, secrets.token_urlsafe(32) for "
                "URL-safe tokens, or secrets.choice() for random selections."
            )

        elif rule == "PATH_TRAVERSAL":
            if "input(" in code:
                guidance["risk"] = (
                    "Direct CLI input used in a file path lets anyone run the script with "
                    "'../../etc/passwd' to read arbitrary files."
                )
            guidance["fix"] = (
                "Use base = Path('/safe/dir').resolve() and verify the resolved path "
                "starts with base before opening any file."
            )

        elif rule == "COMMAND_INJECTION_RISK":
            if "shell=True" in code:
                guidance["risk"] = (
                    "`shell=True` runs the command through a shell, so special characters in input can become commands."
                )
                guidance["fix"] = (
                    "Use `subprocess.run([...], shell=False, check=True)` with a fixed command list and validated arguments."
                )
            elif "os.system" in code:
                guidance["risk"] = (
                    "`os.system` executes a shell command directly and is dangerous with dynamic values."
                )

        return guidance

    def _enriched_issues(self):
        enriched = []
        for issue in self._sorted_issues():
            guidance = self._get_dynamic_guidance(issue)
            enriched_issue = dict(issue)
            enriched_issue["why_this_matters"] = guidance["risk"]
            enriched_issue["recommended_fix"] = guidance["fix"]
            enriched.append(enriched_issue)
        return enriched

    def build_report_data(self):
        """Return a reusable report object for JSON, HTML, and web views."""
        counts = self._severity_counts()
        score = self._severity_score(counts)
        return {
            "file": self.filepath,
            "timestamp": self.timestamp,
            "total_issues": len(self.issues),
            "severity_summary": counts,
            "risk_score": score,
            "risk_level": self._risk_level(score),
            "issues": self._enriched_issues()
        }

    def save_json(self):
        """Save issues as a structured JSON report."""
        report = self.build_report_data()
        out_path = "reports/report.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"  JSON report saved to {out_path}")

    def save_html(self):
        """Save issues as a formatted HTML report."""
        severity_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#16a34a",
            "NONE": "#475569"
        }
        report = self.build_report_data()
        sorted_issues = report["issues"]
        counts = report["severity_summary"]
        score = report["risk_score"]
        risk_level = report["risk_level"]
        risk_color = severity_colors.get(risk_level, "#475569")

        cards = ""
        for index, issue in enumerate(sorted_issues, start=1):
            severity = issue.get("severity", "LOW")
            rule = issue.get("rule", "UNKNOWN_RULE")
            cards += f"""
            <article class="issue-card">
                <div class="issue-header">
                    <div class="issue-title-wrap">
                        <div class="issue-id">Issue #{index:02d}</div>
                        <h3>{escape(rule)}</h3>
                    </div>
                    <span class="severity-badge" style="background:{severity_colors.get(severity, '#475569')};">{escape(severity)}</span>
                </div>
                <p class="issue-meta"><strong>Line:</strong> {issue.get('line', 'N/A')} | <strong>File:</strong> {escape(issue.get('file', self.filepath))}</p>
                <p class="issue-description">{escape(issue.get('description', 'No description provided.'))}</p>
                <div class="issue-grid">
                    <div>
                        <h4>Why this matters</h4>
                        <p>{escape(issue.get('why_this_matters', 'This pattern can increase security risk if not reviewed carefully.'))}</p>
                    </div>
                    <div>
                        <h4>Recommended fix</h4>
                        <p>{escape(issue.get('recommended_fix', 'Review this finding and apply secure coding practices.'))}</p>
                    </div>
                </div>
                <div class="code-block">
                    <span>Code context</span>
                    <code>{escape(issue.get('code', '') or '(Source snippet unavailable)')}</code>
                </div>
            </article>
            """

        if not sorted_issues:
            cards = """
            <div class="no-issues">
                <h3>No security issues found</h3>
                <p>The scan did not detect insecure patterns in this file.</p>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        :root {{
            --bg: #f3f6fb;
            --card: #ffffff;
            --text: #0f172a;
            --muted: #475569;
            --border: #dbe3ee;
            --primary: #1d4ed8;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            padding: 32px;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            color: var(--text);
            background: radial-gradient(circle at top right, #e8efff, var(--bg));
            line-height: 1.45;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .hero {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 22px 24px;
            box-shadow: 0 10px 24px rgba(29, 78, 216, 0.08);
            margin-bottom: 20px;
        }}
        .hero h1 {{ margin: 0 0 8px 0; font-size: 1.6rem; color: #0b3aa4; }}
        .hero p {{ margin: 4px 0; color: var(--muted); }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 12px;
            margin-bottom: 20px;
        }}
        .metric {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 14px;
            box-shadow: 0 4px 10px rgba(15, 23, 42, 0.05);
        }}
        .metric .value {{ font-size: 1.4rem; font-weight: 700; }}
        .metric .label {{ color: var(--muted); font-size: 0.86rem; text-transform: uppercase; letter-spacing: .03em; }}
        .risk-chip {{
            display: inline-block;
            margin-top: 8px;
            padding: 6px 10px;
            border-radius: 20px;
            color: #fff;
            font-size: 0.85rem;
            font-weight: 700;
        }}
        .issues-title {{ margin: 18px 0 12px; font-size: 1.2rem; }}
        .issue-card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 14px;
            box-shadow: 0 6px 12px rgba(15, 23, 42, 0.05);
        }}
        .issue-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 12px;
        }}
        .issue-title-wrap h3 {{ margin: 4px 0 0 0; font-size: 1rem; }}
        .issue-id {{
            color: var(--muted);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: .04em;
        }}
        .severity-badge {{
            color: #fff;
            font-weight: 700;
            font-size: 0.78rem;
            padding: 6px 10px;
            border-radius: 999px;
            white-space: nowrap;
        }}
        .issue-meta {{ color: var(--muted); font-size: 0.9rem; margin: 8px 0 10px; }}
        .issue-description {{ margin: 0 0 12px; }}
        .issue-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 12px;
            margin-bottom: 10px;
        }}
        .issue-grid h4 {{ margin: 0 0 6px; font-size: 0.95rem; color: #0b3aa4; }}
        .issue-grid p {{ margin: 0; color: #1f2937; }}
        .code-block {{
            border: 1px solid var(--border);
            border-radius: 10px;
            background: #f8fafc;
            padding: 10px 12px;
        }}
        .code-block span {{
            display: block;
            color: var(--muted);
            font-size: 0.8rem;
            margin-bottom: 6px;
        }}
        .code-block code {{
            display: block;
            color: #0f172a;
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            word-break: break-word;
        }}
        .no-issues {{
            background: #effdf5;
            border: 1px solid #a7f3d0;
            border-radius: 12px;
            padding: 16px;
        }}
        .no-issues h3 {{ margin: 0 0 8px 0; color: #047857; }}
        .no-issues p {{ margin: 0; color: #065f46; }}
    </style>
</head>
<body>
    <div class="container">
        <section class="hero">
            <h1>Secure Coding Guidelines Report</h1>
            <p><strong>File analyzed:</strong> {escape(self.filepath)}</p>
            <p><strong>Scan time:</strong> {escape(self.timestamp)}</p>
            <span class="risk-chip" style="background:{risk_color};">Overall Risk: {risk_level} (Score: {score})</span>
        </section>

        <section class="summary">
            <div class="metric">
                <div class="value">{len(sorted_issues)}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="metric">
                <div class="value" style="color:{severity_colors['CRITICAL']};">{counts['CRITICAL']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="metric">
                <div class="value" style="color:{severity_colors['HIGH']};">{counts['HIGH']}</div>
                <div class="label">High</div>
            </div>
            <div class="metric">
                <div class="value" style="color:{severity_colors['MEDIUM']};">{counts['MEDIUM']}</div>
                <div class="label">Medium</div>
            </div>
            <div class="metric">
                <div class="value" style="color:{severity_colors['LOW']};">{counts['LOW']}</div>
                <div class="label">Low</div>
            </div>
        </section>

        <h2 class="issues-title">Detailed Findings</h2>
        {cards}
    </div>
</body>
</html>"""

        out_path = "reports/report.html"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"  HTML report saved to {out_path}")