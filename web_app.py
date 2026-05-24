"""
web_app.py — Flask web application entry point.

Purpose:
    Provide a browser UI to scan Python code without using the CLI.

What it does:
    - Serves a single-page form (templates/index.html) on port 5001.
    - Accepts pasted source code or an uploaded .py file.
    - Runs the same CodeAnalyzer and Reporter logic as the CLI.
    - Renders scan results (risk score, findings, guidance) in the browser.

Usage:
    python web_app.py
    Then open http://127.0.0.1:5001
"""
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename

from checker.parser import CodeAnalyzer
from checker.reporter import Reporter


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024


def analyze_source(source, display_name):
    analyzer = CodeAnalyzer(display_name)
    analyzer.load_source(source, display_name)
    analyzer.run_checks()

    reporter = Reporter(analyzer.get_issues(), display_name)
    return reporter.build_report_data()


@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    error = None
    submitted_code = ""

    if request.method == "POST":
        uploaded_file = request.files.get("source_file")
        pasted_code = request.form.get("source_code", "").strip()

        try:
            if uploaded_file and uploaded_file.filename:
                filename = secure_filename(uploaded_file.filename)
                if not filename.endswith(".py"):
                    raise ValueError("Please upload a Python file ending in .py.")

                source = uploaded_file.read().decode("utf-8")
                submitted_code = source
                report = analyze_source(source, filename)
            elif pasted_code:
                submitted_code = pasted_code
                report = analyze_source(pasted_code, "pasted_code.py")
            else:
                error = "Upload a .py file or paste Python code before scanning."
        except UnicodeDecodeError:
            error = "The uploaded file could not be read as UTF-8 text."
        except SyntaxError as exc:
            error = f"Python syntax error on line {exc.lineno}: {exc.msg}"
        except ValueError as exc:
            error = str(exc)

    return render_template(
        "index.html",
        report=report,
        error=error,
        submitted_code=submitted_code
    )


if __name__ == "__main__":
    app.run(debug=True, port=5001)
