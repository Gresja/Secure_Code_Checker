"""
main.py — Command-line interface (CLI) entry point.

Purpose:
    Run security scans on a single Python file from the terminal.

What it does:
    - Accepts a file path and optional flags (--verbose, --output).
    - Uses CodeAnalyzer to parse the file and run all security rules.
    - Prints colored findings and a severity summary to the terminal.
    - Optionally saves JSON and/or HTML reports via Reporter.

Usage:
    python main.py <file.py> [--verbose] [--output json|html|both]
"""
import click
from colorama import Fore, Style, init
from checker.parser import CodeAnalyzer
from checker.reporter import Reporter

init(autoreset=True)

SEVERITY_COLORS = {
    "CRITICAL": Fore.RED,
    "HIGH":     Fore.YELLOW,
    "MEDIUM":   Fore.CYAN,
    "LOW":      Fore.GREEN
}

@click.command()
@click.argument("filepath")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output for each issue.")
@click.option("--output", "-o", type=click.Choice(["json", "html", "both"]), default=None,
              help="Save a report to the reports/ folder.")
def main(filepath, verbose, output):
    """Secure Coding Guidelines Checker — scan Python files for insecure practices."""

    print(Fore.CYAN + "=" * 55)
    print(Fore.CYAN + "   Secure Coding Guidelines Checker")
    print(Fore.CYAN + "=" * 55)

    analyzer = CodeAnalyzer(filepath)

    try:
        analyzer.load_file()
        analyzer.run_checks()
        issues = analyzer.get_issues()

        if not issues:
            print(Fore.GREEN + "\n✔ No issues found. Code looks clean!")
        else:
            print(Fore.RED + f"\n✘ Found {len(issues)} issue(s) in '{filepath}':\n")

            for issue in issues:
                color = SEVERITY_COLORS.get(issue["severity"], Fore.WHITE)
                print(color + f"  [{issue['severity']}] {issue['rule']}")
                print(f"  Line {issue['line']}: {issue['description']}")

                if verbose:
                    print(Fore.WHITE + f"  File: {issue['file']}")

                print()

        # Summary counts
        if issues:
            critical = sum(1 for i in issues if i["severity"] == "CRITICAL")
            high     = sum(1 for i in issues if i["severity"] == "HIGH")
            medium   = sum(1 for i in issues if i["severity"] == "MEDIUM")
            print(Fore.WHITE + "  Summary:")
            print(Fore.RED    + f"    CRITICAL : {critical}")
            print(Fore.YELLOW + f"    HIGH     : {high}")
            print(Fore.CYAN   + f"    MEDIUM   : {medium}")

        # Save reports if requested
        if output:
            print()
            reporter = Reporter(issues, filepath)
            if output in ("json", "both"):
                reporter.save_json()
            if output in ("html", "both"):
                reporter.save_html()

    except (FileNotFoundError, SyntaxError):
        print(Fore.RED + "✘ Could not analyze file. Check the path and try again.")

    print(Fore.CYAN + "\n" + "=" * 55)

if __name__ == "__main__":
    main()