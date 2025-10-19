import argparse
import json
import os
import sys
from colorama import init, Fore, Style

# flexible import: try package-style first, then relative
try:
    from cli_tool.utils import discover_endpoints, check_web_flaws, generate_html_report
except Exception:
    try:
        from utils import discover_endpoints, check_web_flaws, generate_html_report
    except Exception:
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        from utils import discover_endpoints, check_web_flaws, generate_html_report

# Initialize colorama
init(autoreset=True)


def print_banner():
    banner = r"""

███████╗ ██████╗ █████╗ ███╗   ██╗██████╗ ███████╗██████╗ ███████╗
██╔════╝██╔════╝██╔══██╗████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔════╝
███████╗██║     ███████║██╔██╗ ██║██║  ██║█████╗  ██████╔╝███████╗
╚════██║██║     ██╔══██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗██║
███████║╚██████╗██║  ██║██║ ╚████║██████╔╝███████╗██║  ██║███████║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝╚══════╝╚═╝  ╚═╝╚══════╝

               ========== DEVELOPED BY Cybermj ==========
    """
    print(Fore.CYAN + banner + Style.RESET_ALL)


def color_text(vuln_result: dict, vuln_type: str) -> str:
    """Return a colorized string showing status + confidence."""
    found = vuln_result.get("found", False)
    conf = vuln_result.get("confidence", 0.0)
    method = vuln_result.get("method", "")

    if not found:
        return Fore.GREEN + f"✅ Safe ({conf:.2f})" + Style.RESET_ALL

    if vuln_type.lower() in ("xss", "sqli", "sql_injection"):
        color = Fore.RED
        icon = "🟥"
    elif vuln_type.lower() in ("open_redirect", "redirect"):
        color = Fore.YELLOW
        icon = "🟨"
    else:
        color = Fore.RED
        icon = "🟥"

    return f"{color}{icon} Found! ({conf:.2f}, {method}){Style.RESET_ALL}"


def print_scan_result(result: dict):
    endpoint = result.get("endpoint", "<unknown>")
    print(Fore.MAGENTA + f"[SCANNING] → {endpoint}" + Style.RESET_ALL)

    xss = result.get("xss", {})
    sqli = result.get("sqli", {})
    redirect = result.get("open_redirect", {})

    print(f"   XSS Vulnerability:      {color_text(xss, 'xss')}")
    print(f"   SQL Injection:          {color_text(sqli, 'sqli')}")
    print(f"   Open Redirect:          {color_text(redirect, 'open_redirect')}")
    print(Fore.BLUE + "-" * 60 + Style.RESET_ALL)


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description='SCANDERE - A CLI tool for endpoint discovery and vulnerability scanning.'
    )
    parser.add_argument(
        'target', type=str,
        help='The domain or URL to scan (e.g. https://example.com)'
    )
    parser.add_argument(
        '--output', type=str, choices=['json', 'html'], default='json',
        help='Output format (json or html)'
    )
    parser.add_argument(
        '--no-discover', action='store_true',
        help='Skip endpoint discovery and treat the target as a single endpoint'
    )
    parser.add_argument(
        '--confirm', action='store_true',
        help='Enable deeper confirmation checks (boolean SQLi, higher-confidence XSS)'
    )
    parser.add_argument(
        '--time-confirm', action='store_true',
        help='Enable time-based SQLi confirmation (⚠️ intrusive, use only with permission)'
    )
    parser.add_argument(
        '--fast', action='store_true',
        help='Run in fast mode (reduced payloads and timeouts for quicker scans)'
    )

    args = parser.parse_args()

    target = args.target
    print(Fore.YELLOW + f"Starting scan for: {target}" + Style.RESET_ALL)

    # Step 1: Discover endpoints
    if args.no_discover:
        endpoints = [target]
    else:
        print(Fore.CYAN + "Discovering endpoints..." + Style.RESET_ALL)
        endpoints = discover_endpoints(target)

    print(Fore.GREEN + f"Discovered {len(endpoints)} endpoints." + Style.RESET_ALL)

    # Step 2: Run vulnerability checks
    print(Fore.CYAN + "Running web flaw checks..." + Style.RESET_ALL)
    results = check_web_flaws(
        endpoints,
        confirm=args.confirm,
        do_time_test=args.time_confirm,
        fast_mode=args.fast
    )

    # Step 3: Print colored scan results
    issues_found = 0
    for res in results:
        if (res.get("xss", {}).get("found") or
            res.get("sqli", {}).get("found") or
            res.get("open_redirect", {}).get("found")):
            issues_found += 1
        print_scan_result(res)

    summary = {
        "target": target,
        "endpoints_scanned": len(endpoints),
        "endpoints_with_issues": issues_found
    }

    print(Fore.YELLOW +
          f"Scan complete. {issues_found} endpoints with issues out of {len(endpoints)} scanned."
          + Style.RESET_ALL)

    # Step 4: Save report
    if args.output == 'json':
        out_file = "report.json"
        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump({"summary": summary, "results": results}, f, indent=4)
        print(Fore.GREEN + f"JSON report saved as {out_file}" + Style.RESET_ALL)
    else:
        out_file = "report.html"
        generate_html_report(results, out_file, summary)
        print(Fore.GREEN + f"HTML report generated at {out_file}" + Style.RESET_ALL)


if __name__ == "__main__":
    main()
