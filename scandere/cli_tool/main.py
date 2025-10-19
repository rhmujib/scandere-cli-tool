import argparse
import json
from utils import discover_endpoints, check_web_flaws, generate_html_report



def print_banner():
    banner = r"""
    
    
███████╗ ██████╗ █████╗ ███╗   ██╗██████╗ ███████╗██████╗ ███████╗
██╔════╝██╔════╝██╔══██╗████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔════╝
███████╗██║     ███████║██╔██╗ ██║██║  ██║█████╗  ██████╔╝███████╗
╚════██║██║     ██╔══██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗██║
███████║╚██████╗██║  ██║██║ ╚████║██████╔╝███████╗██║  ██║███████║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝
    
            ==========DEVELOPED BY Cybermj==========
    """
    print(banner)

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description='A CLI tool for endpoint discovery and web flaw checks.'
    )
    parser.add_argument(
        'target', type=str, help='The domain or IP address to scan'
    )
    parser.add_argument(
        '--output', type=str, choices=['json', 'html'], default='json',
        help='Output format (json or html)'
    )

    args = parser.parse_args()

    print(f"Scanning target: {args.target}")
    endpoints = discover_endpoints(args.target)
    print(f"Discovered endpoints: {endpoints}")

    results = check_web_flaws(endpoints)
    print(f"Scan results: {results}")

    if args.output == 'json':
        with open('report.json', 'w') as f:
            json.dump(results, f, indent=4)
        print("Report saved as report.json")
    elif args.output == 'html':
        generate_html_report(results, 'report.html')

if __name__ == "__main__":
    main()