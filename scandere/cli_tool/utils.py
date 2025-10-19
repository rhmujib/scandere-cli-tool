import requests
from bs4 import BeautifulSoup

def example_util_function(param):
    """An example utility function that processes input."""
    return f"Processed: {param}"

def discover_endpoints(domain):
    """Discover endpoints for the given domain."""
    try:
        response = requests.get(domain)
        soup = BeautifulSoup(response.text, 'html.parser')
        endpoints = [a['href'] for a in soup.find_all('a', href=True)]
        return endpoints
    except Exception as e:
        print(f"Error discovering endpoints: {e}")
        return []

def check_web_flaws(endpoints):
    """Run safe checks for common web flaws (XSS, SQLi, open-redirects)."""
    xss_payload = "<script>alert('XSS')</script>"
    sqli_payload = "' OR '1'='1"
    open_redirect_payload = "https://evil.com"

    results = []
    for endpoint in endpoints:
        result = {
            'endpoint': endpoint,
            'xss': False,
            'sqli': False,
            'open_redirect': False
        }

        # Check for XSS
        try:
            response = requests.get(endpoint, params={'q': xss_payload})
            if xss_payload in response.text:
                result['xss'] = True
        except Exception as e:
            print(f"Error checking XSS for {endpoint}: {e}")

        # Check for SQL Injection
        try:
            response = requests.get(endpoint, params={'q': sqli_payload})
            if "syntax error" in response.text.lower() or "sql" in response.text.lower():
                result['sqli'] = True
        except Exception as e:
            print(f"Error checking SQLi for {endpoint}: {e}")

        # Check for Open Redirect
        try:
            response = requests.get(endpoint, params={'redirect': open_redirect_payload}, allow_redirects=False)
            if response.status_code in [301, 302] and "evil.com" in response.headers.get('Location', ''):
                result['open_redirect'] = True
        except Exception as e:
            print(f"Error checking open redirect for {endpoint}: {e}")

        results.append(result)
    return results

def generate_html_report(results, filename):
    """Generate an HTML report from the scan results."""
    html_content = "<html><head><title>Scan Report</title></head><body>"
    html_content += "<h1>Scan Report</h1><table border='1'>"
    html_content += "<tr><th>Endpoint</th><th>XSS</th><th>SQLi</th><th>Open Redirect</th></tr>"
    for result in results:
        html_content += f"<tr><td>{result['endpoint']}</td><td>{result['xss']}</td><td>{result['sqli']}</td><td>{result['open_redirect']}</td></tr>"
    html_content += "</table></body></html>"
    with open(filename, 'w') as f:
        f.write(html_content)