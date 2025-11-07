#!/usr/bin/env python3
"""
HTTP Parameter Pollution (HPP) Scanner
Tests for HTTP parameter pollution vulnerabilities
"""

import requests
import json
import urllib.parse
from datetime import datetime
from bs4 import BeautifulSoup

class ParameterPollutionScanner:
    """HTTP parameter pollution vulnerability scanner"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def scan(self):
        """Run HPP scan"""
        print(f"[*] Starting HTTP parameter pollution scan on {self.target_url}")

        # Test GET parameters
        self._test_get_parameters()

        # Test POST parameters
        self._test_post_parameters()

        # Test header pollution
        self._test_header_pollution()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_get_parameters(self):
        """Test GET parameters for HPP"""
        print("[*] Testing GET parameter pollution...")

        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            # Try common parameters
            params = {
                'id': ['1'],
                'user': ['test'],
                'page': ['1'],
                'action': ['view'],
                'redirect': ['index'],
            }

        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Get baseline response
        try:
            baseline = self.session.get(self.target_url, timeout=10)
        except:
            baseline = None

        for param_name, param_value in params.items():
            original_value = param_value[0] if param_value else 'test'

            # Test case 1: Duplicate parameter with different values
            test_cases = [
                # Same parameter twice
                f"{param_name}={original_value}&{param_name}=injected",
                f"{param_name}=injected&{param_name}={original_value}",

                # Parameter pollution with admin/privileged values
                f"{param_name}={original_value}&{param_name}=admin",
                f"{param_name}={original_value}&{param_name}=1",
                f"{param_name}={original_value}&{param_name}=true",

                # Multiple duplicates
                f"{param_name}={original_value}&{param_name}=value1&{param_name}=value2",

                # Pollution with special values
                f"{param_name}={original_value}&{param_name}=",
                f"{param_name}={original_value}&{param_name}=null",
            ]

            for test_query in test_cases:
                test_url = f"{base_url}?{test_query}"

                try:
                    response = self.session.get(test_url, timeout=10, allow_redirects=False)

                    # Check for HPP vulnerability
                    if self._check_hpp_vuln(response, param_name, test_query, baseline, 'GET'):
                        return

                except Exception as e:
                    pass

    def _test_post_parameters(self):
        """Test POST parameters for HPP"""
        print("[*] Testing POST parameter pollution...")

        # Try to find forms
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            if not forms:
                return

            for form in forms[:3]:
                inputs = form.find_all('input')
                form_data = {}

                for inp in inputs:
                    name = inp.get('name')
                    if name and inp.get('type') != 'submit':
                        form_data[name] = 'test'

                if not form_data:
                    continue

                # Get form action
                action = form.get('action', '')
                method = form.get('method', 'get').lower()

                if method != 'post':
                    continue

                if action:
                    if action.startswith('http'):
                        form_url = action
                    else:
                        parsed = urllib.parse.urlparse(self.target_url)
                        form_url = f"{parsed.scheme}://{parsed.netloc}{action}"
                else:
                    form_url = self.target_url

                # Get baseline
                try:
                    baseline = self.session.post(form_url, data=form_data, timeout=10)
                except:
                    baseline = None

                # Test HPP on each parameter
                for param_name in form_data.keys():
                    # Create polluted POST data
                    polluted_data = []
                    for key, value in form_data.items():
                        if key == param_name:
                            # Duplicate this parameter
                            polluted_data.append((key, value))
                            polluted_data.append((key, 'injected'))
                        else:
                            polluted_data.append((key, value))

                    try:
                        response = self.session.post(
                            form_url,
                            data=polluted_data,
                            timeout=10,
                            allow_redirects=False
                        )

                        if self._check_hpp_vuln(response, param_name, str(polluted_data), baseline, 'POST'):
                            return

                    except Exception as e:
                        pass

        except Exception as e:
            pass

    def _test_header_pollution(self):
        """Test header pollution"""
        print("[*] Testing header pollution...")

        # Headers that might be vulnerable to pollution
        test_headers = [
            'X-Forwarded-For',
            'X-Forwarded-Host',
            'Cookie',
            'Referer',
        ]

        # Get baseline
        try:
            baseline = self.session.get(self.target_url, timeout=10)
        except:
            baseline = None

        for header_name in test_headers:
            # Test duplicate headers with different values
            polluted_headers = {
                'User-Agent': 'Mozilla/5.0',
            }

            # Requests library doesn't support duplicate headers directly
            # But we can test header injection via comma-separated values
            test_values = [
                '127.0.0.1,injected.com',
                'value1, value2',
                'admin,user',
            ]

            for test_value in test_values:
                polluted_headers[header_name] = test_value

                try:
                    response = self.session.get(
                        self.target_url,
                        headers=polluted_headers,
                        timeout=10
                    )

                    # Check if pollution worked
                    if 'injected' in response.text or 'value2' in response.text:
                        vuln = {
                            'type': 'HTTP Header Pollution',
                            'severity': 'medium',
                            'url': self.target_url,
                            'header': header_name,
                            'payload': test_value,
                            'evidence': 'Polluted header value reflected in response',
                            'cwe': 'CWE-444',
                            'impact': 'Request smuggling, cache poisoning, authentication bypass'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Header pollution found in {header_name}")
                        return

                except Exception as e:
                    pass

    def _check_hpp_vuln(self, response, param_name, payload, baseline, method):
        """Check for HPP vulnerability"""

        # Check if injected value appears in response
        if 'injected' in response.text:
            vuln = {
                'type': 'HTTP Parameter Pollution',
                'severity': 'medium',
                'url': self.target_url,
                'parameter': param_name,
                'method': method,
                'payload': payload,
                'evidence': 'Injected parameter value reflected in response',
                'cwe': 'CWE-444',
                'description': 'Server processes multiple instances of same parameter',
                'impact': 'WAF bypass, authentication bypass, XSS, injection attacks'
            }
            self.vulnerabilities.append(vuln)
            print(f"[!] HPP found in parameter: {param_name}")
            return True

        # Check for privilege escalation (admin value accepted)
        if baseline:
            # Check if response differs significantly
            if 'admin' in response.text.lower() and 'admin' not in baseline.text.lower():
                vuln = {
                    'type': 'HTTP Parameter Pollution (Privilege Escalation)',
                    'severity': 'high',
                    'url': self.target_url,
                    'parameter': param_name,
                    'method': method,
                    'payload': payload,
                    'evidence': 'Admin context accessible via parameter pollution',
                    'cwe': 'CWE-444',
                    'description': 'Parameter pollution leads to privilege escalation',
                    'impact': 'Unauthorized access, privilege escalation'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] HPP privilege escalation in: {param_name}")
                return True

            # Check for WAF bypass (status code change)
            if baseline.status_code == 403 and response.status_code == 200:
                vuln = {
                    'type': 'HTTP Parameter Pollution (WAF Bypass)',
                    'severity': 'high',
                    'url': self.target_url,
                    'parameter': param_name,
                    'method': method,
                    'payload': payload,
                    'evidence': f'Status changed from {baseline.status_code} to {response.status_code}',
                    'cwe': 'CWE-444',
                    'description': 'Parameter pollution bypasses WAF/security controls',
                    'impact': 'WAF bypass, access to blocked resources'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] HPP WAF bypass via: {param_name}")
                return True

        # Check for parameter precedence issues
        if response.status_code in [301, 302]:
            location = response.headers.get('Location', '')
            if 'injected' in location or 'admin' in location:
                vuln = {
                    'type': 'HTTP Parameter Pollution (Redirect)',
                    'severity': 'medium',
                    'url': self.target_url,
                    'parameter': param_name,
                    'method': method,
                    'payload': payload,
                    'evidence': f'Redirect to: {location}',
                    'cwe': 'CWE-444',
                    'description': 'Parameter pollution affects redirect logic',
                    'impact': 'Open redirect, parameter manipulation'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] HPP redirect vulnerability in: {param_name}")
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
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high'),
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'medium')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 parameter_pollution.py <url>")
        print("\nExample:")
        print("  python3 parameter_pollution.py https://example.com/page?id=1")
        print("\nTests for:")
        print("  - GET parameter pollution")
        print("  - POST parameter pollution")
        print("  - Header pollution")
        print("  - WAF bypass via HPP")
        print("  - Privilege escalation via HPP")
        sys.exit(1)

    scanner = ParameterPollutionScanner(sys.argv[1])
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")

    if len(results['vulnerabilities']) > 0:
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
        print(f"    Medium: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'medium')}")
