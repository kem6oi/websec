#!/usr/bin/env python3
"""
Security Headers and Configuration Checker
Tests for missing security headers, cookie security, clickjacking, and other misconfigurations
"""

import requests
import json
from datetime import datetime

class SecurityChecker:
    """Comprehensive security configuration checker"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def scan(self):
        """Run comprehensive security scan"""
        print(f"[*] Starting security configuration scan on {self.target_url}")

        try:
            response = self.session.get(self.target_url, timeout=10)

            # Check security headers
            self._check_security_headers(response)

            # Check cookie security
            self._check_cookie_security(response)

            # Check clickjacking protection
            self._check_clickjacking(response)

            # Check HTTPS configuration
            self._check_https(response)

            # Check information disclosure
            self._check_information_disclosure(response)

            # Save results
            if self.output_file:
                self._save_results()

            return {
                'target': self.target_url,
                'timestamp': datetime.now().isoformat(),
                'findings': self.findings
            }

        except Exception as e:
            print(f"[!] Error during scan: {e}")
            return None

    def _check_security_headers(self, response):
        """Check for missing or misconfigured security headers"""
        print("[*] Checking security headers...")

        headers_to_check = {
            'X-Frame-Options': {
                'expected': ['DENY', 'SAMEORIGIN'],
                'severity': 'medium',
                'description': 'Protects against clickjacking attacks'
            },
            'X-Content-Type-Options': {
                'expected': ['nosniff'],
                'severity': 'low',
                'description': 'Prevents MIME type sniffing'
            },
            'X-XSS-Protection': {
                'expected': ['1; mode=block'],
                'severity': 'low',
                'description': 'Enables XSS filter in browsers'
            },
            'Strict-Transport-Security': {
                'expected': ['max-age='],
                'severity': 'medium',
                'description': 'Forces HTTPS connections (HSTS)'
            },
            'Content-Security-Policy': {
                'expected': ["default-src", "script-src"],
                'severity': 'medium',
                'description': 'Controls resource loading'
            },
            'Referrer-Policy': {
                'expected': ['no-referrer', 'strict-origin'],
                'severity': 'low',
                'description': 'Controls referrer information'
            },
            'Permissions-Policy': {
                'expected': ['camera', 'microphone', 'geolocation'],
                'severity': 'low',
                'description': 'Controls browser features'
            }
        }

        for header, config in headers_to_check.items():
            header_value = response.headers.get(header)

            if not header_value:
                finding = {
                    'type': 'Missing Security Header',
                    'severity': config['severity'],
                    'header': header,
                    'description': config['description'],
                    'recommendation': f'Add {header} header',
                    'cwe': 'CWE-693'
                }
                self.findings.append(finding)
                print(f"[!] Missing header: {header}")

            elif not any(exp in header_value for exp in config['expected']):
                finding = {
                    'type': 'Misconfigured Security Header',
                    'severity': config['severity'],
                    'header': header,
                    'value': header_value,
                    'description': f'{config["description"]} - Current value may be insufficient',
                    'recommendation': f'Review {header} configuration',
                    'cwe': 'CWE-693'
                }
                self.findings.append(finding)
                print(f"[!] Misconfigured header: {header}")

    def _check_cookie_security(self, response):
        """Check cookie security attributes"""
        print("[*] Checking cookie security...")

        cookies = response.headers.get('Set-Cookie', '')

        if not cookies:
            return

        # Parse multiple Set-Cookie headers
        cookie_list = [cookies] if isinstance(cookies, str) else cookies

        for cookie in cookie_list:
            cookie_name = cookie.split('=')[0] if '=' in cookie else 'unknown'

            issues = []

            # Check for Secure flag
            if 'secure' not in cookie.lower():
                issues.append('Missing Secure flag')

            # Check for HttpOnly flag
            if 'httponly' not in cookie.lower():
                issues.append('Missing HttpOnly flag')

            # Check for SameSite attribute
            if 'samesite' not in cookie.lower():
                issues.append('Missing SameSite attribute')
            elif 'samesite=none' in cookie.lower() and 'secure' not in cookie.lower():
                issues.append('SameSite=None without Secure flag')

            if issues:
                finding = {
                    'type': 'Insecure Cookie Configuration',
                    'severity': 'medium',
                    'cookie': cookie_name,
                    'issues': issues,
                    'evidence': cookie[:100],
                    'recommendation': 'Add Secure, HttpOnly, and SameSite attributes',
                    'cwe': 'CWE-614'
                }
                self.findings.append(finding)
                print(f"[!] Insecure cookie: {cookie_name}")

    def _check_clickjacking(self, response):
        """Check for clickjacking protection"""
        print("[*] Checking clickjacking protection...")

        x_frame_options = response.headers.get('X-Frame-Options')
        csp = response.headers.get('Content-Security-Policy', '')

        # Check if frame-ancestors is in CSP
        has_frame_ancestors = 'frame-ancestors' in csp

        if not x_frame_options and not has_frame_ancestors:
            finding = {
                'type': 'Clickjacking Vulnerability',
                'severity': 'medium',
                'url': self.target_url,
                'evidence': 'No X-Frame-Options or CSP frame-ancestors directive',
                'description': 'Page can be embedded in iframes, enabling clickjacking attacks',
                'recommendation': 'Add X-Frame-Options: DENY or CSP frame-ancestors directive',
                'cwe': 'CWE-1021'
            }
            self.findings.append(finding)
            print(f"[!] Clickjacking possible!")

    def _check_https(self, response):
        """Check HTTPS configuration"""
        print("[*] Checking HTTPS configuration...")

        if not self.target_url.startswith('https://'):
            finding = {
                'type': 'Missing HTTPS',
                'severity': 'high',
                'url': self.target_url,
                'evidence': 'Site accessed over HTTP',
                'description': 'Unencrypted communication allows eavesdropping and MITM attacks',
                'recommendation': 'Implement HTTPS and redirect HTTP to HTTPS',
                'cwe': 'CWE-311'
            }
            self.findings.append(finding)
            print(f"[!] Site not using HTTPS!")
            return

        # Check HSTS
        hsts = response.headers.get('Strict-Transport-Security')
        if not hsts:
            finding = {
                'type': 'Missing HSTS',
                'severity': 'medium',
                'url': self.target_url,
                'evidence': 'No Strict-Transport-Security header',
                'description': 'HSTS header forces HTTPS connections',
                'recommendation': 'Add Strict-Transport-Security header with max-age',
                'cwe': 'CWE-311'
            }
            self.findings.append(finding)
            print(f"[!] HSTS not enabled!")

    def _check_information_disclosure(self, response):
        """Check for information disclosure"""
        print("[*] Checking information disclosure...")

        # Check Server header
        server = response.headers.get('Server')
        if server:
            # Check if version information is disclosed
            if any(char.isdigit() for char in server):
                finding = {
                    'type': 'Server Version Disclosure',
                    'severity': 'low',
                    'header': 'Server',
                    'value': server,
                    'description': 'Server version information disclosed',
                    'recommendation': 'Remove version information from Server header',
                    'cwe': 'CWE-200'
                }
                self.findings.append(finding)
                print(f"[!] Server version disclosed: {server}")

        # Check X-Powered-By header
        powered_by = response.headers.get('X-Powered-By')
        if powered_by:
            finding = {
                'type': 'Technology Disclosure',
                'severity': 'low',
                'header': 'X-Powered-By',
                'value': powered_by,
                'description': 'Technology stack information disclosed',
                'recommendation': 'Remove X-Powered-By header',
                'cwe': 'CWE-200'
            }
            self.findings.append(finding)
            print(f"[!] Technology disclosed: {powered_by}")

        # Check for exposed debug information
        debug_indicators = [
            'Traceback',
            'Stack trace',
            'Exception',
            'Debug mode',
            'phpinfo()',
            'mysql_error',
            'Warning:',
            'Fatal error:'
        ]

        for indicator in debug_indicators:
            if indicator in response.text:
                finding = {
                    'type': 'Debug Information Disclosure',
                    'severity': 'medium',
                    'url': self.target_url,
                    'evidence': f'Found: {indicator}',
                    'description': 'Debug/error information exposed in response',
                    'recommendation': 'Disable debug mode in production',
                    'cwe': 'CWE-489'
                }
                self.findings.append(finding)
                print(f"[!] Debug info found: {indicator}")
                break

    def _save_results(self):
        """Save results to file"""
        results = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'findings': self.findings,
            'summary': {
                'total': len(self.findings),
                'high': sum(1 for f in self.findings if f['severity'] == 'high'),
                'medium': sum(1 for f in self.findings if f['severity'] == 'medium'),
                'low': sum(1 for f in self.findings if f['severity'] == 'low')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 security_headers.py <url>")
        print("\nExample:")
        print("  python3 security_headers.py https://example.com")
        sys.exit(1)

    checker = SecurityChecker(sys.argv[1])
    results = checker.scan()

    if results:
        print(f"\n[+] Scan complete!")
        print(f"    Total findings: {len(results['findings'])}")
        print(f"    High: {sum(1 for f in results['findings'] if f['severity'] == 'high')}")
        print(f"    Medium: {sum(1 for f in results['findings'] if f['severity'] == 'medium')}")
        print(f"    Low: {sum(1 for f in results['findings'] if f['severity'] == 'low')}")
