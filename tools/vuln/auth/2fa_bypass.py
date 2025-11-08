#!/usr/bin/env python3
"""
2FA/MFA Bypass Tester
Tests for two-factor authentication bypass vulnerabilities
"""

import requests
import json
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

class TwoFactorBypassTester:
    """2FA bypass vulnerability tester"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url.rstrip('/')
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        parsed = urlparse(target_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"

    def scan(self):
        """Run 2FA bypass tests"""
        print(f"[*] Starting 2FA bypass testing on {self.target_url}")

        # Test rate limiting on 2FA codes
        self._test_rate_limiting()

        # Test response manipulation
        self._test_response_manipulation()

        # Test direct access bypass
        self._test_direct_access_bypass()

        # Test backup code weaknesses
        self._test_backup_codes()

        # Test code reuse
        self._test_code_reuse()

        # Test predictable codes
        self._test_predictable_codes()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_rate_limiting(self):
        """Test for missing rate limiting on 2FA codes"""
        print("[*] Testing 2FA rate limiting...")

        two_fa_endpoints = [
            '/2fa/verify',
            '/mfa/verify',
            '/verify-2fa',
            '/verify-otp',
            '/otp/verify',
            '/auth/2fa',
            '/auth/verify',
        ]

        for endpoint in two_fa_endpoints:
            test_url = urljoin(self.base_url, endpoint)

            try:
                # Attempt multiple 2FA code submissions
                attempts = 0
                blocked = False

                for i in range(15):  # Try 15 attempts
                    code = f"{i:06d}"  # 000000, 000001, etc.

                    response = self.session.post(
                        test_url,
                        data={'code': code, 'otp': code, 'token': code},
                        timeout=10
                    )

                    attempts += 1

                    # Check if we're being rate limited
                    if response.status_code == 429 or 'rate limit' in response.text.lower() or 'too many' in response.text.lower():
                        blocked = True
                        break

                    time.sleep(0.5)

                # If we could try 15+ codes without being blocked
                if attempts >= 15 and not blocked:
                    vuln = {
                        'type': '2FA Brute Force (No Rate Limiting)',
                        'severity': 'critical',
                        'url': test_url,
                        'evidence': f'{attempts} attempts made without rate limiting',
                        'description': 'No rate limiting on 2FA code verification',
                        'cwe': 'CWE-307',
                        'impact': '2FA bypass via brute force (1,000,000 possible codes)',
                        'remediation': 'Implement strict rate limiting (3-5 attempts max)'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] CRITICAL: No rate limiting on 2FA at {endpoint}")
                    return

            except:
                pass

    def _test_response_manipulation(self):
        """Test for client-side 2FA bypass"""
        print("[*] Testing response manipulation...")

        two_fa_endpoints = [
            '/2fa/verify',
            '/mfa/verify',
            '/verify-2fa',
        ]

        for endpoint in two_fa_endpoints:
            test_url = urljoin(self.base_url, endpoint)

            try:
                # Submit wrong 2FA code
                response = self.session.post(
                    test_url,
                    data={'code': '000000', 'otp': '000000'},
                    timeout=10
                )

                # Check for client-side validation indicators
                client_side_indicators = [
                    '"success":false',
                    '"valid":false',
                    '"authenticated":false',
                    '"2fa_verified":false',
                    'isValid: false',
                    'verified: false',
                ]

                for indicator in client_side_indicators:
                    if indicator in response.text:
                        vuln = {
                            'type': '2FA Response Manipulation',
                            'severity': 'high',
                            'url': test_url,
                            'evidence': f'Client-side validation indicator found: {indicator}',
                            'description': '2FA validation appears to be client-side',
                            'cwe': 'CWE-603',
                            'impact': 'Bypass via response manipulation in browser dev tools',
                            'remediation': 'Enforce 2FA validation server-side only'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Potential client-side 2FA validation")
                        return

            except:
                pass

    def _test_direct_access_bypass(self):
        """Test for direct access bypass"""
        print("[*] Testing direct access bypass...")

        # Common post-2FA pages
        protected_pages = [
            '/dashboard',
            '/account',
            '/profile',
            '/home',
            '/app',
            '/portal',
            '/admin',
        ]

        for page in protected_pages:
            test_url = urljoin(self.base_url, page)

            try:
                # Try to access without completing 2FA
                response = self.session.get(test_url, timeout=10, allow_redirects=False)

                # If we get 200 instead of redirect to 2FA
                if response.status_code == 200:
                    # Check if it's actually the protected content
                    protected_indicators = ['dashboard', 'welcome', 'account', 'logout']

                    if any(indicator in response.text.lower() for indicator in protected_indicators):
                        vuln = {
                            'type': '2FA Direct Access Bypass',
                            'severity': 'critical',
                            'url': test_url,
                            'evidence': 'Protected page accessible without 2FA',
                            'description': 'Can access protected resources without completing 2FA',
                            'cwe': 'CWE-288',
                            'impact': 'Complete 2FA bypass',
                            'remediation': 'Enforce 2FA verification for all protected resources'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: Direct access bypass at {page}")
                        return

            except:
                pass

    def _test_backup_codes(self):
        """Test backup code security"""
        print("[*] Testing backup code security...")

        backup_endpoints = [
            '/2fa/backup',
            '/auth/backup-codes',
            '/account/backup-codes',
            '/mfa/backup',
        ]

        for endpoint in backup_endpoints:
            test_url = urljoin(self.base_url, endpoint)

            try:
                response = self.session.get(test_url, timeout=10)

                if response.status_code == 200:
                    # Check for sequential or predictable backup codes
                    # Look for patterns like 12345678, 11111111, etc.
                    code_patterns = [
                        r'\b(\d)\1{7,}\b',  # 11111111, 22222222
                        r'\b12345678\b',
                        r'\b87654321\b',
                        r'\b\d{4}-\d{4}\b',  # Short codes like 1234-5678
                    ]

                    import re
                    for pattern in code_patterns:
                        if re.search(pattern, response.text):
                            vuln = {
                                'type': 'Predictable Backup Codes',
                                'severity': 'high',
                                'url': test_url,
                                'evidence': 'Backup codes appear predictable or sequential',
                                'description': 'Backup codes may be weak or predictable',
                                'cwe': 'CWE-330',
                                'impact': '2FA bypass via predictable backup codes',
                                'remediation': 'Use cryptographically secure random backup codes'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] Predictable backup codes detected")
                            return

            except:
                pass

    def _test_code_reuse(self):
        """Test if 2FA codes can be reused"""
        print("[*] Testing code reuse...")

        two_fa_endpoints = [
            '/2fa/verify',
            '/mfa/verify',
            '/verify-2fa',
        ]

        for endpoint in two_fa_endpoints:
            test_url = urljoin(self.base_url, endpoint)

            try:
                test_code = '123456'

                # First attempt
                response1 = self.session.post(
                    test_url,
                    data={'code': test_code},
                    timeout=10
                )

                # Second attempt with same code
                time.sleep(1)
                response2 = self.session.post(
                    test_url,
                    data={'code': test_code},
                    timeout=10
                )

                # If both attempts get similar responses (not explicitly rejected)
                if response1.status_code == response2.status_code:
                    if response1.text == response2.text or len(response1.text) == len(response2.text):
                        vuln = {
                            'type': '2FA Code Reuse',
                            'severity': 'medium',
                            'url': test_url,
                            'evidence': 'Same 2FA code accepted multiple times',
                            'description': '2FA codes can be reused',
                            'cwe': 'CWE-294',
                            'impact': 'Replay attacks, extended window for code theft',
                            'remediation': 'Invalidate 2FA codes after first use'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] 2FA code reuse possible")

            except:
                pass

    def _test_predictable_codes(self):
        """Test for predictable 2FA codes"""
        print("[*] Testing for predictable 2FA patterns...")

        two_fa_endpoints = [
            '/2fa/verify',
            '/mfa/verify',
        ]

        for endpoint in two_fa_endpoints:
            test_url = urljoin(self.base_url, endpoint)

            try:
                # Test common/weak codes
                weak_codes = [
                    '000000', '111111', '123456', '654321',
                    '000001', '999999', '112233'
                ]

                for code in weak_codes[:5]:
                    response = self.session.post(
                        test_url,
                        data={'code': code, 'otp': code},
                        timeout=10
                    )

                    # Check for success
                    success_indicators = ['success', 'verified', 'authenticated', 'welcome', 'dashboard']

                    if any(indicator in response.text.lower() for indicator in success_indicators):
                        vuln = {
                            'type': 'Weak 2FA Code Accepted',
                            'severity': 'critical',
                            'url': test_url,
                            'code': code,
                            'evidence': f'Weak/predictable code {code} accepted',
                            'description': 'Predictable 2FA code accepted',
                            'cwe': 'CWE-330',
                            'impact': '2FA bypass with common codes',
                            'remediation': 'Generate truly random 2FA codes'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: Weak 2FA code accepted: {code}")
                        return

                    time.sleep(0.5)

            except:
                pass

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
        print("Usage: python3 2fa_bypass.py <url> [output_file]")
        print("\nExample:")
        print("  python3 2fa_bypass.py https://example.com")
        print("  python3 2fa_bypass.py https://example.com results.json")
        print("\nTests for:")
        print("  - Missing rate limiting (brute force)")
        print("  - Response manipulation (client-side validation)")
        print("  - Direct access bypass")
        print("  - Weak backup codes")
        print("  - Code reuse vulnerabilities")
        print("  - Predictable 2FA codes")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    tester = TwoFactorBypassTester(target, output)
    results = tester.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
        print(f"    Medium: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'medium')}")
