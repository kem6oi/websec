#!/usr/bin/env python3
"""
Session Security Tester
Tests for session management vulnerabilities including session fixation,
hijacking, prediction, and insecure cookie attributes
"""

import requests
import json
import time
import hashlib
from datetime import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

class SessionSecurityTester:
    """Comprehensive session security tester"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url.rstrip('/')
        self.output_file = output_file
        self.vulnerabilities = []
        self.base_url = urlparse(target_url).scheme + "://" + urlparse(target_url).netloc

    def scan(self):
        """Run session security tests"""
        print(f"[*] Starting session security testing on {self.target_url}")

        # Test session fixation
        self._test_session_fixation()

        # Test session token entropy
        self._test_token_entropy()

        # Test cookie security attributes
        self._test_cookie_security()

        # Test session timeout
        self._test_session_timeout()

        # Test concurrent sessions
        self._test_concurrent_sessions()

        # Test logout functionality
        self._test_logout()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_session_fixation(self):
        """Test for session fixation"""
        print("[*] Testing session fixation...")

        session1 = requests.Session()
        response1 = session1.get(self.target_url, timeout=10)
        cookies_before = session1.cookies.get_dict()

        # Try login
        login_data = {'username': 'test', 'password': 'test'}
        login_endpoints = ['/login', '/signin', '/auth/login']

        for endpoint in login_endpoints:
            try:
                login_url = urljoin(self.base_url, endpoint)
                response2 = session1.post(login_url, data=login_data, timeout=10)
                cookies_after = session1.cookies.get_dict()

                # Check if session ID changed
                session_keys = ['sessionid', 'session', 'PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId']

                for key in session_keys:
                    if key in cookies_before and key in cookies_after:
                        if cookies_before[key] == cookies_after[key]:
                            vuln = {
                                'type': 'Session Fixation',
                                'severity': 'high',
                                'url': login_url,
                                'evidence': f'Session ID {key} unchanged after login',
                                'description': 'Session not regenerated on authentication',
                                'cwe': 'CWE-384',
                                'impact': 'Session fixation attack',
                                'remediation': 'Regenerate session ID after login'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] Session fixation vulnerability")
                            return
            except:
                pass

    def _test_token_entropy(self):
        """Test session token randomness"""
        print("[*] Testing session token entropy...")

        tokens = []
        for i in range(10):
            try:
                session = requests.Session()
                response = session.get(self.target_url, timeout=10)

                for cookie in session.cookies:
                    if 'session' in cookie.name.lower():
                        tokens.append(cookie.value)
                        break

                time.sleep(0.3)
            except:
                pass

        if len(tokens) >= 5:
            # Check token length
            avg_length = sum(len(t) for t in tokens) / len(tokens)

            if avg_length < 16:
                vuln = {
                    'type': 'Weak Session Tokens',
                    'severity': 'high',
                    'url': self.target_url,
                    'evidence': f'Average token length: {avg_length:.1f} chars',
                    'description': 'Session tokens too short',
                    'cwe': 'CWE-6 30',
                    'impact': 'Brute force session tokens',
                    'remediation': 'Use 128+ bit random tokens'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] Weak session tokens (too short)")

            # Check for sequential patterns
            if all(t.isdigit() for t in tokens):
                try:
                    numeric_tokens = [int(t) for t in tokens]
                    diffs = [numeric_tokens[i+1] - numeric_tokens[i] for i in range(len(numeric_tokens)-1)]

                    if all(d == diffs[0] for d in diffs):
                        vuln = {
                            'type': 'Predictable Session Tokens',
                            'severity': 'critical',
                            'url': self.target_url,
                            'evidence': f'Sequential tokens: {tokens[:3]}',
                            'description': 'Session tokens are sequential',
                            'cwe': 'CWE-330',
                            'impact': 'Session hijacking',
                            'remediation': 'Use cryptographically random tokens'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: Predictable session tokens")
                        return
                except:
                    pass

    def _test_cookie_security(self):
        """Test cookie security attributes"""
        print("[*] Testing cookie security attributes...")

        try:
            session = requests.Session()
            response = session.get(self.target_url, timeout=10)

            for cookie in session.cookies:
                issues = []

                # Check Secure flag
                if not cookie.secure and self.target_url.startswith('https://'):
                    issues.append('Missing Secure flag (HTTPS)')

                # Check HttpOnly flag
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append('Missing HttpOnly flag')

                # Check SameSite
                if not cookie.has_nonstandard_attr('SameSite'):
                    issues.append('Missing SameSite attribute')

                if issues:
                    vuln = {
                        'type': 'Insecure Cookie Attributes',
                        'severity': 'medium',
                        'url': self.target_url,
                        'cookie': cookie.name,
                        'issues': issues,
                        'description': 'Cookie lacks security attributes',
                        'cwe': 'CWE-614',
                        'impact': 'Session hijacking, XSS, CSRF',
                        'remediation': 'Set Secure, HttpOnly, and SameSite flags'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Insecure cookie: {cookie.name}")

        except:
            pass

    def _test_session_timeout(self):
        """Test session timeout"""
        print("[*] Testing session timeout...")

        try:
            session = requests.Session()
            response = session.get(self.target_url, timeout=10)

            # Check cookie expiration
            for cookie in session.cookies:
                if cookie.expires:
                    lifetime = cookie.expires - time.time()

                    # If session cookie lasts more than 24 hours
                    if lifetime > 24 * 60 * 60:
                        vuln = {
                            'type': 'Excessive Session Lifetime',
                            'severity': 'low',
                            'url': self.target_url,
                            'cookie': cookie.name,
                            'evidence': f'Session expires in {int(lifetime / 3600)} hours',
                            'description': 'Session lifetime too long',
                            'cwe': 'CWE-613',
                            'impact': 'Extended exposure window',
                            'remediation': 'Implement shorter session timeout'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Excessive session lifetime")

        except:
            pass

    def _test_concurrent_sessions(self):
        """Test if concurrent sessions are allowed"""
        print("[*] Testing concurrent sessions...")

        login_endpoints = ['/login', '/signin', '/auth/login']

        for endpoint in login_endpoints:
            try:
                login_url = urljoin(self.base_url, endpoint)

                # Create two sessions with same credentials
                session1 = requests.Session()
                session2 = requests.Session()

                login_data = {'username': 'test', 'password': 'test'}

                r1 = session1.post(login_url, data=login_data, timeout=10)
                time.sleep(1)
                r2 = session2.post(login_url, data=login_data, timeout=10)

                # If both succeeded
                if r1.status_code == 200 and r2.status_code == 200:
                    # Try accessing protected resource with first session
                    protected_urls = ['/dashboard', '/account', '/profile']

                    for protected in protected_urls:
                        protected_url = urljoin(self.base_url, protected)

                        resp1 = session1.get(protected_url, timeout=10)

                        # If first session still works after second login
                        if resp1.status_code == 200 and 'login' not in resp1.url.lower():
                            vuln = {
                                'type': 'Concurrent Sessions Allowed',
                                'severity': 'low',
                                'url': login_url,
                                'evidence': 'Multiple active sessions for same user',
                                'description': 'No session invalidation on new login',
                                'cwe': 'CWE-362',
                                'impact': 'Session persistence after new login',
                                'remediation': 'Invalidate old sessions on new login'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] Concurrent sessions allowed")
                            return

            except:
                pass

    def _test_logout(self):
        """Test logout functionality"""
        print("[*] Testing logout functionality...")

        logout_endpoints = ['/logout', '/signout', '/auth/logout']

        for endpoint in logout_endpoints:
            try:
                logout_url = urljoin(self.base_url, endpoint)

                session = requests.Session()

                # Try to login first
                login_url = urljoin(self.base_url, '/login')
                session.post(login_url, data={'username': 'test', 'password': 'test'}, timeout=10)

                # Store session cookies
                cookies_before_logout = session.cookies.copy()

                # Logout
                logout_response = session.get(logout_url, timeout=10)

                # Try to access protected resource with old session
                protected_urls = ['/dashboard', '/account', '/profile']

                for protected in protected_urls:
                    protected_url = urljoin(self.base_url, protected)

                    # Use old cookies
                    old_session = requests.Session()
                    old_session.cookies = cookies_before_logout

                    resp = old_session.get(protected_url, timeout=10, allow_redirects=False)

                    # If still accessible
                    if resp.status_code == 200:
                        vuln = {
                            'type': 'Incomplete Logout',
                            'severity': 'medium',
                            'url': logout_url,
                            'evidence': 'Session still valid after logout',
                            'description': 'Logout doesn\'t invalidate session',
                            'cwe': 'CWE-613',
                            'impact': 'Session remains active after logout',
                            'remediation': 'Invalidate session on logout'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Incomplete logout")
                        return

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
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'medium'),
                'low': sum(1 for v in self.vulnerabilities if v['severity'] == 'low')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 session_security.py <url> [output_file]")
        print("\nExample:")
        print("  python3 session_security.py https://example.com")
        print("\nTests for:")
        print("  - Session fixation")
        print("  - Weak/predictable session tokens")
        print("  - Insecure cookie attributes")
        print("  - Excessive session lifetime")
        print("  - Concurrent sessions")
        print("  - Incomplete logout")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    tester = SessionSecurityTester(target, output)
    results = tester.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
