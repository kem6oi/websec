#!/usr/bin/env python3
"""
Account Takeover Chain Tester
Tests complete account takeover flows including password reset, OAuth, and session management
"""

import requests
import json
import re
import time
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup

class AccountTakeoverChainTester:
    """Complete account takeover chain testing"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def scan(self):
        """Run account takeover chain tests"""
        print(f"[*] Starting account takeover chain testing on {self.target_url}")

        # Test password reset flow
        self._test_password_reset_flow()

        # Test OAuth flow
        self._test_oauth_flow()

        # Test session management
        self._test_session_management()

        # Test email verification bypass
        self._test_email_verification()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_password_reset_flow(self):
        """Test complete password reset flow for vulnerabilities"""
        print("[*] Testing password reset flow...")

        # Common password reset endpoints
        reset_endpoints = [
            '/password/reset',
            '/forgot-password',
            '/reset-password',
            '/account/password/reset',
            '/api/password/reset',
            '/auth/forgot-password',
        ]

        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in reset_endpoints:
            reset_url = base_url + endpoint

            try:
                # Test 1: Password reset token leak in response
                response = self.session.post(reset_url, data={'email': 'test@example.com'}, timeout=10)

                # Check if token is leaked in response
                token_patterns = [
                    r'token["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
                    r'reset[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
                    r'/reset/([a-zA-Z0-9]{20,})',
                ]

                for pattern in token_patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    if matches:
                        vuln = {
                            'type': 'Account Takeover - Password Reset Token Leak',
                            'severity': 'critical',
                            'url': reset_url,
                            'evidence': f'Password reset token leaked in response: {matches[0][:20]}...',
                            'description': 'Password reset token exposed in API response',
                            'cwe': 'CWE-640',
                            'impact': 'Full account takeover via leaked reset token',
                            'remediation': 'Send reset tokens only via email, never in response'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: Password reset token leaked in response")
                        return

                # Test 2: Token reuse
                # Simulate getting a token (in real scenario, from email)
                test_token = 'test_reset_token_12345'
                confirm_endpoints = [
                    f'/password/reset/confirm',
                    f'/reset-password/confirm',
                    f'/password/reset?token={test_token}',
                ]

                for confirm_endpoint in confirm_endpoints:
                    confirm_url = base_url + confirm_endpoint

                    # Try to use token twice
                    reset_data = {
                        'token': test_token,
                        'password': 'NewPassword123!',
                        'password_confirmation': 'NewPassword123!'
                    }

                    try:
                        # First use
                        response1 = self.session.post(confirm_url, data=reset_data, timeout=10)

                        # Second use (should fail)
                        response2 = self.session.post(confirm_url, data=reset_data, timeout=10)

                        # If both succeed, token reuse is possible
                        if response1.status_code == 200 and response2.status_code == 200:
                            if 'success' in response2.text.lower() or 'reset' in response2.text.lower():
                                vuln = {
                                    'type': 'Account Takeover - Reset Token Reuse',
                                    'severity': 'high',
                                    'url': confirm_url,
                                    'evidence': 'Password reset token can be reused multiple times',
                                    'description': 'Reset tokens are not invalidated after use',
                                    'cwe': 'CWE-640',
                                    'impact': 'Token interception allows persistent access',
                                    'remediation': 'Invalidate reset tokens after first use'
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"[!] Password reset token reuse possible")
                    except:
                        pass

                # Test 3: Missing rate limiting
                print("[*] Testing password reset rate limiting...")
                reset_attempts = []
                for i in range(5):
                    try:
                        start = time.time()
                        resp = self.session.post(reset_url, data={'email': f'test{i}@example.com'}, timeout=5)
                        elapsed = time.time() - start
                        reset_attempts.append({'status': resp.status_code, 'time': elapsed})
                    except:
                        pass

                # If all requests succeed quickly, no rate limiting
                if len(reset_attempts) >= 5 and all(a['status'] in [200, 201, 202] for a in reset_attempts):
                    avg_time = sum(a['time'] for a in reset_attempts) / len(reset_attempts)
                    if avg_time < 1:  # All requests under 1 second
                        vuln = {
                            'type': 'Account Takeover - Password Reset Rate Limit Missing',
                            'severity': 'medium',
                            'url': reset_url,
                            'evidence': f'5 password reset requests accepted in {avg_time:.2f}s average',
                            'description': 'No rate limiting on password reset endpoint',
                            'cwe': 'CWE-307',
                            'impact': 'Email bombing, enumeration, DoS',
                            'remediation': 'Implement rate limiting and CAPTCHA'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Password reset lacks rate limiting")

            except:
                pass

    def _test_oauth_flow(self):
        """Test OAuth flow for vulnerabilities"""
        print("[*] Testing OAuth flow...")

        # Common OAuth endpoints
        oauth_endpoints = [
            '/oauth/authorize',
            '/auth/oauth',
            '/login/oauth/authorize',
            '/api/oauth/authorize',
        ]

        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in oauth_endpoints:
            oauth_url = base_url + endpoint

            try:
                # Test 1: Missing state parameter (CSRF)
                params = {
                    'client_id': 'test_client_123',
                    'redirect_uri': 'https://attacker.com/callback',
                    'response_type': 'code',
                    'scope': 'read write'
                }

                response = self.session.get(oauth_url, params=params, timeout=10, allow_redirects=False)

                # If redirect happens without state, CSRF possible
                if response.status_code in [302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if 'code=' in location and 'state=' not in params:
                        vuln = {
                            'type': 'Account Takeover - OAuth CSRF (Missing State)',
                            'severity': 'high',
                            'url': oauth_url,
                            'evidence': 'OAuth flow proceeds without state parameter',
                            'description': 'OAuth implementation missing CSRF protection',
                            'cwe': 'CWE-352',
                            'impact': 'Account linking attack, OAuth CSRF',
                            'remediation': 'Require and validate state parameter'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] OAuth CSRF vulnerability (missing state)")
                        return

                # Test 2: Open redirect via redirect_uri
                open_redirect_uris = [
                    'https://evil.com',
                    'https://example.com.evil.com',
                    'https://example.com@evil.com',
                    'https://example.com/../evil.com',
                ]

                for evil_uri in open_redirect_uris:
                    params['redirect_uri'] = evil_uri
                    try:
                        response = self.session.get(oauth_url, params=params, timeout=10, allow_redirects=False)

                        if response.status_code in [302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            if 'evil.com' in location:
                                vuln = {
                                    'type': 'Account Takeover - OAuth Redirect URI Bypass',
                                    'severity': 'critical',
                                    'url': oauth_url,
                                    'evidence': f'OAuth redirects to attacker domain: {evil_uri}',
                                    'description': 'OAuth redirect_uri validation can be bypassed',
                                    'cwe': 'CWE-601',
                                    'impact': 'Authorization code theft, full account takeover',
                                    'remediation': 'Strict redirect_uri validation, use allowlist'
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"[!] CRITICAL: OAuth redirect_uri bypass")
                                return
                    except:
                        pass

            except:
                pass

    def _test_session_management(self):
        """Test session management vulnerabilities"""
        print("[*] Testing session management...")

        # Test session fixation
        try:
            # Get a session before authentication
            response = self.session.get(self.target_url, timeout=10)
            cookies_before = self.session.cookies.copy()

            # Simulate login (in real scenario, would use actual credentials)
            login_endpoints = [
                '/login',
                '/auth/login',
                '/api/login',
                '/signin',
            ]

            parsed = urlparse(self.target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for endpoint in login_endpoints:
                login_url = base_url + endpoint

                try:
                    # Attempt login
                    login_data = {
                        'username': 'test@example.com',
                        'password': 'password123',
                        'email': 'test@example.com'
                    }

                    response = self.session.post(login_url, data=login_data, timeout=10)
                    cookies_after = self.session.cookies.copy()

                    # Check if session ID changed
                    session_cookie_names = ['session', 'sessionid', 'PHPSESSID', 'JSESSIONID', 'connect.sid']

                    for cookie_name in session_cookie_names:
                        if cookie_name in cookies_before and cookie_name in cookies_after:
                            if cookies_before[cookie_name] == cookies_after[cookie_name]:
                                vuln = {
                                    'type': 'Account Takeover - Session Fixation',
                                    'severity': 'high',
                                    'url': login_url,
                                    'evidence': f'Session ID ({cookie_name}) not regenerated after login',
                                    'description': 'Application vulnerable to session fixation',
                                    'cwe': 'CWE-384',
                                    'impact': 'Account takeover via session fixation',
                                    'remediation': 'Regenerate session ID after authentication'
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"[!] Session fixation vulnerability detected")
                                return

                except:
                    pass

        except:
            pass

        # Test session token predictability
        print("[*] Testing session token entropy...")
        session_tokens = []

        for i in range(3):
            try:
                # Create new session
                new_session = requests.Session()
                new_session.headers.update({'User-Agent': 'Mozilla/5.0'})
                response = new_session.get(self.target_url, timeout=10)

                # Extract session token
                for cookie in new_session.cookies:
                    if 'session' in cookie.name.lower():
                        session_tokens.append(cookie.value)
                        break

            except:
                pass

        # Analyze tokens
        if len(session_tokens) >= 3:
            # Check if tokens are too short or predictable
            avg_length = sum(len(t) for t in session_tokens) / len(session_tokens)

            if avg_length < 16:
                vuln = {
                    'type': 'Account Takeover - Weak Session Token',
                    'severity': 'high',
                    'url': self.target_url,
                    'evidence': f'Session tokens too short (avg: {avg_length:.0f} chars)',
                    'description': 'Session tokens have insufficient entropy',
                    'cwe': 'CWE-330',
                    'impact': 'Session token prediction, brute force attacks',
                    'remediation': 'Use cryptographically secure random tokens (128+ bits)'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] Weak session tokens detected")

    def _test_email_verification(self):
        """Test email verification bypass"""
        print("[*] Testing email verification bypass...")

        # Common registration endpoints
        register_endpoints = [
            '/register',
            '/signup',
            '/auth/register',
            '/api/register',
            '/user/register',
        ]

        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in register_endpoints:
            register_url = base_url + endpoint

            try:
                # Test 1: Access without verification
                registration_data = {
                    'email': 'test@example.com',
                    'username': 'testuser',
                    'password': 'Password123!',
                    'password_confirmation': 'Password123!'
                }

                response = self.session.post(register_url, data=registration_data, timeout=10)

                # Check if account created successfully
                if response.status_code in [200, 201]:
                    # Try to access authenticated endpoints
                    protected_endpoints = [
                        '/dashboard',
                        '/profile',
                        '/account',
                        '/api/user',
                    ]

                    for protected in protected_endpoints:
                        protected_url = base_url + protected

                        try:
                            resp = self.session.get(protected_url, timeout=10)

                            # If we can access without email verification
                            if resp.status_code == 200 and 'verify' not in resp.text.lower():
                                vuln = {
                                    'type': 'Account Takeover - Email Verification Bypass',
                                    'severity': 'medium',
                                    'url': register_url,
                                    'evidence': 'Account functional without email verification',
                                    'description': 'Users can access features without verifying email',
                                    'cwe': 'CWE-287',
                                    'impact': 'Account enumeration, spam, fake accounts',
                                    'remediation': 'Enforce email verification before account access'
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"[!] Email verification can be bypassed")
                                return

                        except:
                            pass

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
        print("Usage: python3 account_takeover_chain.py <url> [output_file]")
        print("\nExample:")
        print("  python3 account_takeover_chain.py https://example.com")
        print("\nTests for:")
        print("  - Password reset token leakage")
        print("  - Password reset token reuse")
        print("  - OAuth CSRF (missing state parameter)")
        print("  - OAuth redirect_uri bypass")
        print("  - Session fixation")
        print("  - Weak session tokens")
        print("  - Email verification bypass")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    tester = AccountTakeoverChainTester(target, output)
    results = tester.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
        print(f"    Medium: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'medium')}")
