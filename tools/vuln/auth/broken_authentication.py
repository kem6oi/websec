#!/usr/bin/env python3
"""
Broken Authentication Scanner
Tests for authentication vulnerabilities including password reset poisoning,
session fixation, authentication bypass, and weak password policies
"""

import requests
import json
import re
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

class BrokenAuthenticationScanner:
    """Scanner for broken authentication vulnerabilities"""

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
        """Run comprehensive authentication security scan"""
        print(f"[*] Starting broken authentication scan on {self.target_url}")

        # Test password reset poisoning
        self._test_password_reset_poisoning()

        # Test session fixation
        self._test_session_fixation()

        # Test authentication bypass techniques
        self._test_auth_bypass()

        # Test weak password policy
        self._test_weak_password_policy()

        # Test predictable session tokens
        self._test_session_prediction()

        # Test remember me functionality
        self._test_remember_me()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_password_reset_poisoning(self):
        """Test for password reset poisoning via Host header"""
        print("[*] Testing password reset poisoning...")

        reset_endpoints = [
            '/password/reset',
            '/forgot-password',
            '/reset-password',
            '/password/forgot',
            '/auth/reset',
            '/account/password/reset',
            '/user/password/reset',
            '/reset',
        ]

        for endpoint in reset_endpoints:
            test_url = urljoin(self.base_url, endpoint)

            try:
                # Test with malicious Host header
                headers = {
                    'Host': 'evil.com',
                    'User-Agent': 'Mozilla/5.0'
                }

                response = self.session.get(test_url, headers=headers, timeout=10)

                if response.status_code == 200:
                    # Check if evil.com appears in response
                    if 'evil.com' in response.text:
                        vuln = {
                            'type': 'Password Reset Poisoning',
                            'severity': 'critical',
                            'url': test_url,
                            'evidence': 'Injected host header appears in password reset page',
                            'description': 'Password reset tokens can be sent to attacker-controlled domain',
                            'cwe': 'CWE-640',
                            'impact': 'Account takeover via password reset token theft',
                            'remediation': 'Validate Host header and use absolute URLs for password reset links'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: Password reset poisoning at {endpoint}")
                        return

                # Also test X-Forwarded-Host
                headers = {
                    'X-Forwarded-Host': 'evil.com',
                    'User-Agent': 'Mozilla/5.0'
                }

                response = self.session.get(test_url, headers=headers, timeout=10)

                if response.status_code == 200 and 'evil.com' in response.text:
                    vuln = {
                        'type': 'Password Reset Poisoning (X-Forwarded-Host)',
                        'severity': 'critical',
                        'url': test_url,
                        'evidence': 'X-Forwarded-Host reflected in password reset page',
                        'description': 'Password reset vulnerable to header injection',
                        'cwe': 'CWE-640',
                        'impact': 'Account takeover',
                        'remediation': 'Do not trust X-Forwarded-Host header'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] CRITICAL: Password reset poisoning via X-Forwarded-Host")
                    return

            except:
                pass

    def _test_session_fixation(self):
        """Test for session fixation vulnerabilities"""
        print("[*] Testing session fixation...")

        login_endpoints = [
            '/login',
            '/signin',
            '/auth/login',
            '/user/login',
            '/account/login',
        ]

        for endpoint in login_endpoints:
            test_url = urljoin(self.base_url, endpoint)

            try:
                # Get initial session
                response1 = self.session.get(test_url, timeout=10)
                cookies_before = self.session.cookies.get_dict()

                # Try to login (will likely fail, but we check session handling)
                login_data = {
                    'username': 'testuser',
                    'password': 'testpass',
                    'email': 'test@example.com',
                }

                response2 = self.session.post(test_url, data=login_data, timeout=10, allow_redirects=False)
                cookies_after = self.session.cookies.get_dict()

                # Check if session ID changed after login attempt
                session_keys = ['sessionid', 'session', 'PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId']

                for key in session_keys:
                    if key in cookies_before and key in cookies_after:
                        if cookies_before[key] == cookies_after[key]:
                            vuln = {
                                'type': 'Session Fixation',
                                'severity': 'high',
                                'url': test_url,
                                'evidence': f'Session ID {key} not regenerated after login',
                                'description': 'Session token not regenerated on authentication',
                                'cwe': 'CWE-384',
                                'impact': 'Session fixation attack, attacker can hijack user session',
                                'remediation': 'Regenerate session ID after successful authentication'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] Session fixation vulnerability at {endpoint}")
                            return

            except:
                pass

    def _test_auth_bypass(self):
        """Test for authentication bypass techniques"""
        print("[*] Testing authentication bypass...")

        # Common admin/protected endpoints
        protected_endpoints = [
            '/admin',
            '/admin/',
            '/administrator',
            '/admin/dashboard',
            '/admin/config',
            '/api/admin',
            '/user/admin',
            '/dashboard',
            '/profile',
            '/account',
        ]

        bypass_techniques = [
            # Path traversal
            ('/../admin', 'Path Traversal'),
            ('/admin/..;/', 'Path Traversal with Encoding'),
            ('/admin%2f..%2f', 'URL Encoded Path Traversal'),

            # HTTP verb tampering
            ('', 'HEAD Request'),
            ('', 'OPTIONS Request'),

            # Case manipulation
            ('/Admin', 'Case Variation'),
            ('/ADMIN', 'Uppercase'),

            # Double slash
            ('//admin', 'Double Slash'),
            ('/admin//', 'Trailing Double Slash'),

            # Null byte injection
            ('/admin%00', 'Null Byte'),
            ('/admin%00.jpg', 'Null Byte with Extension'),
        ]

        for endpoint in protected_endpoints:
            base_endpoint_url = urljoin(self.base_url, endpoint)

            try:
                # Get baseline (might be 401, 403, or redirect)
                baseline = self.session.get(base_endpoint_url, timeout=10, allow_redirects=False)
                baseline_status = baseline.status_code

                # If already accessible, skip
                if baseline_status == 200:
                    continue

                # Try bypass techniques
                for bypass_path, technique in bypass_techniques:
                    if 'Request' in technique:
                        # HTTP verb tampering
                        if 'HEAD' in technique:
                            response = self.session.head(base_endpoint_url, timeout=10)
                        elif 'OPTIONS' in technique:
                            response = self.session.options(base_endpoint_url, timeout=10)
                        else:
                            continue
                    else:
                        # Path manipulation
                        test_url = urljoin(self.base_url, bypass_path or endpoint)
                        response = self.session.get(test_url, timeout=10, allow_redirects=False)

                    # Check if bypass worked
                    if response.status_code == 200 and baseline_status != 200:
                        vuln = {
                            'type': 'Authentication Bypass',
                            'severity': 'critical',
                            'url': base_endpoint_url if 'Request' in technique else test_url,
                            'technique': technique,
                            'evidence': f'Protected resource accessible via {technique}',
                            'description': f'Authentication bypass using {technique}',
                            'cwe': 'CWE-287',
                            'impact': 'Unauthorized access to protected resources',
                            'remediation': 'Implement proper access control on all HTTP methods and paths'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: Auth bypass at {endpoint} using {technique}")
                        return

            except:
                pass

    def _test_weak_password_policy(self):
        """Test for weak password policy"""
        print("[*] Testing weak password policy...")

        register_endpoints = [
            '/register',
            '/signup',
            '/auth/register',
            '/user/register',
            '/account/register',
            '/create-account',
        ]

        weak_passwords = [
            '123',
            '1234',
            'pass',
            'password',
            'test',
            'a',
            '111',
        ]

        for endpoint in register_endpoints:
            test_url = urljoin(self.base_url, endpoint)

            try:
                # Try to find registration form
                response = self.session.get(test_url, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')

                if not forms:
                    continue

                for form in forms:
                    # Find password field
                    password_fields = form.find_all('input', {'type': 'password'})

                    if not password_fields:
                        continue

                    # Get form action
                    action = form.get('action', '')
                    if action:
                        if action.startswith('http'):
                            form_url = action
                        else:
                            form_url = urljoin(self.base_url, action)
                    else:
                        form_url = test_url

                    # Test weak passwords
                    for weak_pwd in weak_passwords[:3]:  # Test first 3
                        # Build form data
                        form_data = {
                            'username': 'testuser12345',
                            'email': 'test12345@example.com',
                            'password': weak_pwd,
                        }

                        # Add any other input fields
                        for inp in form.find_all('input'):
                            name = inp.get('name')
                            if name and name not in form_data and inp.get('type') != 'submit':
                                form_data[name] = 'test'

                        response = self.session.post(form_url, data=form_data, timeout=10, allow_redirects=False)

                        # Check if weak password was accepted
                        if response.status_code in [200, 201, 302, 303]:
                            # Check for success indicators
                            success_indicators = ['success', 'welcome', 'registered', 'account created', 'dashboard']

                            if any(indicator in response.text.lower() for indicator in success_indicators) or response.status_code in [302, 303]:
                                vuln = {
                                    'type': 'Weak Password Policy',
                                    'severity': 'medium',
                                    'url': form_url,
                                    'evidence': f'Weak password accepted: {len(weak_pwd)} characters',
                                    'description': 'No password complexity requirements enforced',
                                    'cwe': 'CWE-521',
                                    'impact': 'Accounts vulnerable to brute force attacks',
                                    'remediation': 'Enforce minimum password length (8+) and complexity requirements'
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"[!] Weak password policy at {endpoint}")
                                return

            except:
                pass

    def _test_session_prediction(self):
        """Test for predictable session tokens"""
        print("[*] Testing session token predictability...")

        login_endpoints = [
            '/login',
            '/signin',
            '/auth/login',
        ]

        for endpoint in login_endpoints:
            test_url = urljoin(self.base_url, endpoint)

            try:
                # Collect multiple session tokens
                tokens = []
                for i in range(5):
                    session = requests.Session()
                    response = session.get(test_url, timeout=10)

                    # Look for session tokens in cookies
                    for cookie_name, cookie_value in session.cookies.items():
                        if 'session' in cookie_name.lower() or cookie_name in ['PHPSESSID', 'JSESSIONID']:
                            tokens.append(cookie_value)
                            break

                    time.sleep(0.5)  # Small delay

                if len(tokens) >= 3:
                    # Check for sequential or predictable patterns
                    # Check if tokens are numeric and sequential
                    try:
                        numeric_tokens = [int(t) for t in tokens]
                        # Check if sequential
                        differences = [numeric_tokens[i+1] - numeric_tokens[i] for i in range(len(numeric_tokens)-1)]
                        if all(d == differences[0] for d in differences):
                            vuln = {
                                'type': 'Predictable Session Tokens',
                                'severity': 'critical',
                                'url': test_url,
                                'evidence': f'Sequential session tokens detected: {tokens[:3]}',
                                'description': 'Session tokens are sequential and predictable',
                                'cwe': 'CWE-330',
                                'impact': 'Session hijacking, unauthorized access',
                                'remediation': 'Use cryptographically secure random session token generation'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] CRITICAL: Predictable session tokens")
                            return
                    except:
                        pass

                    # Check for very short tokens (< 16 chars)
                    if all(len(t) < 16 for t in tokens):
                        vuln = {
                            'type': 'Weak Session Tokens',
                            'severity': 'high',
                            'url': test_url,
                            'evidence': f'Short session tokens detected (< 16 chars): {tokens[0]}',
                            'description': 'Session tokens too short, vulnerable to brute force',
                            'cwe': 'CWE-6 30',
                            'impact': 'Session token brute force',
                            'remediation': 'Use longer session tokens (128+ bits)'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Weak session tokens detected")

            except:
                pass

    def _test_remember_me(self):
        """Test remember me functionality"""
        print("[*] Testing 'Remember Me' functionality...")

        login_endpoints = [
            '/login',
            '/signin',
            '/auth/login',
        ]

        for endpoint in login_endpoints:
            test_url = urljoin(self.base_url, endpoint)

            try:
                # Try to find login form
                response = self.session.get(test_url, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')

                for form in forms:
                    # Look for "remember me" checkbox
                    remember_inputs = form.find_all('input', attrs={'name': re.compile(r'remember', re.I)})

                    if not remember_inputs:
                        continue

                    # Get form action
                    action = form.get('action', '')
                    if action:
                        if action.startswith('http'):
                            form_url = action
                        else:
                            form_url = urljoin(self.base_url, action)
                    else:
                        form_url = test_url

                    # Try login with remember me
                    form_data = {
                        'username': 'testuser',
                        'password': 'testpass',
                        'remember': '1',
                        'remember_me': '1',
                    }

                    response = self.session.post(form_url, data=form_data, timeout=10)

                    # Check for long-lived cookies
                    for cookie in self.session.cookies:
                        if cookie.expires and cookie.expires > time.time() + (365 * 24 * 60 * 60):
                            # Cookie expires in more than 1 year
                            vuln = {
                                'type': 'Insecure Remember Me',
                                'severity': 'medium',
                                'url': form_url,
                                'evidence': f'Long-lived cookie: {cookie.name} (expires in {int((cookie.expires - time.time()) / (24*60*60))} days)',
                                'description': 'Remember me sets very long-lived cookies',
                                'cwe': 'CWE-613',
                                'impact': 'Extended session exposure if device compromised',
                                'remediation': 'Limit remember me cookie lifetime and use secure storage'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] Long-lived remember me cookie detected")
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
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'medium')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 broken_authentication.py <url> [output_file]")
        print("\nExample:")
        print("  python3 broken_authentication.py https://example.com")
        print("  python3 broken_authentication.py https://example.com results.json")
        print("\nTests for:")
        print("  - Password reset poisoning (Host header manipulation)")
        print("  - Session fixation vulnerabilities")
        print("  - Authentication bypass techniques")
        print("  - Weak password policy enforcement")
        print("  - Predictable session tokens")
        print("  - Insecure 'Remember Me' functionality")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    scanner = BrokenAuthenticationScanner(target, output)
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
        print(f"    Medium: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'medium')}")
