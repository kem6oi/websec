#!/usr/bin/env python3
"""
OAuth Vulnerability Scanner
Tests for OAuth 2.0 security vulnerabilities including token theft,
redirect URI manipulation, state parameter issues, and scope abuse
"""

import requests
import json
import re
import urllib.parse
from datetime import datetime
from bs4 import BeautifulSoup

class OAuthVulnerabilityScanner:
    """Scanner for OAuth 2.0 vulnerabilities"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url.rstrip('/')
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        parsed = urllib.parse.urlparse(target_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"

    def scan(self):
        """Run OAuth vulnerability scan"""
        print(f"[*] Starting OAuth vulnerability scan on {self.target_url}")

        # Find OAuth endpoints
        oauth_endpoints = self._find_oauth_endpoints()

        if not oauth_endpoints:
            print("[!] No OAuth endpoints detected")
            return {
                'target': self.target_url,
                'timestamp': datetime.now().isoformat(),
                'vulnerabilities': []
            }

        print(f"[*] Found {len(oauth_endpoints)} potential OAuth endpoints")

        # Test redirect URI manipulation
        self._test_redirect_uri_manipulation(oauth_endpoints)

        # Test missing state parameter
        self._test_missing_state_parameter(oauth_endpoints)

        # Test open redirect in callback
        self._test_open_redirect_callback(oauth_endpoints)

        # Test token theft vulnerabilities
        self._test_token_theft(oauth_endpoints)

        # Test scope abuse
        self._test_scope_abuse(oauth_endpoints)

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _find_oauth_endpoints(self):
        """Find OAuth endpoints"""
        endpoints = []

        # Common OAuth paths
        oauth_paths = [
            '/oauth/authorize',
            '/oauth/token',
            '/oauth/callback',
            '/oauth2/authorize',
            '/oauth2/token',
            '/oauth2/callback',
            '/auth/oauth',
            '/auth/callback',
            '/login/oauth',
            '/api/oauth',
            '/connect/authorize',
            '/connect/token',
        ]

        for path in oauth_paths:
            test_url = urllib.parse.urljoin(self.base_url, path)

            try:
                response = self.session.get(test_url, timeout=10, allow_redirects=False)

                # Check if it looks like an OAuth endpoint
                if response.status_code in [200, 302, 400]:
                    # Look for OAuth parameters or keywords
                    oauth_indicators = [
                        'client_id', 'redirect_uri', 'response_type',
                        'scope', 'state', 'code', 'access_token',
                        'authorization', 'oauth', 'consent'
                    ]

                    content = response.text.lower() + str(response.headers).lower()

                    if any(indicator in content for indicator in oauth_indicators):
                        endpoints.append({
                            'url': test_url,
                            'path': path,
                            'status': response.status_code
                        })
                        print(f"[+] Found OAuth endpoint: {path}")

            except:
                pass

        return endpoints

    def _test_redirect_uri_manipulation(self, endpoints):
        """Test for redirect URI manipulation"""
        print("[*] Testing redirect URI manipulation...")

        for endpoint in endpoints:
            if 'authorize' not in endpoint['path']:
                continue

            test_url = endpoint['url']

            # Test payloads for redirect URI
            redirect_payloads = [
                # Open redirect to evil.com
                'https://evil.com',
                'http://evil.com',

                # Subdomain takeover
                'https://attacker.example.com',

                # Path traversal
                'https://example.com/../evil.com',
                'https://example.com/..;/evil.com',

                # Protocol manipulation
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',

                # Partial override
                'https://example.com.evil.com',
                'https://example.com@evil.com',
                'https://example.com#@evil.com',

                # Null byte
                'https://example.com%00.evil.com',

                # Open redirect with URL encoding
                'https://example.com/%2f/evil.com',
            ]

            for payload in redirect_payloads:
                params = {
                    'client_id': 'test_client',
                    'redirect_uri': payload,
                    'response_type': 'code',
                    'scope': 'read',
                    'state': 'test'
                }

                test_url_with_params = f"{test_url}?{urllib.parse.urlencode(params)}"

                try:
                    response = self.session.get(
                        test_url_with_params,
                        timeout=10,
                        allow_redirects=False
                    )

                    # Check if redirect is accepted
                    if response.status_code in [302, 303, 307, 308]:
                        location = response.headers.get('Location', '')

                        # Check if our malicious redirect is used
                        if 'evil.com' in location or payload in location:
                            vuln = {
                                'type': 'OAuth Redirect URI Manipulation',
                                'severity': 'critical',
                                'url': test_url,
                                'payload': payload,
                                'evidence': f'Redirect to: {location}',
                                'description': 'OAuth authorization accepts arbitrary redirect URIs',
                                'cwe': 'CWE-601',
                                'impact': 'OAuth token theft, authorization code theft',
                                'remediation': 'Implement strict redirect URI whitelist validation'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] CRITICAL: Redirect URI manipulation with payload: {payload}")
                            return

                    # Check if error but payload reflected in response
                    if 'evil.com' in response.text or payload in response.text:
                        vuln = {
                            'type': 'OAuth Redirect URI Reflected',
                            'severity': 'high',
                            'url': test_url,
                            'payload': payload,
                            'evidence': 'Malicious redirect URI reflected in response',
                            'description': 'Unvalidated redirect URI reflected, potential for exploitation',
                            'cwe': 'CWE-601',
                            'impact': 'Potential token leakage',
                            'remediation': 'Validate and sanitize redirect URIs'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Redirect URI reflected: {payload}")

                except:
                    pass

    def _test_missing_state_parameter(self, endpoints):
        """Test for missing state parameter (CSRF)"""
        print("[*] Testing for missing state parameter...")

        for endpoint in endpoints:
            if 'authorize' not in endpoint['path']:
                continue

            test_url = endpoint['url']

            # Request without state parameter
            params = {
                'client_id': 'test_client',
                'redirect_uri': 'https://example.com/callback',
                'response_type': 'code',
                'scope': 'read'
            }

            test_url_with_params = f"{test_url}?{urllib.parse.urlencode(params)}"

            try:
                response = self.session.get(
                    test_url_with_params,
                    timeout=10,
                    allow_redirects=False
                )

                # If request succeeds without state, it's vulnerable
                if response.status_code in [200, 302, 303]:
                    # Check if it's NOT rejecting the request
                    error_indicators = ['error', 'invalid', 'missing', 'required']

                    if not any(indicator in response.text.lower() for indicator in error_indicators):
                        vuln = {
                            'type': 'OAuth Missing State Parameter',
                            'severity': 'high',
                            'url': test_url,
                            'evidence': 'OAuth flow proceeds without state parameter',
                            'description': 'State parameter not enforced, vulnerable to CSRF',
                            'cwe': 'CWE-352',
                            'impact': 'Cross-Site Request Forgery (CSRF) on OAuth flow',
                            'remediation': 'Require and validate state parameter in OAuth flow'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Missing state parameter vulnerability")
                        return

            except:
                pass

    def _test_open_redirect_callback(self, endpoints):
        """Test for open redirect in OAuth callback"""
        print("[*] Testing OAuth callback for open redirect...")

        for endpoint in endpoints:
            if 'callback' not in endpoint['path']:
                continue

            test_url = endpoint['url']

            # Test various redirect payloads in callback
            redirect_tests = [
                ('next', 'https://evil.com'),
                ('return', 'https://evil.com'),
                ('url', 'https://evil.com'),
                ('redirect', 'https://evil.com'),
                ('continue', 'https://evil.com'),
            ]

            for param_name, payload in redirect_tests:
                params = {
                    'code': 'test_auth_code',
                    'state': 'test_state',
                    param_name: payload
                }

                test_url_with_params = f"{test_url}?{urllib.parse.urlencode(params)}"

                try:
                    response = self.session.get(
                        test_url_with_params,
                        timeout=10,
                        allow_redirects=False
                    )

                    if response.status_code in [302, 303, 307, 308]:
                        location = response.headers.get('Location', '')

                        if 'evil.com' in location:
                            vuln = {
                                'type': 'Open Redirect in OAuth Callback',
                                'severity': 'high',
                                'url': test_url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': f'Redirect to: {location}',
                                'description': 'OAuth callback vulnerable to open redirect',
                                'cwe': 'CWE-601',
                                'impact': 'Phishing, token theft via open redirect',
                                'remediation': 'Validate redirect parameters in OAuth callback'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] Open redirect in OAuth callback via {param_name}")
                            return

                except:
                    pass

    def _test_token_theft(self, endpoints):
        """Test for token theft vulnerabilities"""
        print("[*] Testing for token theft vulnerabilities...")

        for endpoint in endpoints:
            if 'authorize' not in endpoint['path']:
                continue

            test_url = endpoint['url']

            # Test implicit flow (token in fragment)
            params = {
                'client_id': 'test_client',
                'redirect_uri': 'https://example.com/callback',
                'response_type': 'token',  # Implicit flow
                'scope': 'read',
                'state': 'test'
            }

            test_url_with_params = f"{test_url}?{urllib.parse.urlencode(params)}"

            try:
                response = self.session.get(
                    test_url_with_params,
                    timeout=10,
                    allow_redirects=False
                )

                # If implicit flow is allowed
                if response.status_code in [200, 302]:
                    if 'access_token' in response.text or 'token' in response.text:
                        vuln = {
                            'type': 'OAuth Implicit Flow Enabled',
                            'severity': 'medium',
                            'url': test_url,
                            'evidence': 'Implicit flow (response_type=token) is supported',
                            'description': 'Implicit flow exposes tokens in URL fragments',
                            'cwe': 'CWE-522',
                            'impact': 'Token leakage via browser history, referrer headers',
                            'remediation': 'Use authorization code flow instead of implicit flow'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Implicit flow enabled (token exposure risk)")

            except:
                pass

    def _test_scope_abuse(self, endpoints):
        """Test for scope abuse"""
        print("[*] Testing for scope abuse...")

        for endpoint in endpoints:
            if 'authorize' not in endpoint['path']:
                continue

            test_url = endpoint['url']

            # Test with excessive scopes
            dangerous_scopes = [
                'admin',
                'write:all',
                'delete:all',
                'root',
                '*',
                'full_access',
                'sudo',
            ]

            for scope in dangerous_scopes:
                params = {
                    'client_id': 'test_client',
                    'redirect_uri': 'https://example.com/callback',
                    'response_type': 'code',
                    'scope': scope,
                    'state': 'test'
                }

                test_url_with_params = f"{test_url}?{urllib.parse.urlencode(params)}"

                try:
                    response = self.session.get(
                        test_url_with_params,
                        timeout=10,
                        allow_redirects=False
                    )

                    # If dangerous scope is accepted without error
                    if response.status_code in [200, 302]:
                        error_indicators = ['invalid_scope', 'error', 'unauthorized']

                        if not any(indicator in response.text.lower() for indicator in error_indicators):
                            vuln = {
                                'type': 'OAuth Scope Abuse',
                                'severity': 'high',
                                'url': test_url,
                                'scope': scope,
                                'evidence': f'Dangerous scope "{scope}" accepted',
                                'description': 'Excessive OAuth scopes not properly validated',
                                'cwe': 'CWE-285',
                                'impact': 'Privilege escalation, excessive permissions',
                                'remediation': 'Implement strict scope validation and least privilege'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] Dangerous scope accepted: {scope}")

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
        print("Usage: python3 oauth_vulnerabilities.py <url> [output_file]")
        print("\nExample:")
        print("  python3 oauth_vulnerabilities.py https://example.com")
        print("  python3 oauth_vulnerabilities.py https://example.com results.json")
        print("\nTests for:")
        print("  - Redirect URI manipulation (token theft)")
        print("  - Missing state parameter (CSRF)")
        print("  - Open redirect in OAuth callback")
        print("  - Implicit flow vulnerabilities")
        print("  - OAuth scope abuse")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    scanner = OAuthVulnerabilityScanner(target, output)
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
        print(f"    Medium: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'medium')}")
