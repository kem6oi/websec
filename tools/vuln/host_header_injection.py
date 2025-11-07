#!/usr/bin/env python3
"""
Host Header Injection Scanner
Tests for Host header injection vulnerabilities
"""

import requests
import json
import re
from datetime import datetime
from urllib.parse import urlparse

class HostHeaderInjectionScanner:
    """Host header injection vulnerability scanner"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        parsed = urlparse(target_url)
        self.original_host = parsed.netloc

        # Host header injection payloads
        self.payloads = [
            # Basic injection
            'evil.com',
            'attacker.com',
            'localhost',
            '127.0.0.1',

            # Port manipulation
            f'{self.original_host}:8080',
            f'{self.original_host}:22',

            # Absolute URL
            f'http://evil.com',
            f'https://evil.com',

            # Inject with original host
            f'{self.original_host}.evil.com',
            f'evil.com#{self.original_host}',
            f'evil.com@{self.original_host}',

            # SSRF attempts
            'localhost:22',
            'localhost:25',
            '0.0.0.0',
            '127.0.0.1:25',

            # XSS in Host header
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',

            # Bypass attempts
            f'{self.original_host} evil.com',
            f'{self.original_host}\\tevil.com',
            f'{self.original_host}%20evil.com',

            # Null byte injection
            f'{self.original_host}%00.evil.com',

            # Unicode/encoding
            'evil。com',
            'evil%2ecom',
        ]

        # Additional headers to test
        self.alternative_headers = [
            'X-Forwarded-Host',
            'X-Host',
            'X-Forwarded-Server',
            'X-HTTP-Host-Override',
            'Forwarded',
        ]

    def scan(self):
        """Run host header injection scan"""
        print(f"[*] Starting Host header injection scan on {self.target_url}")
        print(f"[*] Original host: {self.original_host}")

        # Get baseline response
        baseline = self._get_baseline()

        # Test Host header
        self._test_host_header(baseline)

        # Test alternative headers
        self._test_alternative_headers(baseline)

        # Test password reset poisoning
        self._test_password_reset()

        # Test cache poisoning
        self._test_cache_poisoning(baseline)

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _get_baseline(self):
        """Get baseline response"""
        try:
            return self.session.get(self.target_url, timeout=10)
        except Exception as e:
            print(f"[!] Error getting baseline: {e}")
            return None

    def _test_host_header(self, baseline):
        """Test Host header manipulation"""
        print("[*] Testing Host header manipulation...")

        for payload in self.payloads:
            try:
                # Create custom headers with modified Host
                headers = {
                    'Host': payload,
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
                }

                response = self.session.get(
                    self.target_url,
                    headers=headers,
                    timeout=10,
                    allow_redirects=False
                )

                self._check_vulnerability(response, 'Host', payload, baseline)

            except Exception as e:
                pass

    def _test_alternative_headers(self, baseline):
        """Test alternative host-related headers"""
        print("[*] Testing alternative headers...")

        for header in self.alternative_headers:
            for payload in self.payloads[:10]:  # Test subset
                try:
                    headers = {
                        header: payload,
                        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
                    }

                    response = self.session.get(
                        self.target_url,
                        headers=headers,
                        timeout=10,
                        allow_redirects=False
                    )

                    self._check_vulnerability(response, header, payload, baseline)

                except Exception as e:
                    pass

    def _test_password_reset(self):
        """Test for password reset poisoning"""
        print("[*] Testing password reset poisoning...")

        # Look for password reset endpoints
        reset_endpoints = [
            '/reset-password',
            '/forgot-password',
            '/password/reset',
            '/password/forgot',
            '/api/password/reset',
            '/auth/reset',
            '/account/password/reset',
        ]

        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in reset_endpoints:
            test_url = base_url + endpoint

            try:
                # Test with evil.com in Host header
                headers = {
                    'Host': 'evil.com',
                    'User-Agent': 'Mozilla/5.0'
                }

                response = self.session.get(test_url, headers=headers, timeout=10)

                if response.status_code == 200:
                    # Check if evil.com appears in response
                    if 'evil.com' in response.text:
                        vuln = {
                            'type': 'Host Header Injection (Password Reset Poisoning)',
                            'severity': 'high',
                            'url': test_url,
                            'header': 'Host',
                            'payload': 'evil.com',
                            'evidence': 'Injected host appears in password reset page',
                            'description': 'Password reset emails may be poisoned with attacker domain',
                            'cwe': 'CWE-644',
                            'impact': 'Password reset token theft, account takeover'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Password reset poisoning possible at {endpoint}")
                        return

            except:
                pass

    def _test_cache_poisoning(self, baseline):
        """Test for cache poisoning via Host header"""
        print("[*] Testing cache poisoning...")

        if not baseline:
            return

        # Test with unique identifier
        unique_payload = f'cache-test-{datetime.now().timestamp()}.evil.com'

        try:
            headers = {'Host': unique_payload}

            # Make first request
            response1 = self.session.get(
                self.target_url,
                headers=headers,
                timeout=10
            )

            # Check cache headers
            cache_headers = ['X-Cache', 'Cache-Control', 'CF-Cache-Status', 'X-Cache-Hits']
            has_cache = any(h in response1.headers for h in cache_headers)

            if has_cache and unique_payload in response1.text:
                vuln = {
                    'type': 'Host Header Injection (Cache Poisoning)',
                    'severity': 'critical',
                    'url': self.target_url,
                    'header': 'Host',
                    'payload': unique_payload,
                    'evidence': f'Injected host in cached response. Cache headers: {[h for h in cache_headers if h in response1.headers]}',
                    'description': 'Host header injection with caching enables mass poisoning',
                    'cwe': 'CWE-644',
                    'impact': 'Mass XSS, phishing, all users affected'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] CRITICAL: Cache poisoning possible!")

        except:
            pass

    def _check_vulnerability(self, response, header, payload, baseline):
        """Check for host header injection vulnerability"""

        # Check if payload appears in response
        if payload in response.text:
            # Check in various contexts
            contexts = []

            # Check in links
            link_pattern = f'href=["\']([^"\']*{re.escape(payload)}[^"\']*)["\']'
            links = re.findall(link_pattern, response.text, re.IGNORECASE)
            if links:
                contexts.append(f'Links: {links[:3]}')

            # Check in script src
            script_pattern = f'src=["\']([^"\']*{re.escape(payload)}[^"\']*)["\']'
            scripts = re.findall(script_pattern, response.text, re.IGNORECASE)
            if scripts:
                contexts.append(f'Script sources: {scripts[:3]}')

            # Check in meta tags
            if '<meta' in response.text and payload in response.text:
                contexts.append('Meta tags')

            # Check in Location header
            location = response.headers.get('Location', '')
            if payload in location:
                contexts.append(f'Location header: {location}')

            if contexts:
                severity = 'critical' if header == 'Host' else 'high'

                vuln = {
                    'type': 'Host Header Injection',
                    'severity': severity,
                    'url': self.target_url,
                    'header': header,
                    'payload': payload,
                    'evidence': '; '.join(contexts),
                    'description': 'Injected host header appears in response',
                    'cwe': 'CWE-644',
                    'impact': 'XSS, password reset poisoning, SSRF, cache poisoning'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] Host header injection found via {header}")
                return True

        # Check for redirect to injected host
        location = response.headers.get('Location', '')
        if location and payload in location:
            vuln = {
                'type': 'Host Header Injection (Redirect)',
                'severity': 'high',
                'url': self.target_url,
                'header': header,
                'payload': payload,
                'evidence': f'Redirect to: {location}',
                'description': 'Server redirects to injected host',
                'cwe': 'CWE-644',
                'impact': 'Open redirect, phishing'
            }
            self.vulnerabilities.append(vuln)
            print(f"[!] Host header redirect via {header}")
            return True

        # Check for SSRF indicators (localhost, internal IPs)
        if payload in ['localhost', '127.0.0.1', '0.0.0.0']:
            if baseline and response.text != baseline.text:
                # Different response when using localhost
                if 'SSH' in response.text or 'SMTP' in response.text or 'root@' in response.text:
                    vuln = {
                        'type': 'Host Header Injection (SSRF)',
                        'severity': 'critical',
                        'url': self.target_url,
                        'header': header,
                        'payload': payload,
                        'evidence': 'Different response with localhost, possible SSRF',
                        'description': 'Server makes request to localhost',
                        'cwe': 'CWE-918',
                        'impact': 'SSRF, access to internal services'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Possible SSRF via {header}")
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
                'critical': sum(1 for v in self.vulnerabilities if v['severity'] == 'critical'),
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 host_header_injection.py <url>")
        print("\nExample:")
        print("  python3 host_header_injection.py https://example.com")
        print("\nTests for:")
        print("  - Host header manipulation")
        print("  - Alternative headers (X-Forwarded-Host, etc.)")
        print("  - Password reset poisoning")
        print("  - Cache poisoning")
        print("  - SSRF via Host header")
        sys.exit(1)

    scanner = HostHeaderInjectionScanner(sys.argv[1])
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")

    if len(results['vulnerabilities']) > 0:
        print(f"\n[!] Host header injection vulnerabilities detected!")
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
