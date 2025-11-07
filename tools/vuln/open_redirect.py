#!/usr/bin/env python3
"""
Open Redirect Scanner
Tests for unvalidated redirect vulnerabilities
"""

import requests
import urllib.parse
import json
from datetime import datetime
from bs4 import BeautifulSoup
import re

class OpenRedirectScanner:
    """Open redirect vulnerability scanner"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        # Test payloads
        self.test_domain = "evil.com"
        self.payloads = [
            # Standard payloads
            f"http://{self.test_domain}",
            f"https://{self.test_domain}",
            f"//{self.test_domain}",
            f"\\\\{self.test_domain}",

            # Encoded payloads
            f"http%3A%2F%2F{self.test_domain}",
            f"https%3A%2F%2F{self.test_domain}",

            # With path
            f"http://{self.test_domain}/path",
            f"/{self.test_domain}",

            # JavaScript protocol
            f"javascript:alert(document.domain)//{self.test_domain}",

            # Bypass attempts
            f"http://localhost@{self.test_domain}",
            f"http://127.0.0.1@{self.test_domain}",
            f"http://{self.test_domain}@localhost",

            # With @ symbol
            f"@{self.test_domain}",
            f"http://example.com@{self.test_domain}",

            # Whitelisted domain bypass
            f"http://{self.test_domain}.example.com",
            f"http://example.com.{self.test_domain}",

            # Dot variations
            f"http://{self.test_domain}.",
            f"http://。{self.test_domain}",

            # Null byte
            f"http://example.com%00.{self.test_domain}",

            # CRLF
            f"http://example.com%0d%0aLocation:http://{self.test_domain}",

            # Backslashes
            f"http://example.com\\@{self.test_domain}",
            f"http:\\\\{self.test_domain}",
        ]

        # Common redirect parameters
        self.redirect_params = [
            'url', 'redirect', 'redirect_url', 'redirect_uri',
            'return', 'return_url', 'returnurl', 'return_to',
            'next', 'next_page', 'destination', 'dest',
            'continue', 'callback', 'success', 'failure',
            'link', 'target', 'redir', 'out', 'view',
            'to', 'goto', 'exit', 'checkout_url', 'return_path'
        ]

    def scan(self):
        """Run open redirect scan"""
        print(f"[*] Starting open redirect scan on {self.target_url}")

        # Test URL parameters
        self._test_url_parameters()

        # Test POST parameters
        self._test_post_parameters()

        # Test referer-based redirects
        self._test_referer_redirect()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_url_parameters(self):
        """Test URL parameters for open redirect"""
        print("[*] Testing URL parameters...")

        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)

        # If no params, try common redirect params
        if not params:
            params = {p: ['http://example.com'] for p in self.redirect_params[:5]}

        for param_name in params.keys():
            for payload in self.payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]

                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

                if self._test_redirect(test_url, param_name, payload, 'GET'):
                    return  # Found vulnerability

    def _test_post_parameters(self):
        """Test POST parameters for open redirect"""
        print("[*] Testing POST parameters...")

        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            if not forms:
                # Try common POST params anyway
                for param in self.redirect_params[:3]:
                    for payload in self.payloads[:5]:
                        data = {param: payload}
                        if self._test_post_redirect(self.target_url, data, param, payload):
                            return

            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').upper()

                if method != 'POST':
                    continue

                action_url = urllib.parse.urljoin(self.target_url, action) if action else self.target_url

                # Get form data
                form_data = {}
                inputs = form.find_all(['input', 'textarea'])
                for input_field in inputs:
                    name = input_field.get('name')
                    value = input_field.get('value', '')
                    if name:
                        form_data[name] = value

                # Test each field
                for field_name in form_data.keys():
                    for payload in self.payloads:
                        test_data = form_data.copy()
                        test_data[field_name] = payload

                        if self._test_post_redirect(action_url, test_data, field_name, payload):
                            return

        except Exception as e:
            pass

    def _test_referer_redirect(self):
        """Test referer-based redirects"""
        print("[*] Testing referer-based redirects...")

        for payload in self.payloads[:5]:
            headers = {'Referer': payload}

            try:
                response = self.session.get(
                    self.target_url,
                    headers=headers,
                    allow_redirects=False,
                    timeout=10
                )

                if self._is_redirect_response(response):
                    location = response.headers.get('Location', '')

                    if self._is_malicious_redirect(location):
                        vuln = {
                            'type': 'Open Redirect',
                            'severity': 'medium',
                            'url': self.target_url,
                            'parameter': 'Referer Header',
                            'payload': payload,
                            'redirect_location': location,
                            'evidence': 'Referer header influences redirect location',
                            'cwe': 'CWE-601'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Open redirect via Referer header!")
                        return True

            except Exception as e:
                pass

        return False

    def _test_redirect(self, url, param_name, payload, method):
        """Test single redirect payload"""
        try:
            response = self.session.get(
                url,
                allow_redirects=False,
                timeout=10
            )

            # Check for redirect response
            if self._is_redirect_response(response):
                location = response.headers.get('Location', '')

                if self._is_malicious_redirect(location):
                    vuln = {
                        'type': 'Open Redirect',
                        'severity': 'medium',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'redirect_location': location,
                        'method': method,
                        'evidence': f'Redirects to attacker-controlled domain: {location}',
                        'cwe': 'CWE-601'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Open redirect found: {param_name}")
                    return True

            # Check for meta refresh
            if self._has_meta_refresh(response.text):
                meta_url = self._extract_meta_refresh_url(response.text)
                if meta_url and self._is_malicious_redirect(meta_url):
                    vuln = {
                        'type': 'Open Redirect (Meta Refresh)',
                        'severity': 'medium',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'redirect_location': meta_url,
                        'method': method,
                        'evidence': 'Meta refresh redirects to attacker domain',
                        'cwe': 'CWE-601'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Open redirect (meta refresh) found!")
                    return True

            # Check for JavaScript redirect
            if self._has_js_redirect(response.text):
                js_url = self._extract_js_redirect_url(response.text)
                if js_url and self._is_malicious_redirect(js_url):
                    vuln = {
                        'type': 'Open Redirect (JavaScript)',
                        'severity': 'medium',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'redirect_location': js_url,
                        'method': method,
                        'evidence': 'JavaScript redirect to attacker domain',
                        'cwe': 'CWE-601'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Open redirect (JS) found!")
                    return True

        except Exception as e:
            pass

        return False

    def _test_post_redirect(self, url, data, field_name, payload):
        """Test POST redirect"""
        try:
            response = self.session.post(
                url,
                data=data,
                allow_redirects=False,
                timeout=10
            )

            if self._is_redirect_response(response):
                location = response.headers.get('Location', '')

                if self._is_malicious_redirect(location):
                    vuln = {
                        'type': 'Open Redirect',
                        'severity': 'medium',
                        'url': url,
                        'parameter': field_name,
                        'payload': payload,
                        'redirect_location': location,
                        'method': 'POST',
                        'evidence': 'POST request redirects to attacker domain',
                        'cwe': 'CWE-601'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Open redirect (POST) found!")
                    return True

        except Exception as e:
            pass

        return False

    def _is_redirect_response(self, response):
        """Check if response is a redirect"""
        return response.status_code in [301, 302, 303, 307, 308]

    def _is_malicious_redirect(self, location):
        """Check if redirect location is malicious"""
        if not location:
            return False

        location_lower = location.lower()

        # Check for our test domain
        if self.test_domain in location_lower:
            return True

        # Check for common bypass patterns
        malicious_patterns = [
            r'evil\.com',
            r'attacker\.com',
            r'@.*evil',
            r'//evil',
            r'\\\\evil'
        ]

        for pattern in malicious_patterns:
            if re.search(pattern, location_lower):
                return True

        return False

    def _has_meta_refresh(self, html):
        """Check for meta refresh redirect"""
        return 'http-equiv' in html.lower() and 'refresh' in html.lower()

    def _extract_meta_refresh_url(self, html):
        """Extract URL from meta refresh"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            meta = soup.find('meta', attrs={'http-equiv': re.compile('refresh', re.I)})
            if meta:
                content = meta.get('content', '')
                # Format: "0;URL=http://example.com"
                match = re.search(r'url\s*=\s*["\']?([^"\'>\s]+)', content, re.I)
                if match:
                    return match.group(1)
        except:
            pass
        return None

    def _has_js_redirect(self, html):
        """Check for JavaScript redirect"""
        js_patterns = [
            r'window\.location',
            r'location\.href',
            r'location\.replace',
            r'location\.assign'
        ]
        for pattern in js_patterns:
            if re.search(pattern, html, re.I):
                return True
        return False

    def _extract_js_redirect_url(self, html):
        """Extract URL from JavaScript redirect"""
        patterns = [
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'location\.replace\(["\']([^"\']+)["\']\)',
            r'location\.assign\(["\']([^"\']+)["\']\)'
        ]

        for pattern in patterns:
            match = re.search(pattern, html, re.I)
            if match:
                return match.group(1)

        return None

    def _save_results(self):
        """Save results to file"""
        results = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total': len(self.vulnerabilities),
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
        print("Usage: python3 open_redirect.py <url>")
        print("\nExample:")
        print("  python3 open_redirect.py https://example.com/redirect?url=http://test.com")
        sys.exit(1)

    scanner = OpenRedirectScanner(sys.argv[1])
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")
