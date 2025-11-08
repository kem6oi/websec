#!/usr/bin/env python3
"""
REST API Fuzzer
Tests for REST API vulnerabilities including HTTP verb tampering,
content-type confusion, and API versioning bypass
"""

import requests
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse, urljoin, urlencode

class RestAPIFuzzer:
    """REST API security fuzzer"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def scan(self):
        """Run REST API fuzzing tests"""
        print(f"[*] Starting REST API fuzzing on {self.target_url}")

        # Test HTTP verb tampering
        self._test_http_verb_tampering()

        # Test content-type confusion
        self._test_content_type_confusion()

        # Test API versioning bypass
        self._test_api_versioning()

        # Test method override headers
        self._test_method_override()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_http_verb_tampering(self):
        """Test HTTP verb tampering"""
        print("[*] Testing HTTP verb tampering...")

        # HTTP methods to test
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']

        # Get baseline
        try:
            baseline = self.session.get(self.target_url, timeout=10, allow_redirects=False)
            baseline_status = baseline.status_code
        except:
            baseline_status = 0

        for method in methods:
            try:
                if method == 'GET':
                    response = self.session.get(self.target_url, timeout=10, allow_redirects=False)
                elif method == 'POST':
                    response = self.session.post(self.target_url, json={}, timeout=10, allow_redirects=False)
                elif method == 'PUT':
                    response = self.session.put(self.target_url, json={}, timeout=10, allow_redirects=False)
                elif method == 'DELETE':
                    response = self.session.delete(self.target_url, timeout=10, allow_redirects=False)
                elif method == 'PATCH':
                    response = self.session.patch(self.target_url, json={}, timeout=10, allow_redirects=False)
                elif method == 'HEAD':
                    response = self.session.head(self.target_url, timeout=10, allow_redirects=False)
                elif method == 'OPTIONS':
                    response = self.session.options(self.target_url, timeout=10, allow_redirects=False)
                elif method == 'TRACE':
                    response = self.session.request('TRACE', self.target_url, timeout=10, allow_redirects=False)
                else:
                    continue

                # Check if different verb gives different access
                if response.status_code == 200 and baseline_status in [401, 403, 405]:
                    vuln = {
                        'type': 'HTTP Verb Tampering',
                        'severity': 'high',
                        'url': self.target_url,
                        'method': method,
                        'evidence': f'{method} returns 200, baseline {baseline_status}',
                        'description': f'Endpoint accessible via {method} verb',
                        'cwe': 'CWE-749',
                        'impact': 'Bypass access controls, unauthorized actions',
                        'remediation': 'Implement method-based access control'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] HTTP verb tampering: {method} bypasses controls")
                    return

                # Check for TRACE method (XST)
                if method == 'TRACE' and response.status_code == 200:
                    if self.target_url in response.text or 'TRACE' in response.text:
                        vuln = {
                            'type': 'HTTP TRACE Method Enabled',
                            'severity': 'medium',
                            'url': self.target_url,
                            'evidence': 'TRACE method reflects request',
                            'description': 'TRACE method enabled (Cross-Site Tracing)',
                            'cwe': 'CWE-693',
                            'impact': 'XST attacks, steal HttpOnly cookies',
                            'remediation': 'Disable TRACE method'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] TRACE method enabled")

            except:
                pass

    def _test_content_type_confusion(self):
        """Test content-type confusion"""
        print("[*] Testing content-type confusion...")

        test_data = {'test': 'data', 'value': '123'}

        # Content types to test
        content_types = [
            ('application/json', json.dumps(test_data)),
            ('application/xml', '<root><test>data</test><value>123</value></root>'),
            ('application/x-www-form-urlencoded', urlencode(test_data)),
            ('text/xml', '<?xml version="1.0"?><root><test>data</test></root>'),
            ('text/plain', str(test_data)),
            ('multipart/form-data', str(test_data)),
        ]

        for content_type, data in content_types:
            try:
                headers = {'Content-Type': content_type}
                response = self.session.post(self.target_url, data=data, headers=headers, timeout=10)

                if response.status_code in [200, 201]:
                    # Check if unexpected content-type was accepted
                    if 'json' not in content_type.lower():
                        vuln = {
                            'type': 'Content-Type Confusion',
                            'severity': 'medium',
                            'url': self.target_url,
                            'content_type': content_type,
                            'evidence': f'{content_type} accepted (status: {response.status_code})',
                            'description': 'API accepts unexpected content types',
                            'cwe': 'CWE-436',
                            'impact': 'Parser confusion, injection attacks',
                            'remediation': 'Strictly validate Content-Type header'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Content-type confusion: {content_type}")
                        return

            except:
                pass

    def _test_api_versioning(self):
        """Test API versioning bypass"""
        print("[*] Testing API versioning bypass...")

        parsed = urlparse(self.target_url)
        path = parsed.path

        # Version patterns to test
        version_tests = []

        # If path contains version
        if '/v1/' in path:
            version_tests.append(('/v2/', 'v2'))
            version_tests.append(('/v3/', 'v3'))
            version_tests.append(('/internal/', 'internal'))
            version_tests.append(('/admin/', 'admin'))
        elif '/v2/' in path:
            version_tests.append(('/v1/', 'v1'))
            version_tests.append(('/v3/', 'v3'))
            version_tests.append(('/internal/', 'internal'))
        elif '/api/' in path:
            version_tests.append(('/api/v1/', 'v1'))
            version_tests.append(('/api/v2/', 'v2'))
            version_tests.append(('/api/internal/', 'internal'))

        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for version_path, version_name in version_tests:
            # Replace version in path
            if '/v1/' in path:
                new_path = path.replace('/v1/', version_path)
            elif '/v2/' in path:
                new_path = path.replace('/v2/', version_path)
            elif '/api/' in path and version_path.startswith('/api/'):
                new_path = path.replace('/api/', version_path)
            else:
                continue

            test_url = urljoin(base_url, new_path)

            try:
                response = self.session.get(test_url, timeout=10, allow_redirects=False)

                if response.status_code == 200:
                    vuln = {
                        'type': 'API Versioning Bypass',
                        'severity': 'medium',
                        'url': test_url,
                        'version': version_name,
                        'evidence': f'Accessible via {version_name} version',
                        'description': f'API endpoint accessible via different version ({version_name})',
                        'cwe': 'CWE-284',
                        'impact': 'Access deprecated/internal APIs',
                        'remediation': 'Properly deprecate and protect old API versions'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] API versioning bypass: {version_name}")
                    return

            except:
                pass

    def _test_method_override(self):
        """Test method override headers"""
        print("[*] Testing method override headers...")

        # Method override headers
        override_headers = [
            'X-HTTP-Method-Override',
            'X-Method-Override',
            'X-HTTP-Method',
        ]

        # Methods to try overriding to
        override_methods = ['PUT', 'DELETE', 'PATCH']

        for header in override_headers:
            for method in override_methods:
                try:
                    headers = {header: method}
                    response = self.session.post(self.target_url, headers=headers, json={}, timeout=10, allow_redirects=False)

                    # Check if override worked
                    if response.status_code in [200, 201, 204]:
                        # Check for signs that override worked
                        if method == 'DELETE':
                            if 'deleted' in response.text.lower() or 'removed' in response.text.lower():
                                vuln = {
                                    'type': 'HTTP Method Override',
                                    'severity': 'high',
                                    'url': self.target_url,
                                    'header': header,
                                    'method': method,
                                    'evidence': f'POST with {header}: {method} executed',
                                    'description': 'HTTP method override allows privilege escalation',
                                    'cwe': 'CWE-749',
                                    'impact': 'Execute unauthorized methods',
                                    'remediation': 'Disable method override headers'
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"[!] Method override: {header} -> {method}")
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
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high'),
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'medium')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 rest_api_fuzzer.py <api_url> [output_file]")
        print("\nExample:")
        print("  python3 rest_api_fuzzer.py https://api.example.com/v1/users")
        print("\nTests for:")
        print("  - HTTP verb tampering (GET/POST/PUT/DELETE)")
        print("  - Content-Type confusion (JSON/XML/Form)")
        print("  - API versioning bypass (/v1/ -> /v2/ -> /internal/)")
        print("  - Method override headers")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    fuzzer = RestAPIFuzzer(target, output)
    results = fuzzer.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
        print(f"    Medium: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'medium')}")
