#!/usr/bin/env python3
"""
Information Disclosure Scanner
Detects information leakage through error messages, comments, API documentation,
and server headers that reveal sensitive technical details
"""

import requests
import json
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

class InformationDisclosureScanner:
    """Scanner for information disclosure vulnerabilities"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def scan(self):
        """Run information disclosure scanning"""
        print(f"[*] Starting information disclosure scanning on {self.target_url}")

        # Test error messages
        self._test_error_messages()

        # Test HTML/JS comments
        self._test_comments()

        # Test API documentation
        self._test_api_documentation()

        # Test server headers
        self._test_server_headers()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_error_messages(self):
        """Test for verbose error messages and stack traces"""
        print("[*] Testing for error messages and stack traces...")

        # Trigger errors with malformed input
        error_triggers = [
            ('?id=', 'Invalid query parameter'),
            ('?id=\'', 'SQL error'),
            ('?id=1/0', 'Division by zero'),
            ('?page=../../../etc/passwd', 'Path traversal error'),
            ('?file=', 'Empty file parameter'),
            ('/nonexistent', 'File not found'),
            ('/admin', '403 Forbidden'),
        ]

        for trigger, description in error_triggers:
            if trigger.startswith('/'):
                test_url = urljoin(self.target_url, trigger)
            else:
                test_url = self.target_url + trigger

            try:
                response = self.session.get(test_url, timeout=10)

                # Check for stack traces and detailed errors
                error_patterns = [
                    (r'Stack trace:', 'Stack trace'),
                    (r'Fatal error:', 'Fatal error'),
                    (r'Warning: .*? in .*? on line \d+', 'PHP warning with file path'),
                    (r'Traceback \(most recent call last\):', 'Python traceback'),
                    (r'Exception in thread', 'Java exception'),
                    (r'at [\w.]+\([\w.]+:\d+\)', 'Java stack trace'),
                    (r'System\..*?Exception:', '.NET exception'),
                    (r'server error in.*?application', 'ASP.NET error'),
                    (r'Microsoft OLE DB Provider', 'Database error'),
                    (r'ODBC.*?error', 'ODBC error'),
                    (r'SQL syntax.*?MySQL', 'MySQL error'),
                    (r'PostgreSQL.*?ERROR', 'PostgreSQL error'),
                    (r'Oracle.*?error', 'Oracle error'),
                    (r'<b>Notice</b>:.*?<b>', 'PHP notice'),
                    (r'<b>Warning</b>:.*?<b>', 'PHP warning'),
                ]

                for pattern, error_type in error_patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE | re.MULTILINE)
                    if matches:
                        evidence = matches[0][:200] if matches else error_type

                        vuln = {
                            'type': 'Information Disclosure - Error Message',
                            'severity': 'medium',
                            'url': test_url,
                            'error_type': error_type,
                            'evidence': f'{error_type} detected: {evidence}',
                            'description': 'Application exposes detailed error messages',
                            'cwe': 'CWE-209',
                            'impact': 'Internal path disclosure, technology stack exposure',
                            'remediation': 'Implement custom error pages, disable debug mode'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Error message found: {error_type}")
                        return

            except:
                pass

    def _test_comments(self):
        """Test for sensitive information in HTML/JavaScript comments"""
        print("[*] Testing for comments with sensitive information...")

        try:
            response = self.session.get(self.target_url, timeout=10)

            if response.status_code == 200:
                # Parse HTML
                soup = BeautifulSoup(response.text, 'html.parser')

                # Find HTML comments
                html_comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))

                # Sensitive patterns in comments
                sensitive_patterns = [
                    (r'password|passwd|pwd', 'Password reference'),
                    (r'api[_-]?key|apikey', 'API key reference'),
                    (r'secret|token', 'Secret/token reference'),
                    (r'admin|administrator', 'Admin reference'),
                    (r'debug|test|todo|fixme|hack', 'Development comment'),
                    (r'username|user|email', 'Username/email'),
                    (r'database|db|sql', 'Database reference'),
                    (r'//', 'URL or path'),
                    (r'http://|https://', 'Internal URL'),
                ]

                for comment in html_comments:
                    comment_text = str(comment)

                    for pattern, info_type in sensitive_patterns:
                        if re.search(pattern, comment_text, re.IGNORECASE):
                            vuln = {
                                'type': 'Information Disclosure - HTML Comment',
                                'severity': 'low',
                                'url': self.target_url,
                                'info_type': info_type,
                                'evidence': f'Comment contains {info_type}: {comment_text[:200]}',
                                'description': 'HTML comments contain sensitive information',
                                'cwe': 'CWE-615',
                                'impact': 'Information leakage, developer notes exposed',
                                'remediation': 'Remove sensitive comments from production code'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] Sensitive comment found: {info_type}")
                            break

                # Check JavaScript for comments and hardcoded credentials
                scripts = soup.find_all('script')
                for script in scripts:
                    if script.string:
                        js_code = script.string

                        # Check for JavaScript comments
                        js_comment_patterns = [
                            r'//.*?(password|api|key|secret|token)',
                            r'/\*.*?(password|api|key|secret|token).*?\*/',
                        ]

                        for pattern in js_comment_patterns:
                            matches = re.findall(pattern, js_code, re.IGNORECASE | re.DOTALL)
                            if matches:
                                vuln = {
                                    'type': 'Information Disclosure - JavaScript Comment',
                                    'severity': 'low',
                                    'url': self.target_url,
                                    'evidence': f'JavaScript comment contains sensitive data: {str(matches[0])[:200]}',
                                    'description': 'JavaScript comments contain sensitive information',
                                    'cwe': 'CWE-615',
                                    'impact': 'Credential or key exposure',
                                    'remediation': 'Remove comments, use build process to strip them'
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"[!] Sensitive JS comment found")
                                break

        except:
            pass

    def _test_api_documentation(self):
        """Test for exposed API documentation"""
        print("[*] Testing for exposed API documentation...")

        # Common API documentation endpoints
        doc_endpoints = [
            '/api/docs',
            '/api/documentation',
            '/api',
            '/swagger',
            '/swagger-ui',
            '/swagger-ui.html',
            '/swagger/index.html',
            '/api/swagger.json',
            '/api/swagger.yaml',
            '/v1/api-docs',
            '/v2/api-docs',
            '/api-docs',
            '/docs',
            '/graphql',
            '/graphiql',
            '/playground',
            '/__graphql',
            '/api/graphql',
            '/redoc',
            '/openapi.json',
            '/openapi.yaml',
        ]

        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in doc_endpoints:
            test_url = urljoin(base_url, endpoint)

            try:
                response = self.session.get(test_url, timeout=10)

                if response.status_code == 200:
                    # Check for API documentation indicators
                    doc_indicators = [
                        ('swagger', 'Swagger UI'),
                        ('openapi', 'OpenAPI'),
                        ('graphql', 'GraphQL'),
                        ('graphiql', 'GraphiQL'),
                        ('redoc', 'ReDoc'),
                        ('api documentation', 'API Docs'),
                        ('"paths":', 'OpenAPI Schema'),
                        ('"query":', 'GraphQL Schema'),
                    ]

                    for indicator, doc_type in doc_indicators:
                        if indicator in response.text.lower():
                            # Try to count endpoints
                            endpoint_count = response.text.count('"path"') + response.text.count('endpoint')

                            vuln = {
                                'type': 'Exposed API Documentation',
                                'severity': 'medium',
                                'url': test_url,
                                'doc_type': doc_type,
                                'evidence': f'{doc_type} documentation accessible - ~{endpoint_count} endpoints found',
                                'description': 'API documentation is publicly accessible',
                                'cwe': 'CWE-200',
                                'impact': 'API schema disclosure, easier to find vulnerabilities',
                                'remediation': 'Restrict access to documentation in production'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] API documentation found: {doc_type}")
                            return

            except:
                pass

    def _test_server_headers(self):
        """Test for information disclosure in server headers"""
        print("[*] Testing server headers for version disclosure...")

        try:
            response = self.session.get(self.target_url, timeout=10)

            headers = response.headers

            # Check for version disclosure in headers
            disclosure_headers = {
                'Server': 'Web server',
                'X-Powered-By': 'Technology stack',
                'X-AspNet-Version': 'ASP.NET version',
                'X-AspNetMvc-Version': 'ASP.NET MVC version',
                'X-Generator': 'CMS/framework',
                'X-Runtime': 'Runtime information',
            }

            for header, description in disclosure_headers.items():
                if header in headers:
                    value = headers[header]

                    # Check if version info is present
                    if re.search(r'\d+\.\d+', value):
                        vuln = {
                            'type': 'Information Disclosure - Server Header',
                            'severity': 'low',
                            'url': self.target_url,
                            'header': header,
                            'value': value,
                            'evidence': f'{header}: {value}',
                            'description': f'{description} version disclosed in headers',
                            'cwe': 'CWE-200',
                            'impact': 'Technology fingerprinting, targeted attacks',
                            'remediation': 'Remove or obfuscate version information in headers'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Version disclosure in {header}: {value}")

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
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'medium'),
                'low': sum(1 for v in self.vulnerabilities if v['severity'] == 'low')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 information_disclosure.py <url> [output_file]")
        print("\nExample:")
        print("  python3 information_disclosure.py https://example.com")
        print("\nScans for:")
        print("  - Error messages and stack traces")
        print("  - Sensitive information in HTML/JS comments")
        print("  - Exposed API documentation (Swagger, GraphQL)")
        print("  - Version disclosure in server headers")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    scanner = InformationDisclosureScanner(target, output)
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Medium: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'medium')}")
        print(f"    Low: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'low')}")
