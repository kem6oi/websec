#!/usr/bin/env python3
"""
BOLA/IDOR Tester (Broken Object Level Authorization / Insecure Direct Object References)
Tests for authorization bypass vulnerabilities
"""

import requests
import json
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import itertools

class BOLATester:
    """BOLA/IDOR vulnerability tester"""

    def __init__(self, target_url, auth_token=None, output_file=None):
        self.target_url = target_url
        self.auth_token = auth_token
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        if auth_token:
            self.session.headers.update({'Authorization': f'Bearer {auth_token}'})

    def scan(self):
        """Run BOLA/IDOR scan"""
        print(f"[*] Starting BOLA/IDOR scan on {self.target_url}")

        # Extract IDs from URL
        ids = self._extract_ids_from_url()

        if ids:
            print(f"[*] Found {len(ids)} potential ID parameters")

            # Test for IDOR
            self._test_sequential_idor(ids)
            self._test_unauthorized_access()
            self._test_horizontal_privilege_escalation(ids)
            self._test_uuid_enumeration(ids)
        else:
            print("[!] No ID parameters found in URL")
            self._test_unauthorized_access()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _extract_ids_from_url(self):
        """Extract potential ID parameters from URL"""
        parsed = urlparse(self.target_url)
        ids = {}

        # Check query parameters
        params = parse_qs(parsed.query)
        for key, value in params.items():
            if any(term in key.lower() for term in ['id', 'user', 'uid', 'account', 'profile', 'doc', 'file']):
                ids[key] = value[0]

        # Check path segments that look like IDs
        path_parts = [p for p in parsed.path.split('/') if p]
        for i, part in enumerate(path_parts):
            # Numeric IDs
            if part.isdigit():
                ids[f'path_segment_{i}'] = part
            # UUID pattern
            elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', part, re.I):
                ids[f'uuid_segment_{i}'] = part
            # Alphanumeric IDs
            elif len(part) > 8 and part.isalnum():
                ids[f'alphanum_segment_{i}'] = part

        return ids

    def _test_sequential_idor(self, ids):
        """Test for sequential IDOR vulnerabilities"""
        print("[*] Testing for sequential IDOR...")

        for key, value in ids.items():
            if value.isdigit():
                original_id = int(value)

                # Try adjacent IDs
                test_ids = [
                    original_id - 2,
                    original_id - 1,
                    original_id + 1,
                    original_id + 2,
                    1,  # First user
                    100,  # Common test ID
                ]

                for test_id in test_ids:
                    if test_id == original_id:
                        continue

                    # Get baseline (original ID)
                    baseline = self._make_request(key, str(original_id))
                    if not baseline:
                        continue

                    # Test with different ID
                    test_response = self._make_request(key, str(test_id))

                    if test_response and test_response.status_code == 200:
                        # Check if we got different data
                        if self._is_different_object(baseline, test_response):
                            vuln = {
                                'type': 'IDOR - Sequential Access',
                                'severity': 'critical',
                                'url': self.target_url,
                                'parameter': key,
                                'original_id': str(original_id),
                                'accessed_id': str(test_id),
                                'evidence': f'Able to access object {test_id} when authenticated for {original_id}',
                                'cwe': 'CWE-639',
                                'owasp_api': 'API1:2023 Broken Object Level Authorization'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] CRITICAL: IDOR found! Accessed ID {test_id}")
                            return  # Found one, that's enough

    def _test_unauthorized_access(self):
        """Test access without authentication"""
        print("[*] Testing unauthorized access...")

        # Save original auth
        original_auth = self.session.headers.get('Authorization')

        # Remove auth
        if 'Authorization' in self.session.headers:
            del self.session.headers['Authorization']

        try:
            response = self.session.get(self.target_url, timeout=10)

            if response.status_code == 200:
                # Check if we got sensitive data
                if len(response.text) > 100:
                    vuln = {
                        'type': 'Missing Authorization',
                        'severity': 'critical',
                        'url': self.target_url,
                        'evidence': 'Endpoint accessible without authentication',
                        'status_code': response.status_code,
                        'cwe': 'CWE-284',
                        'owasp_api': 'API1:2023 Broken Object Level Authorization'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] CRITICAL: Endpoint accessible without auth!")

        except Exception as e:
            pass
        finally:
            # Restore auth
            if original_auth:
                self.session.headers['Authorization'] = original_auth

    def _test_horizontal_privilege_escalation(self, ids):
        """Test for horizontal privilege escalation"""
        print("[*] Testing horizontal privilege escalation...")

        # Test with commonly used test IDs
        test_user_ids = ['admin', 'administrator', 'root', 'test', 'demo', 'guest']

        for key, value in ids.items():
            for test_id in test_user_ids:
                if test_id.lower() == value.lower():
                    continue

                response = self._make_request(key, test_id)

                if response and response.status_code == 200:
                    vuln = {
                        'type': 'BOLA - Horizontal Privilege Escalation',
                        'severity': 'critical',
                        'url': self.target_url,
                        'parameter': key,
                        'original_id': value,
                        'accessed_id': test_id,
                        'evidence': f'Accessed different user account: {test_id}',
                        'cwe': 'CWE-639'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] CRITICAL: Accessed other user: {test_id}")
                    return

    def _test_uuid_enumeration(self, ids):
        """Test UUID enumeration"""
        print("[*] Testing UUID enumeration...")

        for key, value in ids.items():
            # Check if it's a UUID
            if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
                # Try incrementing the UUID
                uuid_parts = value.split('-')

                # Try modifying last segment
                try:
                    last_part = int(uuid_parts[-1], 16)
                    new_last = hex(last_part + 1)[2:].zfill(12)
                    test_uuid = '-'.join(uuid_parts[:-1] + [new_last])

                    response = self._make_request(key, test_uuid)

                    if response and response.status_code == 200:
                        vuln = {
                            'type': 'UUID Enumeration',
                            'severity': 'high',
                            'url': self.target_url,
                            'parameter': key,
                            'original_uuid': value,
                            'accessed_uuid': test_uuid,
                            'evidence': 'Sequential UUID enumeration possible',
                            'cwe': 'CWE-639'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] UUID enumeration possible!")

                except Exception as e:
                    pass

    def _test_parameter_pollution(self, ids):
        """Test for HTTP parameter pollution"""
        print("[*] Testing parameter pollution...")

        for key, value in ids.items():
            if 'path_segment' not in key:
                # Try adding multiple values for same parameter
                test_ids = ['1', '2', 'admin', value]

                for id1, id2 in itertools.combinations(test_ids, 2):
                    parsed = urlparse(self.target_url)
                    params = parse_qs(parsed.query)
                    params[key] = [id1, id2]

                    # Reconstruct URL with duplicate params
                    query = '&'.join([f"{k}={v}" for k, vals in params.items() for v in vals])
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, query, parsed.fragment
                    ))

                    try:
                        response = self.session.get(test_url, timeout=10)

                        if response.status_code == 200:
                            vuln = {
                                'type': 'Parameter Pollution',
                                'severity': 'medium',
                                'url': test_url,
                                'parameter': key,
                                'values': [id1, id2],
                                'evidence': 'Multiple parameter values processed',
                                'cwe': 'CWE-235'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] Parameter pollution possible!")
                            return

                    except Exception as e:
                        pass

    def _make_request(self, param_key, param_value):
        """Make request with modified parameter"""
        try:
            if 'path_segment' in param_key:
                # Modify path segment
                parsed = urlparse(self.target_url)
                path_parts = parsed.path.split('/')

                segment_index = int(param_key.split('_')[-1])
                if segment_index < len(path_parts):
                    path_parts[segment_index] = param_value
                    new_path = '/'.join(path_parts)

                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, new_path,
                        parsed.params, parsed.query, parsed.fragment
                    ))
            else:
                # Modify query parameter
                parsed = urlparse(self.target_url)
                params = parse_qs(parsed.query)
                params[param_key] = [param_value]

                query = urlencode(params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, query, parsed.fragment
                ))

            response = self.session.get(test_url, timeout=10)
            return response

        except Exception as e:
            return None

    def _is_different_object(self, response1, response2):
        """Check if two responses contain different objects"""
        if response1.status_code != response2.status_code:
            return True

        # Compare content length
        if abs(len(response1.text) - len(response2.text)) > 50:
            return True

        # Try to parse as JSON and compare
        try:
            json1 = response1.json()
            json2 = response2.json()

            # Look for ID fields
            id_fields = ['id', 'user_id', 'uid', 'username', 'email', 'name']

            for field in id_fields:
                if field in json1 and field in json2:
                    if json1[field] != json2[field]:
                        return True

            # Compare entire JSON
            return json1 != json2

        except:
            # Not JSON, compare text
            return response1.text != response2.text

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
        print("Usage: python3 bola_tester.py <url> [auth_token]")
        print("\nExample:")
        print("  python3 bola_tester.py https://api.example.com/users/123")
        print("  python3 bola_tester.py https://api.example.com/users/123 eyJhbGc...")
        sys.exit(1)

    url = sys.argv[1]
    token = sys.argv[2] if len(sys.argv) > 2 else None

    tester = BOLATester(url, token)
    results = tester.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")
