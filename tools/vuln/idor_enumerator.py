#!/usr/bin/env python3
"""
IDOR Enumeration Tool
Automated enumeration for Insecure Direct Object Reference vulnerabilities
"""

import requests
import json
import re
import uuid
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import random

class IDOREnumerator:
    """IDOR enumeration and detection tool"""

    def __init__(self, target_url, auth_token=None, output_file=None, max_enum=20):
        self.target_url = target_url
        self.auth_token = auth_token
        self.output_file = output_file
        self.max_enum = max_enum
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        if auth_token:
            # Try both Authorization header and Bearer token
            self.session.headers.update({
                'Authorization': f'Bearer {auth_token}' if not auth_token.startswith('Bearer') else auth_token
            })

    def scan(self):
        """Run IDOR enumeration"""
        print(f"[*] Starting IDOR enumeration on {self.target_url}")

        # Detect ID type
        id_type, current_id = self._detect_id_type()

        if not current_id:
            print("[!] No ID parameter detected in URL")
            return {
                'target': self.target_url,
                'timestamp': datetime.now().isoformat(),
                'vulnerabilities': []
            }

        print(f"[*] Detected ID type: {id_type}, Current ID: {current_id}")

        # Enumerate IDs
        self._enumerate_ids(id_type, current_id)

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _detect_id_type(self):
        """Detect the type of ID being used"""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)

        # Check URL parameters
        for param_name, param_values in params.items():
            if param_values:
                value = param_values[0]

                # Check if it's a UUID
                try:
                    uuid.UUID(value)
                    return ('uuid', value)
                except:
                    pass

                # Check if it's numeric
                if value.isdigit():
                    return ('numeric', value)

                # Check if it's alphanumeric
                if re.match(r'^[a-zA-Z0-9_-]+$', value):
                    return ('alphanumeric', value)

        # Check path segments
        path_segments = parsed.path.strip('/').split('/')
        for segment in path_segments:
            # Check for UUID in path
            try:
                uuid.UUID(segment)
                return ('uuid_path', segment)
            except:
                pass

            # Check for numeric ID in path
            if segment.isdigit() and len(segment) < 10:
                return ('numeric_path', segment)

            # Check for alphanumeric ID
            if re.match(r'^[a-zA-Z0-9_-]{8,}$', segment):
                return ('alphanumeric_path', segment)

        return (None, None)

    def _enumerate_ids(self, id_type, current_id):
        """Enumerate IDs based on type"""
        parsed = urlparse(self.target_url)

        # Get baseline response
        try:
            baseline = self.session.get(self.target_url, timeout=10)
            baseline_status = baseline.status_code
            baseline_length = len(baseline.text)
        except:
            print("[!] Failed to get baseline response")
            return

        print(f"[*] Baseline: Status {baseline_status}, Length {baseline_length}")
        print(f"[*] Enumerating {self.max_enum} IDs...")

        found_accessible = []

        if id_type in ['numeric', 'numeric_path']:
            # Numeric enumeration
            current_num = int(current_id)
            test_ids = []

            # Test sequential IDs
            test_ids.extend(range(current_num - 10, current_num))
            test_ids.extend(range(current_num + 1, current_num + self.max_enum))

            # Test common IDs
            test_ids.extend([1, 2, 3, 100, 1000, 9999])

            for test_id in test_ids[:self.max_enum]:
                if test_id == current_num:
                    continue

                test_url = self._build_test_url(id_type, current_id, str(test_id))
                result = self._test_idor(test_url, str(test_id), baseline_status, baseline_length)

                if result:
                    found_accessible.append(result)

        elif id_type in ['uuid', 'uuid_path']:
            # UUID enumeration (limited, mostly for testing access control)
            print("[*] Testing UUID with modified variants...")

            # Generate similar UUIDs
            test_uuids = [str(uuid.uuid4()) for _ in range(min(10, self.max_enum))]

            # Also test predictable UUIDs
            test_uuids.extend([
                '00000000-0000-0000-0000-000000000001',
                '00000000-0000-0000-0000-000000000002',
                '11111111-1111-1111-1111-111111111111',
            ])

            for test_uuid in test_uuids:
                test_url = self._build_test_url(id_type, current_id, test_uuid)
                result = self._test_idor(test_url, test_uuid, baseline_status, baseline_length)

                if result:
                    found_accessible.append(result)

        elif id_type in ['alphanumeric', 'alphanumeric_path']:
            # Alphanumeric enumeration
            print("[*] Testing common alphanumeric patterns...")

            # Generate test IDs
            test_ids = [
                'admin',
                'user1',
                'user2',
                'test',
                'demo',
            ]

            # Add random variations
            for i in range(1, min(10, self.max_enum)):
                test_ids.append(f"user{i}")
                test_ids.append(f"test{i}")

            for test_id in test_ids:
                test_url = self._build_test_url(id_type, current_id, test_id)
                result = self._test_idor(test_url, test_id, baseline_status, baseline_length)

                if result:
                    found_accessible.append(result)

        # Analyze results
        if found_accessible:
            vuln = {
                'type': 'IDOR (Insecure Direct Object Reference)',
                'severity': 'high',
                'url': self.target_url,
                'id_type': id_type,
                'current_id': current_id,
                'accessible_ids': found_accessible,
                'evidence': f'Found {len(found_accessible)} accessible objects',
                'cwe': 'CWE-639',
                'description': 'Multiple objects accessible without proper authorization',
                'impact': 'Unauthorized access to other users\' data'
            }
            self.vulnerabilities.append(vuln)
            print(f"\n[!] IDOR vulnerability found!")
            print(f"    Accessible IDs: {len(found_accessible)}")
            for item in found_accessible[:5]:
                print(f"    - {item['id']}: Status {item['status']}, Length {item['length']}")

    def _build_test_url(self, id_type, current_id, test_id):
        """Build test URL with modified ID"""
        parsed = urlparse(self.target_url)

        if id_type in ['numeric', 'uuid', 'alphanumeric']:
            # ID is in query parameter
            params = parse_qs(parsed.query)

            # Find and replace the ID parameter
            for param_name, param_values in params.items():
                if param_values and param_values[0] == current_id:
                    params[param_name] = [test_id]
                    break

            new_query = urlencode(params, doseq=True)
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        elif id_type in ['numeric_path', 'uuid_path', 'alphanumeric_path']:
            # ID is in path
            new_path = parsed.path.replace(current_id, test_id)
            return urlunparse((parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, parsed.fragment))

        return self.target_url

    def _test_idor(self, test_url, test_id, baseline_status, baseline_length):
        """Test single ID for IDOR"""
        try:
            response = self.session.get(test_url, timeout=10, allow_redirects=False)

            # Check if accessible
            if response.status_code == 200:
                # Check if content is different (not just error page)
                response_length = len(response.text)

                # If length is very different, it might be an error page
                length_diff_percent = abs(response_length - baseline_length) / baseline_length * 100 if baseline_length > 0 else 0

                # Content is similar enough to be valid
                if length_diff_percent < 80:  # Allow up to 80% difference
                    print(f"[+] Accessible: {test_id} (Status: {response.status_code}, Length: {response_length})")
                    return {
                        'id': test_id,
                        'url': test_url,
                        'status': response.status_code,
                        'length': response_length
                    }

        except Exception as e:
            pass

        return None

    def _save_results(self):
        """Save results to file"""
        results = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total': len(self.vulnerabilities),
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 idor_enumerator.py <url> [auth_token] [max_enum]")
        print("\nExample:")
        print("  python3 idor_enumerator.py https://example.com/api/user/123")
        print("  python3 idor_enumerator.py https://example.com/api/user?id=123 Bearer_token_here 50")
        print("\nDetects and enumerates:")
        print("  - Numeric IDs (sequential enumeration)")
        print("  - UUIDs (random testing)")
        print("  - Alphanumeric IDs (pattern-based)")
        sys.exit(1)

    target = sys.argv[1]
    auth_token = sys.argv[2] if len(sys.argv) > 2 else None
    max_enum = int(sys.argv[3]) if len(sys.argv) > 3 else 20

    enumerator = IDOREnumerator(target, auth_token, max_enum=max_enum)
    results = enumerator.scan()

    print(f"\n[+] Enumeration complete!")
    print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")
