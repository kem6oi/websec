#!/usr/bin/env python3
"""
CORS (Cross-Origin Resource Sharing) Misconfiguration Checker
Tests for CORS misconfigurations
"""

import requests
import json
from datetime import datetime
from urllib.parse import urlparse

class CORSChecker:
    """CORS misconfiguration checker"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()

        # Test origins to check
        self.test_origins = [
            'https://evil.com',
            'http://evil.com',
            'null',
            'https://evil.com.target.com',  # Subdomain trick
            self.target_url.replace('https://', 'https://evil-'),  # Prefix
            self.target_url + '.evil.com',  # Suffix
        ]

    def scan(self):
        """Run CORS misconfiguration check"""
        print(f"[*] Starting CORS check on {self.target_url}")

        # Test with various origins
        for origin in self.test_origins:
            self._test_origin(origin)

        # Test for reflected origin
        self._test_reflected_origin()

        # Test for wildcard with credentials
        self._test_wildcard()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_origin(self, origin):
        """Test with specific origin"""
        headers = {
            'Origin': origin,
            'User-Agent': 'Mozilla/5.0'
        }

        try:
            response = self.session.get(self.target_url, headers=headers, timeout=10)

            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')

            # Check for vulnerabilities
            if acao == origin:
                severity = 'critical' if acac.lower() == 'true' else 'high'
                vuln = {
                    'type': 'CORS Misconfiguration',
                    'severity': severity,
                    'url': self.target_url,
                    'issue': f'Arbitrary origin reflected: {origin}',
                    'acao': acao,
                    'acac': acac,
                    'evidence': f'Origin {origin} was reflected in Access-Control-Allow-Origin'
                }

                if acac.lower() == 'true':
                    vuln['critical_note'] = 'Credentials are allowed! This enables complete account takeover.'

                self.vulnerabilities.append(vuln)
                print(f"[!] CORS misconfiguration found with origin: {origin}")

            elif acao == '*' and acac.lower() == 'true':
                # Wildcard with credentials (technically invalid but worth reporting)
                vuln = {
                    'type': 'CORS Misconfiguration',
                    'severity': 'high',
                    'url': self.target_url,
                    'issue': 'Wildcard origin with credentials',
                    'acao': acao,
                    'acac': acac,
                    'evidence': 'Wildcard (*) used with Access-Control-Allow-Credentials: true'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] CORS misconfiguration: wildcard with credentials")

        except Exception as e:
            pass

    def _test_reflected_origin(self):
        """Test if origin is blindly reflected"""
        random_origin = 'https://random-evil-site-12345.com'
        headers = {
            'Origin': random_origin,
            'User-Agent': 'Mozilla/5.0'
        }

        try:
            response = self.session.get(self.target_url, headers=headers, timeout=10)

            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')

            if acao == random_origin:
                severity = 'critical' if acac.lower() == 'true' else 'high'
                vuln = {
                    'type': 'CORS Misconfiguration',
                    'severity': severity,
                    'url': self.target_url,
                    'issue': 'Origin blindly reflected',
                    'acao': acao,
                    'acac': acac,
                    'evidence': 'Arbitrary origin is reflected without validation',
                    'exploitation': 'Any attacker-controlled origin can access the resource'
                }

                if acac.lower() == 'true':
                    vuln['critical_note'] = 'With credentials! Complete account takeover possible.'

                self.vulnerabilities.append(vuln)
                print(f"[!] CRITICAL: Origin blindly reflected!")

        except Exception as e:
            pass

    def _test_wildcard(self):
        """Test for wildcard CORS"""
        try:
            response = self.session.get(self.target_url, timeout=10)

            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')

            if acao == '*':
                severity = 'medium'
                vuln = {
                    'type': 'CORS Misconfiguration',
                    'severity': severity,
                    'url': self.target_url,
                    'issue': 'Wildcard CORS policy',
                    'acao': acao,
                    'acac': acac,
                    'evidence': 'Access-Control-Allow-Origin: * allows any origin',
                    'impact': 'Public data exposure, depending on endpoint sensitivity'
                }

                # Check if sensitive data is exposed
                if self._has_sensitive_data(response):
                    vuln['severity'] = 'high'
                    vuln['sensitive_data'] = 'Response may contain sensitive information'

                self.vulnerabilities.append(vuln)
                print(f"[!] Wildcard CORS policy detected")

        except Exception as e:
            pass

    def _has_sensitive_data(self, response):
        """Check if response might contain sensitive data"""
        sensitive_keywords = [
            'password', 'token', 'api_key', 'secret', 'ssn',
            'credit_card', 'email', 'phone', 'address',
            'session', 'cookie', 'auth'
        ]

        response_lower = response.text.lower()
        for keyword in sensitive_keywords:
            if keyword in response_lower:
                return True

        return False

    def _test_null_origin(self):
        """Test null origin (can be exploited via sandbox iframe)"""
        headers = {
            'Origin': 'null',
            'User-Agent': 'Mozilla/5.0'
        }

        try:
            response = self.session.get(self.target_url, headers=headers, timeout=10)

            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')

            if acao == 'null':
                severity = 'high' if acac.lower() == 'true' else 'medium'
                vuln = {
                    'type': 'CORS Misconfiguration',
                    'severity': severity,
                    'url': self.target_url,
                    'issue': 'Null origin accepted',
                    'acao': acao,
                    'acac': acac,
                    'evidence': 'Origin "null" is accepted',
                    'exploitation': 'Can be exploited via sandboxed iframe'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] Null origin accepted")

        except Exception as e:
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
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high'),
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'medium')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 cors_checker.py <url>")
        sys.exit(1)

    checker = CORSChecker(sys.argv[1])
    results = checker.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")
