#!/usr/bin/env python3
"""
PII (Personally Identifiable Information) Scanner
Scans for exposed emails, phone numbers, SSNs, credit cards, and API keys
in web pages and API responses
"""

import requests
import json
import re
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup

class PIIScanner:
    """Scanner for exposed PII and sensitive data"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def scan(self):
        """Run PII scanning"""
        print(f"[*] Starting PII scanning on {self.target_url}")

        # Get page content
        try:
            response = self.session.get(self.target_url, timeout=15)
            content = response.text
        except:
            print(f"[-] Failed to fetch {self.target_url}")
            return {
                'target': self.target_url,
                'timestamp': datetime.now().isoformat(),
                'vulnerabilities': []
            }

        # Test for email exposure
        self._test_email_exposure(content)

        # Test for phone numbers
        self._test_phone_numbers(content)

        # Test for SSNs and credit cards
        self._test_ssn_credit_cards(content)

        # Test for API keys and tokens
        self._test_api_keys(content)

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_email_exposure(self, content):
        """Test for exposed email addresses"""
        print("[*] Testing for exposed email addresses...")

        # Email regex pattern
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

        emails = re.findall(email_pattern, content)

        if emails:
            # Deduplicate
            unique_emails = list(set(emails))

            # Filter out common false positives
            filtered_emails = [
                email for email in unique_emails
                if not any(fp in email.lower() for fp in ['example.com', 'test.com', 'domain.com', 'email.com'])
            ]

            if filtered_emails:
                vuln = {
                    'type': 'PII Exposure - Email Addresses',
                    'severity': 'medium',
                    'url': self.target_url,
                    'count': len(filtered_emails),
                    'emails': filtered_emails[:10],  # Limit to first 10
                    'evidence': f'{len(filtered_emails)} email addresses exposed',
                    'description': 'Email addresses are exposed in page content',
                    'cwe': 'CWE-359',
                    'impact': 'Privacy violation, spam, phishing attacks',
                    'remediation': 'Remove or obfuscate email addresses, use contact forms'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] Found {len(filtered_emails)} email addresses")

    def _test_phone_numbers(self, content):
        """Test for exposed phone numbers"""
        print("[*] Testing for exposed phone numbers...")

        # Phone number patterns (various formats)
        phone_patterns = [
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # 123-456-7890
            r'\b\(\d{3}\)\s?\d{3}[-.]?\d{4}\b',  # (123) 456-7890
            r'\b\+\d{1,3}\s?\d{1,14}\b',  # International format
            r'\b\d{3}\s\d{3}\s\d{4}\b',  # 123 456 7890
        ]

        all_phones = []

        for pattern in phone_patterns:
            phones = re.findall(pattern, content)
            all_phones.extend(phones)

        if all_phones:
            unique_phones = list(set(all_phones))

            vuln = {
                'type': 'PII Exposure - Phone Numbers',
                'severity': 'medium',
                'url': self.target_url,
                'count': len(unique_phones),
                'phones': unique_phones[:10],  # Limit to first 10
                'evidence': f'{len(unique_phones)} phone numbers exposed',
                'description': 'Phone numbers are exposed in page content',
                'cwe': 'CWE-359',
                'impact': 'Privacy violation, unwanted calls/SMS',
                'remediation': 'Remove or obfuscate phone numbers'
            }
            self.vulnerabilities.append(vuln)
            print(f"[!] Found {len(unique_phones)} phone numbers")

    def _test_ssn_credit_cards(self, content):
        """Test for exposed SSNs and credit card numbers"""
        print("[*] Testing for SSNs and credit card numbers...")

        # SSN pattern (XXX-XX-XXXX)
        ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        ssns = re.findall(ssn_pattern, content)

        if ssns:
            vuln = {
                'type': 'PII Exposure - Social Security Numbers',
                'severity': 'critical',
                'url': self.target_url,
                'count': len(ssns),
                'evidence': f'{len(ssns)} potential SSN patterns found',
                'description': 'Potential Social Security Numbers exposed',
                'cwe': 'CWE-359',
                'impact': 'SEVERE privacy violation, identity theft',
                'remediation': 'IMMEDIATELY remove SSNs from page'
            }
            self.vulnerabilities.append(vuln)
            print(f"[!] CRITICAL: Found {len(ssns)} potential SSNs")

        # Credit card patterns (simplified Luhn check)
        cc_patterns = [
            r'\b4\d{15}\b',  # Visa
            r'\b5[1-5]\d{14}\b',  # Mastercard
            r'\b3[47]\d{13}\b',  # American Express
            r'\b6(?:011|5\d{2})\d{12}\b',  # Discover
        ]

        all_cards = []
        for pattern in cc_patterns:
            cards = re.findall(pattern, content)
            all_cards.extend(cards)

        if all_cards:
            # Validate with Luhn algorithm
            valid_cards = [card for card in all_cards if self._luhn_check(card)]

            if valid_cards:
                vuln = {
                    'type': 'PII Exposure - Credit Card Numbers',
                    'severity': 'critical',
                    'url': self.target_url,
                    'count': len(valid_cards),
                    'evidence': f'{len(valid_cards)} potential credit card numbers found',
                    'description': 'Potential credit card numbers exposed',
                    'cwe': 'CWE-359',
                    'impact': 'SEVERE privacy violation, PCI-DSS violation, fraud',
                    'remediation': 'IMMEDIATELY remove credit card data, report to security team'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] CRITICAL: Found {len(valid_cards)} potential credit cards")

    def _test_api_keys(self, content):
        """Test for exposed API keys and tokens"""
        print("[*] Testing for exposed API keys and tokens...")

        # API key patterns
        api_patterns = [
            # AWS
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'aws_secret_access_key.*?[\'"](.*?)[\'"]', 'AWS Secret Key'),

            # Google
            (r'AIza[0-9A-Za-z\\-_]{35}', 'Google API Key'),

            # GitHub
            (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token'),
            (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token'),
            (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', 'GitHub Fine-grained PAT'),

            # Slack
            (r'xox[baprs]-[0-9a-zA-Z]{10,48}', 'Slack Token'),

            # Stripe
            (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe Live Secret Key'),
            (r'pk_live_[0-9a-zA-Z]{24}', 'Stripe Live Publishable Key'),

            # Mailgun
            (r'key-[0-9a-zA-Z]{32}', 'Mailgun API Key'),

            # Twilio
            (r'SK[0-9a-fA-F]{32}', 'Twilio API Key'),

            # Generic patterns
            (r'api[_-]?key[\'":\s]+[\'"]{0,1}([a-zA-Z0-9]{32,})[\'"]{0,1}', 'Generic API Key'),
            (r'access[_-]?token[\'":\s]+[\'"]{0,1}([a-zA-Z0-9]{32,})[\'"]{0,1}', 'Access Token'),
            (r'secret[_-]?key[\'":\s]+[\'"]{0,1}([a-zA-Z0-9]{32,})[\'"]{0,1}', 'Secret Key'),

            # JWT tokens
            (r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'JWT Token'),

            # Private keys
            (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'Private Key'),
        ]

        for pattern, key_type in api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)

            if matches:
                # Deduplicate
                unique_matches = list(set(matches))

                # Determine severity
                severity = 'critical'
                if 'publishable' in key_type.lower() or 'public' in key_type.lower():
                    severity = 'medium'

                vuln = {
                    'type': f'Exposed API Key - {key_type}',
                    'severity': severity,
                    'url': self.target_url,
                    'key_type': key_type,
                    'count': len(unique_matches),
                    'evidence': f'{len(unique_matches)} {key_type}(s) exposed in source',
                    'description': f'{key_type} exposed in page source or JavaScript',
                    'cwe': 'CWE-798',
                    'impact': 'Unauthorized API access, account compromise, data breach',
                    'remediation': 'Rotate keys immediately, use environment variables'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] {severity.upper()}: Found {len(unique_matches)} {key_type}(s)")

    def _luhn_check(self, card_number):
        """Validate credit card number using Luhn algorithm"""
        try:
            digits = [int(d) for d in str(card_number)]
            checksum = 0

            # Double every second digit from right to left
            for i in range(len(digits) - 2, -1, -2):
                digits[i] *= 2
                if digits[i] > 9:
                    digits[i] -= 9

            # Sum all digits
            checksum = sum(digits)

            # Valid if checksum is divisible by 10
            return checksum % 10 == 0
        except:
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
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'medium')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 pii_scanner.py <url> [output_file]")
        print("\nExample:")
        print("  python3 pii_scanner.py https://example.com")
        print("\nScans for:")
        print("  - Email addresses")
        print("  - Phone numbers")
        print("  - SSNs and credit card numbers")
        print("  - API keys and tokens (AWS, Google, GitHub, Stripe, etc.)")
        print("  - JWT tokens and private keys")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    scanner = PIIScanner(target, output)
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    Medium: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'medium')}")
