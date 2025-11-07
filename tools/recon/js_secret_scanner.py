#!/usr/bin/env python3
"""
JavaScript Secret Scanner
Extracts secrets, API keys, tokens, and endpoints from JavaScript files
"""

import requests
import re
import json
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class JSSecretScanner:
    """JavaScript secret and endpoint scanner"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.secrets = []
        self.endpoints = []
        self.js_files = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        # Secret patterns (regex)
        self.secret_patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'aws(.{0,20})?["\']?[0-9a-zA-Z/+]{40}["\']?',
            'Google API Key': r'AIza[0-9A-Za-z\\-_]{35}',
            'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com',
            'GitHub Token': r'gh[pousr]_[0-9a-zA-Z]{36}',
            'Slack Token': r'xox[baprs]-([0-9a-zA-Z]{10,48})?',
            'Slack Webhook': r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
            'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24}',
            'Stripe Publishable Key': r'pk_live_[0-9a-zA-Z]{24}',
            'Square Access Token': r'sq0atp-[0-9A-Za-z\\-_]{22}',
            'Square OAuth Secret': r'sq0csp-[0-9A-Za-z\\-_]{43}',
            'PayPal/Braintree': r'access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}',
            'Twilio API Key': r'SK[0-9a-fA-F]{32}',
            'MailChimp API Key': r'[0-9a-f]{32}-us[0-9]{1,2}',
            'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
            'Firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
            'Generic API Key': r'[aA][pP][iI][_]?[kK][eE][yY]["\']?\\s*[:=]\\s*["\'][0-9a-zA-Z]{20,}["\']',
            'Generic Secret': r'[sS][eE][cC][rR][eE][tT]["\']?\\s*[:=]\\s*["\'][0-9a-zA-Z]{20,}["\']',
            'Generic Token': r'[tT][oO][kK][eE][nN]["\']?\\s*[:=]\\s*["\'][0-9a-zA-Z]{20,}["\']',
            'Authorization Bearer': r'[aA]uthorization["\']?\\s*[:=]\\s*["\']?[bB]earer\\s+[0-9a-zA-Z\\-._~+/]+=*',
            'Basic Auth': r'[aA]uthorization["\']?\\s*[:=]\\s*["\']?[bB]asic\\s+[0-9a-zA-Z+/=]+',
            'Private Key': r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
            'SSH Private Key': r'-----BEGIN OPENSSH PRIVATE KEY-----',
            'PGP Private Key': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            'JWT Token': r'eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}',
            'Generic Password': r'[pP]assword["\']?\\s*[:=]\\s*["\'][^"\'\\s]{8,}["\']',
            'Connection String': r'(?:mongodb|mysql|postgresql)://[^\\s]+',
            'Azure Storage Key': r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+',
            'Heroku API Key': r'[hH][eE][rR][oO][kK][uU].*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            'Telegram Bot Token': r'[0-9]{8,10}:[0-9A-Za-z_-]{35}',
            'Discord Token': r'[MNO][A-Za-z\\d]{23,25}\\.[A-Za-z\\d]{6}\\.[A-Za-z\\d_-]{27,}',
            'Generic Credentials': r'["\']?(username|user|login|email)["\']?\\s*[:=]\\s*["\'][^"\']+["\']'
        }

        # API endpoint patterns
        self.endpoint_patterns = [
            r'["\']([/]api[^"\'\\s]+)["\']',
            r'["\']([/]v[0-9]+[^"\'\\s]+)["\']',
            r'["\']([/][a-z]+/[a-z0-9_-]+)["\']',
            r'(https?://[a-zA-Z0-9.-]+/api[^"\'\\s]*)',
            r'(https?://[a-zA-Z0-9.-]+/v[0-9]+[^"\'\\s]*)',
        ]

    def scan(self):
        """Run JavaScript secret scan"""
        print(f"[*] Starting JavaScript secret scan on {self.target_url}")

        # Find JavaScript files
        self._find_js_files()

        print(f"[*] Found {len(self.js_files)} JavaScript files")

        # Scan each JS file
        for i, js_url in enumerate(self.js_files, 1):
            print(f"[*] Scanning {i}/{len(self.js_files)}: {js_url}")
            self._scan_js_file(js_url)

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'js_files_scanned': len(self.js_files),
            'secrets_found': len(self.secrets),
            'endpoints_found': len(self.endpoints)
        }

    def _find_js_files(self):
        """Find JavaScript files from target URL"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find <script> tags with src
            scripts = soup.find_all('script', src=True)

            for script in scripts:
                src = script.get('src')
                if src:
                    # Convert to absolute URL
                    js_url = urljoin(self.target_url, src)
                    if js_url not in self.js_files:
                        self.js_files.append(js_url)

            # Also scan inline scripts for references
            inline_scripts = soup.find_all('script', src=False)
            for script in inline_scripts:
                if script.string:
                    # Look for JS file references in inline scripts
                    js_refs = re.findall(r'["\']([^"\']+\.js[^"\']*)["\']', script.string)
                    for ref in js_refs:
                        js_url = urljoin(self.target_url, ref)
                        if js_url not in self.js_files:
                            self.js_files.append(js_url)

            # Common JS file locations
            common_paths = [
                '/js/app.js',
                '/js/main.js',
                '/js/bundle.js',
                '/static/js/main.js',
                '/assets/js/app.js',
                '/dist/bundle.js',
                '/build/main.js'
            ]

            parsed = urlparse(self.target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for path in common_paths:
                js_url = urljoin(base_url, path)
                if js_url not in self.js_files:
                    # Check if file exists
                    try:
                        resp = self.session.head(js_url, timeout=5)
                        if resp.status_code == 200:
                            self.js_files.append(js_url)
                    except:
                        pass

        except Exception as e:
            print(f"[!] Error finding JS files: {e}")

    def _scan_js_file(self, js_url):
        """Scan a single JavaScript file"""
        try:
            response = self.session.get(js_url, timeout=15)

            if response.status_code != 200:
                return

            content = response.text

            # Scan for secrets
            for secret_type, pattern in self.secret_patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE)

                for match in matches:
                    secret_value = match.group(0)

                    # Skip if it's a placeholder or example
                    if self._is_placeholder(secret_value):
                        continue

                    secret = {
                        'type': secret_type,
                        'value': secret_value,
                        'file': js_url,
                        'severity': self._get_secret_severity(secret_type),
                        'line': content[:match.start()].count('\n') + 1
                    }

                    # Avoid duplicates
                    if not any(s['value'] == secret_value and s['file'] == js_url for s in self.secrets):
                        self.secrets.append(secret)
                        print(f"[!] Found {secret_type}: {secret_value[:50]}...")

            # Extract API endpoints
            for pattern in self.endpoint_patterns:
                matches = re.finditer(pattern, content)

                for match in matches:
                    endpoint = match.group(1)

                    # Skip if too generic or placeholder
                    if self._is_valid_endpoint(endpoint):
                        if endpoint not in self.endpoints:
                            self.endpoints.append(endpoint)

        except Exception as e:
            print(f"[!] Error scanning {js_url}: {e}")

    def _is_placeholder(self, value):
        """Check if value is a placeholder"""
        placeholders = [
            'xxx', 'yyy', 'zzz', 'test', 'example', 'sample',
            'demo', 'your_', 'your-', 'placeholder', 'xxxxxxxxx',
            '11111', '00000', 'fake', 'dummy', 'mock'
        ]

        value_lower = value.lower()

        for placeholder in placeholders:
            if placeholder in value_lower:
                return True

        # Check if it's all same characters
        if len(set(value)) < 3:
            return True

        return False

    def _is_valid_endpoint(self, endpoint):
        """Check if endpoint is valid"""
        if len(endpoint) < 5:
            return False

        # Skip common false positives
        false_positives = [
            '/static/', '/assets/', '/css/', '/js/', '/images/',
            '/img/', '/fonts/', '/icon', '.png', '.jpg', '.gif',
            '.css', '.svg', '.woff'
        ]

        endpoint_lower = endpoint.lower()

        for fp in false_positives:
            if fp in endpoint_lower:
                return False

        return True

    def _get_secret_severity(self, secret_type):
        """Get severity level for secret type"""
        critical = [
            'AWS Access Key', 'AWS Secret Key', 'Private Key',
            'SSH Private Key', 'PGP Private Key', 'Connection String'
        ]

        high = [
            'Google API Key', 'GitHub Token', 'Slack Token',
            'Stripe API Key', 'Square Access Token', 'PayPal/Braintree',
            'Authorization Bearer', 'JWT Token'
        ]

        if any(s in secret_type for s in critical):
            return 'critical'
        elif any(s in secret_type for s in high):
            return 'high'
        else:
            return 'medium'

    def _save_results(self):
        """Save results to file"""
        results = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'js_files': self.js_files,
            'secrets': self.secrets,
            'endpoints': self.endpoints,
            'summary': {
                'js_files_scanned': len(self.js_files),
                'secrets_found': len(self.secrets),
                'endpoints_found': len(self.endpoints),
                'severity': {
                    'critical': sum(1 for s in self.secrets if s['severity'] == 'critical'),
                    'high': sum(1 for s in self.secrets if s['severity'] == 'high'),
                    'medium': sum(1 for s in self.secrets if s['severity'] == 'medium')
                }
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 js_secret_scanner.py <url> [output_file]")
        print("\nExample:")
        print("  python3 js_secret_scanner.py https://example.com")
        print("  python3 js_secret_scanner.py https://example.com secrets.json")
        sys.exit(1)

    url = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    scanner = JSSecretScanner(url, output_file)
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    JS files scanned: {results['js_files_scanned']}")
    print(f"    Secrets found: {results['secrets_found']}")
    print(f"    API endpoints found: {results['endpoints_found']}")

    if results['secrets_found'] > 0:
        print(f"\n[!] WARNING: Found {results['secrets_found']} potential secrets!")
        print(f"    Review the results carefully and report responsibly.")
