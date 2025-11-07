#!/usr/bin/env python3
"""
Subdomain Takeover Checker
Detects dangling DNS records vulnerable to takeover
"""

import requests
import json
import socket
import re
from datetime import datetime
from pathlib import Path
import dns.resolver

class SubdomainTakeoverChecker:
    """Subdomain takeover vulnerability checker"""

    def __init__(self, subdomains_file, output_file=None):
        self.subdomains_file = subdomains_file
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        # Service fingerprints - CNAME patterns and error messages
        self.services = {
            'AWS/S3': {
                'cname': ['amazonaws.com', 's3.amazonaws.com', 's3-website'],
                'patterns': [
                    'NoSuchBucket',
                    'The specified bucket does not exist'
                ],
                'status_codes': [404]
            },
            'GitHub Pages': {
                'cname': ['github.io', 'githubapp.com'],
                'patterns': [
                    'There isn\'t a GitHub Pages site here',
                    'For root URLs (like http://example.com/) you must provide an index.html file'
                ],
                'status_codes': [404]
            },
            'Heroku': {
                'cname': ['herokuapp.com', 'herokussl.com'],
                'patterns': [
                    'No such app',
                    'There\'s nothing here, yet',
                    'herokucdn.com/error-pages/no-such-app.html'
                ],
                'status_codes': [404]
            },
            'Azure': {
                'cname': ['azurewebsites.net', 'cloudapp.azure.com', 'cloudapp.net', 'trafficmanager.net', 'blob.core.windows.net'],
                'patterns': [
                    'Error 404 - Web app not found',
                    'The resource you are looking for has been removed'
                ],
                'status_codes': [404]
            },
            'Shopify': {
                'cname': ['myshopify.com'],
                'patterns': [
                    'Sorry, this shop is currently unavailable',
                    'Only one step left'
                ],
                'status_codes': [404]
            },
            'Tumblr': {
                'cname': ['tumblr.com'],
                'patterns': [
                    'There\'s nothing here',
                    'Whatever you were looking for doesn\'t currently exist'
                ],
                'status_codes': [404]
            },
            'WordPress': {
                'cname': ['wordpress.com'],
                'patterns': [
                    'Do you want to register'
                ],
                'status_codes': [404]
            },
            'Bitbucket': {
                'cname': ['bitbucket.io'],
                'patterns': [
                    'Repository not found'
                ],
                'status_codes': [404]
            },
            'Ghost': {
                'cname': ['ghost.io'],
                'patterns': [
                    'The thing you were looking for is no longer here'
                ],
                'status_codes': [404]
            },
            'Fastly': {
                'cname': ['fastly.net'],
                'patterns': [
                    'Fastly error: unknown domain'
                ],
                'status_codes': [404]
            },
            'Pantheon': {
                'cname': ['pantheonsite.io'],
                'patterns': [
                    '404 error unknown site'
                ],
                'status_codes': [404]
            },
            'Zendesk': {
                'cname': ['zendesk.com'],
                'patterns': [
                    'Help Center Closed'
                ],
                'status_codes': [404]
            },
            'Desk': {
                'cname': ['desk.com'],
                'patterns': [
                    'Please try again or try Desk.com free for'
                ],
                'status_codes': [404]
            },
            'Campaign Monitor': {
                'cname': ['createsend.com', 'name.createsend.com'],
                'patterns': [
                    'Trying to access your account?',
                    'Double check the URL'
                ],
                'status_codes': [404]
            },
            'Cargo': {
                'cname': ['cargocollective.com'],
                'patterns': [
                    'If you\'re moving your domain away from Cargo'
                ],
                'status_codes': [404]
            },
            'StatusPage': {
                'cname': ['statuspage.io'],
                'patterns': [
                    'You are being',
                    'redirected'
                ],
                'status_codes': [404]
            },
            'Surge.sh': {
                'cname': ['surge.sh'],
                'patterns': [
                    'project not found'
                ],
                'status_codes': [404]
            },
            'Unbounce': {
                'cname': ['unbouncepages.com'],
                'patterns': [
                    'The requested URL was not found on this server',
                    'The requested URL / was not found on this server'
                ],
                'status_codes': [404]
            },
            'Netlify': {
                'cname': ['netlify.com', 'netlify.app'],
                'patterns': [
                    'Not Found - Request ID'
                ],
                'status_codes': [404]
            },
            'Vercel': {
                'cname': ['vercel.app', 'now.sh'],
                'patterns': [
                    'The deployment could not be found on Vercel',
                    '404: NOT_FOUND'
                ],
                'status_codes': [404]
            }
        }

    def scan(self):
        """Run subdomain takeover scan"""
        print(f"[*] Starting subdomain takeover scan...")

        # Load subdomains
        subdomains = self._load_subdomains()
        print(f"[*] Loaded {len(subdomains)} subdomains")

        # Check each subdomain
        for i, subdomain in enumerate(subdomains, 1):
            if i % 10 == 0:
                print(f"[*] Checked {i}/{len(subdomains)} subdomains...")

            self._check_subdomain(subdomain.strip())

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'timestamp': datetime.now().isoformat(),
            'total_checked': len(subdomains),
            'vulnerabilities': self.vulnerabilities
        }

    def _load_subdomains(self):
        """Load subdomains from file"""
        try:
            with open(self.subdomains_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error loading subdomains: {e}")
            return []

    def _check_subdomain(self, subdomain):
        """Check if subdomain is vulnerable to takeover"""
        # Get CNAME records
        cnames = self._get_cnames(subdomain)

        if not cnames:
            return

        # Check each CNAME
        for cname in cnames:
            service = self._identify_service(cname)

            if service:
                # Check if service responds with takeover indicators
                vulnerable = self._check_service_response(subdomain, service)

                if vulnerable:
                    vuln = {
                        'type': 'Subdomain Takeover',
                        'severity': 'high',
                        'subdomain': subdomain,
                        'cname': cname,
                        'service': service,
                        'evidence': f'Subdomain points to unclaimed {service} resource',
                        'cwe': 'CWE-350',
                        'impact': 'Attacker can claim this subdomain and host malicious content'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] TAKEOVER POSSIBLE: {subdomain} -> {cname} ({service})")

    def _get_cnames(self, subdomain):
        """Get CNAME records for subdomain"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            answers = resolver.resolve(subdomain, 'CNAME')
            return [str(rdata.target).rstrip('.') for rdata in answers]

        except dns.resolver.NXDOMAIN:
            # Domain doesn't exist
            return []
        except dns.resolver.NoAnswer:
            # No CNAME record
            return []
        except Exception as e:
            return []

    def _identify_service(self, cname):
        """Identify service from CNAME"""
        cname_lower = cname.lower()

        for service_name, config in self.services.items():
            for pattern in config['cname']:
                if pattern in cname_lower:
                    return service_name

        return None

    def _check_service_response(self, subdomain, service):
        """Check if service shows takeover indicators"""
        if service not in self.services:
            return False

        config = self.services[service]

        # Try both HTTP and HTTPS
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{subdomain}"
                response = self.session.get(url, timeout=10, allow_redirects=True)

                # Check status code
                if response.status_code in config.get('status_codes', []):
                    # Check for service-specific patterns
                    for pattern in config['patterns']:
                        if pattern.lower() in response.text.lower():
                            return True

            except requests.exceptions.SSLError:
                # Try without SSL verification
                try:
                    response = self.session.get(url, timeout=10, verify=False, allow_redirects=True)
                    if response.status_code in config.get('status_codes', []):
                        for pattern in config['patterns']:
                            if pattern.lower() in response.text.lower():
                                return True
                except:
                    pass

            except Exception as e:
                pass

        return False

    def _save_results(self):
        """Save results to file"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total': len(self.vulnerabilities),
                'services': {}
            }
        }

        # Count by service
        for vuln in self.vulnerabilities:
            service = vuln['service']
            results['summary']['services'][service] = results['summary']['services'].get(service, 0) + 1

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 subdomain_takeover.py <subdomains_file> [output_file]")
        print("\nExample:")
        print("  python3 subdomain_takeover.py results/subdomains/all_subdomains.txt")
        print("  python3 subdomain_takeover.py subdomains.txt takeover_results.json")
        sys.exit(1)

    subdomains_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    # Check if dnspython is installed
    try:
        import dns.resolver
    except ImportError:
        print("[!] Error: dnspython not installed")
        print("    Install with: pip3 install dnspython")
        sys.exit(1)

    checker = SubdomainTakeoverChecker(subdomains_file, output_file)
    results = checker.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total checked: {results['total_checked']}")
    print(f"    Vulnerable subdomains: {len(results['vulnerabilities'])}")

    if results['vulnerabilities']:
        print(f"\n[!] Found {len(results['vulnerabilities'])} potential takeovers:")
        for vuln in results['vulnerabilities']:
            print(f"    - {vuln['subdomain']} ({vuln['service']})")
