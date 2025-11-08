#!/usr/bin/env python3
"""
Cloud Storage Scanner
Scans for misconfigured and publicly accessible cloud storage buckets
including AWS S3, Azure Blob Storage, Google Cloud Storage, and Digital Ocean Spaces
"""

import requests
import json
from datetime import datetime
from urllib.parse import urlparse
import re

class CloudStorageScanner:
    """Scanner for misconfigured cloud storage"""

    def __init__(self, target_domain, output_file=None):
        self.target_domain = target_domain
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def scan(self):
        """Run cloud storage scanning"""
        print(f"[*] Starting cloud storage scanning for {self.target_domain}")

        # Test S3 buckets
        self._test_s3_buckets()

        # Test Azure blob storage
        self._test_azure_storage()

        # Test Google Cloud Storage
        self._test_gcs_buckets()

        # Test Digital Ocean Spaces
        self._test_do_spaces()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_domain,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_s3_buckets(self):
        """Test for publicly accessible S3 buckets"""
        print("[*] Testing AWS S3 buckets...")

        # Generate bucket name variations
        bucket_names = self._generate_bucket_names(self.target_domain)

        for bucket_name in bucket_names:
            # Test both path-style and virtual-hosted-style URLs
            s3_urls = [
                f'http://{bucket_name}.s3.amazonaws.com',
                f'https://{bucket_name}.s3.amazonaws.com',
                f'http://s3.amazonaws.com/{bucket_name}',
                f'https://s3.amazonaws.com/{bucket_name}',
            ]

            for s3_url in s3_urls:
                try:
                    response = self.session.get(s3_url, timeout=10, allow_redirects=True)

                    # Check for public bucket
                    if response.status_code == 200:
                        # Check if it's an actual bucket listing
                        if '<ListBucketResult' in response.text or 'Contents' in response.text:
                            # Count files
                            file_count = response.text.count('<Key>')

                            vuln = {
                                'type': 'Publicly Accessible S3 Bucket',
                                'severity': 'critical',
                                'url': s3_url,
                                'bucket_name': bucket_name,
                                'evidence': f'Bucket listing accessible - {file_count} files found',
                                'description': 'AWS S3 bucket is publicly accessible and listable',
                                'cwe': 'CWE-200',
                                'impact': 'Data exposure, potential data breach',
                                'remediation': 'Remove public access, use bucket policies'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] CRITICAL: Public S3 bucket found - {bucket_name}")
                            return

                    # Check for bucket exists but access denied (still interesting)
                    elif response.status_code == 403:
                        if 'AccessDenied' in response.text or 'AllAccessDisabled' in response.text:
                            vuln = {
                                'type': 'S3 Bucket Exists (Access Denied)',
                                'severity': 'low',
                                'url': s3_url,
                                'bucket_name': bucket_name,
                                'evidence': 'Bucket exists but access denied',
                                'description': 'S3 bucket confirmed to exist (information disclosure)',
                                'cwe': 'CWE-200',
                                'impact': 'Bucket name disclosure, potential target for further attacks',
                                'remediation': 'Consider using random bucket names'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] S3 bucket exists: {bucket_name}")

                except:
                    pass

    def _test_azure_storage(self):
        """Test for publicly accessible Azure Blob Storage"""
        print("[*] Testing Azure Blob Storage...")

        storage_names = self._generate_bucket_names(self.target_domain)

        for storage_name in storage_names:
            # Azure blob storage URLs
            azure_urls = [
                f'https://{storage_name}.blob.core.windows.net',
                f'http://{storage_name}.blob.core.windows.net',
            ]

            # Common container names
            containers = ['public', 'private', 'backup', 'backups', 'data', 'files', 'uploads', 'images']

            for azure_url in azure_urls:
                for container in containers:
                    test_url = f'{azure_url}/{container}?restype=container&comp=list'

                    try:
                        response = self.session.get(test_url, timeout=10)

                        if response.status_code == 200:
                            # Check for blob listing
                            if '<EnumerationResults' in response.text or '<Blobs>' in response.text:
                                blob_count = response.text.count('<Name>')

                                vuln = {
                                    'type': 'Publicly Accessible Azure Blob Storage',
                                    'severity': 'critical',
                                    'url': test_url,
                                    'storage_account': storage_name,
                                    'container': container,
                                    'evidence': f'Container listing accessible - {blob_count} blobs found',
                                    'description': 'Azure Blob Storage container is publicly accessible',
                                    'cwe': 'CWE-200',
                                    'impact': 'Data exposure, potential data breach',
                                    'remediation': 'Set container access level to private'
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"[!] CRITICAL: Public Azure storage found - {storage_name}/{container}")
                                return

                    except:
                        pass

    def _test_gcs_buckets(self):
        """Test for publicly accessible Google Cloud Storage buckets"""
        print("[*] Testing Google Cloud Storage...")

        bucket_names = self._generate_bucket_names(self.target_domain)

        for bucket_name in bucket_names:
            # GCS URLs
            gcs_urls = [
                f'https://storage.googleapis.com/{bucket_name}',
                f'https://{bucket_name}.storage.googleapis.com',
            ]

            for gcs_url in gcs_urls:
                try:
                    response = self.session.get(gcs_url, timeout=10)

                    if response.status_code == 200:
                        # Check for bucket listing (XML format)
                        if '<ListBucketResult' in response.text or 'Contents' in response.text:
                            file_count = response.text.count('<Name>')

                            vuln = {
                                'type': 'Publicly Accessible GCS Bucket',
                                'severity': 'critical',
                                'url': gcs_url,
                                'bucket_name': bucket_name,
                                'evidence': f'Bucket listing accessible - {file_count} files found',
                                'description': 'Google Cloud Storage bucket is publicly accessible',
                                'cwe': 'CWE-200',
                                'impact': 'Data exposure, potential data breach',
                                'remediation': 'Remove allUsers and allAuthenticatedUsers from IAM'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] CRITICAL: Public GCS bucket found - {bucket_name}")
                            return

                except:
                    pass

    def _test_do_spaces(self):
        """Test for publicly accessible Digital Ocean Spaces"""
        print("[*] Testing Digital Ocean Spaces...")

        space_names = self._generate_bucket_names(self.target_domain)

        # Digital Ocean regions
        regions = ['nyc3', 'ams3', 'sgp1', 'sfo2', 'fra1']

        for space_name in space_names:
            for region in regions:
                do_url = f'https://{space_name}.{region}.digitaloceanspaces.com'

                try:
                    response = self.session.get(do_url, timeout=10)

                    if response.status_code == 200:
                        # Check for space listing
                        if '<ListBucketResult' in response.text or 'Contents' in response.text:
                            file_count = response.text.count('<Key>')

                            vuln = {
                                'type': 'Publicly Accessible Digital Ocean Space',
                                'severity': 'critical',
                                'url': do_url,
                                'space_name': space_name,
                                'region': region,
                                'evidence': f'Space listing accessible - {file_count} files found',
                                'description': 'Digital Ocean Space is publicly accessible',
                                'cwe': 'CWE-200',
                                'impact': 'Data exposure, potential data breach',
                                'remediation': 'Set Space to private, use signed URLs'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] CRITICAL: Public DO Space found - {space_name}")
                            return

                except:
                    pass

    def _generate_bucket_names(self, domain):
        """Generate potential bucket names from domain"""
        # Extract base name from domain
        domain_parts = domain.replace('www.', '').split('.')
        base_name = domain_parts[0]

        bucket_names = [
            base_name,
            f'{base_name}-prod',
            f'{base_name}-production',
            f'{base_name}-dev',
            f'{base_name}-development',
            f'{base_name}-staging',
            f'{base_name}-test',
            f'{base_name}-backup',
            f'{base_name}-backups',
            f'{base_name}-data',
            f'{base_name}-assets',
            f'{base_name}-static',
            f'{base_name}-media',
            f'{base_name}-uploads',
            f'{base_name}-files',
            f'{base_name}-public',
            f'{base_name}-private',
            domain.replace('.', '-'),
            domain.replace('.', ''),
            f'www-{base_name}',
            f'{base_name}-www',
        ]

        return bucket_names

    def _save_results(self):
        """Save results to file"""
        results = {
            'target': self.target_domain,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total': len(self.vulnerabilities),
                'critical': sum(1 for v in self.vulnerabilities if v['severity'] == 'critical'),
                'low': sum(1 for v in self.vulnerabilities if v['severity'] == 'low')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 cloud_storage_scanner.py <domain> [output_file]")
        print("\nExample:")
        print("  python3 cloud_storage_scanner.py example.com")
        print("\nScans for:")
        print("  - AWS S3 buckets (public and access denied)")
        print("  - Azure Blob Storage containers")
        print("  - Google Cloud Storage buckets")
        print("  - Digital Ocean Spaces")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    scanner = CloudStorageScanner(target, output)
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    Low: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'low')}")
