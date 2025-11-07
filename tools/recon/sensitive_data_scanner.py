#!/usr/bin/env python3
"""
Sensitive Data Exposure Scanner
Scans for exposed configuration files, backups, credentials, and sensitive information
"""

import requests
import json
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

class SensitiveDataScanner:
    """Scanner for sensitive data exposure"""

    def __init__(self, target_url, output_file=None, threads=10):
        self.target_url = target_url.rstrip('/')
        self.output_file = output_file
        self.threads = threads
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        parsed = urlparse(target_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Sensitive files and paths
        self.sensitive_files = [
            # Configuration files
            '.env',
            '.env.local',
            '.env.production',
            '.env.development',
            '.env.backup',
            'config.php',
            'config.php.bak',
            'configuration.php',
            'config.yml',
            'config.yaml',
            'config.json',
            'settings.py',
            'settings.php',
            'database.yml',
            'db.php',
            'wp-config.php',
            'wp-config.php.bak',
            'config.inc.php',
            'config.inc',
            'config.xml',
            'web.config',
            'web.config.bak',
            'application.properties',
            'application.yml',
            'application-prod.yml',
            'appsettings.json',

            # Backup files
            'backup.zip',
            'backup.tar.gz',
            'backup.sql',
            'dump.sql',
            'database.sql',
            'db_backup.sql',
            'backup.tar',
            'site-backup.zip',
            'www.zip',
            'wwwroot.zip',
            'public_html.zip',

            # Git files
            '.git/config',
            '.git/HEAD',
            '.git/index',
            '.git/logs/HEAD',
            '.gitignore',
            '.gitlab-ci.yml',
            '.github/workflows/main.yml',

            # SVN files
            '.svn/entries',
            '.svn/wc.db',

            # Docker files
            'Dockerfile',
            'docker-compose.yml',
            '.dockerignore',

            # Cloud files
            '.aws/credentials',
            '.aws/config',
            'credentials.json',
            'service-account.json',
            'gcp-key.json',
            'azure.json',

            # SSH keys
            '.ssh/id_rsa',
            '.ssh/id_dsa',
            '.ssh/authorized_keys',
            'id_rsa',
            'id_rsa.pub',

            # IDE files
            '.idea/workspace.xml',
            '.vscode/settings.json',
            '.project',
            '.classpath',

            # Log files
            'error.log',
            'access.log',
            'debug.log',
            'app.log',
            'laravel.log',
            'error_log',
            'access_log',

            # Database files
            'database.sqlite',
            'db.sqlite',
            'db.sqlite3',
            'database.db',

            # Common sensitive files
            'phpinfo.php',
            'info.php',
            'test.php',
            'adminer.php',
            'phpmyadmin/',
            'pma/',
            'admin/',
            'administrator/',
            'manager/',
            'readme.html',
            'README.md',
            'CHANGELOG',
            'package.json',
            'composer.json',
            'yarn.lock',
            'package-lock.json',

            # Sensitive endpoints
            'server-status',
            'server-info',
            'status',
            'health',
            'metrics',
            'debug',
            'trace',
            'console/',
            'actuator/',
            'actuator/health',
            'actuator/env',
            'actuator/metrics',

            # Common admin interfaces
            'admin.php',
            'login.php',
            'admin/config.php',
            'includes/config.php',
        ]

        # Directories to check
        self.directories = [
            '',
            'backup/',
            'backups/',
            'old/',
            'temp/',
            'tmp/',
            'test/',
            'demo/',
            'dev/',
            'admin/',
            'config/',
            'conf/',
            'include/',
            'includes/',
            'uploads/',
            'files/',
            'public/',
            'private/',
            'assets/',
            '.well-known/',
        ]

        # Sensitive patterns to search for in responses
        self.sensitive_patterns = {
            'API Keys': [
                r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})',
                r'(?i)apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})',
            ],
            'AWS Keys': [
                r'AKIA[0-9A-Z]{16}',
                r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})',
            ],
            'Private Keys': [
                r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
            ],
            'Passwords': [
                r'(?i)password["\']?\s*[:=]\s*["\']([^"\']{6,})',
                r'(?i)passwd["\']?\s*[:=]\s*["\']([^"\']{6,})',
                r'(?i)pwd["\']?\s*[:=]\s*["\']([^"\']{6,})',
            ],
            'Database Credentials': [
                r'(?i)db[_-]?password["\']?\s*[:=]\s*["\']([^"\']+)',
                r'(?i)database[_-]?password["\']?\s*[:=]\s*["\']([^"\']+)',
                r'(?i)mysql[_-]?password["\']?\s*[:=]\s*["\']([^"\']+)',
            ],
            'JWT Tokens': [
                r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            ],
            'Google API': [
                r'AIza[0-9A-Za-z_-]{35}',
            ],
            'Slack Tokens': [
                r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}',
            ],
            'GitHub Tokens': [
                r'gh[pousr]_[A-Za-z0-9_]{36,}',
            ],
        }

    def scan(self):
        """Run sensitive data exposure scan"""
        print(f"[*] Starting sensitive data exposure scan on {self.target_url}")
        print(f"[*] Testing {len(self.sensitive_files)} files across {len(self.directories)} directories")

        # Build list of URLs to test
        urls_to_test = []
        for directory in self.directories:
            for filename in self.sensitive_files:
                url = urljoin(self.base_url + '/', directory + filename)
                urls_to_test.append((url, filename))

        # Test URLs concurrently
        print(f"[*] Testing {len(urls_to_test)} potential sensitive files...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._test_url, url, filename): (url, filename)
                      for url, filename in urls_to_test}

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    pass

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'findings': self.findings
        }

    def _test_url(self, url, filename):
        """Test single URL for sensitive data"""
        try:
            response = self.session.get(url, timeout=10, allow_redirects=False)

            # Check if file exists
            if response.status_code == 200:
                # Analyze content
                self._analyze_response(url, filename, response)
            elif response.status_code == 403:
                # File exists but forbidden
                finding = {
                    'type': 'Exposed Sensitive File (Forbidden)',
                    'severity': 'medium',
                    'url': url,
                    'filename': filename,
                    'status_code': 403,
                    'evidence': 'File exists but access forbidden',
                    'description': 'Sensitive file exists and confirms directory structure',
                    'cwe': 'CWE-200'
                }
                self.findings.append(finding)
                print(f"[!] Found (403): {url}")

        except Exception as e:
            pass

    def _analyze_response(self, url, filename, response):
        """Analyze response for sensitive data"""
        content = response.text
        severity = 'medium'
        secrets_found = []

        # Check for sensitive patterns
        for pattern_type, patterns in self.sensitive_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content)
                if matches:
                    secrets_found.append(f"{pattern_type}: {len(matches)} match(es)")
                    severity = 'high'

        # Determine severity based on file type
        critical_files = ['.env', 'config.php', 'wp-config.php', '.git/config',
                         'id_rsa', '.aws/credentials', 'service-account.json']

        if any(cf in filename for cf in critical_files):
            severity = 'critical'

        # Check content type
        content_type = response.headers.get('Content-Type', '')

        # Check file size
        content_length = len(content)

        finding = {
            'type': 'Exposed Sensitive File',
            'severity': severity,
            'url': url,
            'filename': filename,
            'status_code': response.status_code,
            'content_type': content_type,
            'content_length': content_length,
            'secrets_found': secrets_found if secrets_found else None,
            'evidence': self._get_evidence(filename, content, secrets_found),
            'description': 'Sensitive file publicly accessible',
            'cwe': 'CWE-200',
            'recommendation': 'Remove or restrict access to sensitive files'
        }

        self.findings.append(finding)
        print(f"[!] Found [{severity.upper()}]: {url}")
        if secrets_found:
            for secret in secrets_found:
                print(f"    └─ {secret}")

    def _get_evidence(self, filename, content, secrets_found):
        """Generate evidence for the finding"""
        evidence = []

        # File type evidence
        if filename.endswith(('.env', '.config', '.yml', '.yaml', '.json')):
            evidence.append(f'Configuration file: {filename}')

        if '.git/' in filename:
            evidence.append('Git repository exposed')

        if '.ssh/' in filename or 'id_rsa' in filename:
            evidence.append('SSH key file exposed')

        if 'backup' in filename.lower() or filename.endswith(('.zip', '.tar', '.gz', '.sql')):
            evidence.append('Backup file accessible')

        # Content evidence
        if 'password' in content.lower()[:1000]:
            evidence.append('Contains password references')

        if 'secret' in content.lower()[:1000]:
            evidence.append('Contains secret references')

        if 'api_key' in content.lower()[:1000] or 'apikey' in content.lower()[:1000]:
            evidence.append('Contains API key references')

        # Secret findings
        if secrets_found:
            evidence.extend(secrets_found)

        return '; '.join(evidence) if evidence else 'Sensitive file accessible'

    def _save_results(self):
        """Save results to file"""
        results = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'findings': self.findings,
            'summary': {
                'total': len(self.findings),
                'critical': sum(1 for f in self.findings if f['severity'] == 'critical'),
                'high': sum(1 for f in self.findings if f['severity'] == 'high'),
                'medium': sum(1 for f in self.findings if f['severity'] == 'medium')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 sensitive_data_scanner.py <url> [output_file] [threads]")
        print("\nExample:")
        print("  python3 sensitive_data_scanner.py https://example.com")
        print("  python3 sensitive_data_scanner.py https://example.com results.json 20")
        print("\nScans for:")
        print("  - Configuration files (.env, config.php, etc.)")
        print("  - Backup files (.zip, .sql, etc.)")
        print("  - Git/SVN repositories")
        print("  - SSH keys and cloud credentials")
        print("  - Log files and debug endpoints")
        print("  - API keys, passwords, and secrets")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None
    threads = int(sys.argv[3]) if len(sys.argv) > 3 else 10

    scanner = SensitiveDataScanner(target, output, threads)
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total findings: {len(results['findings'])}")
    if len(results['findings']) > 0:
        print(f"    Critical: {sum(1 for f in results['findings'] if f['severity'] == 'critical')}")
        print(f"    High: {sum(1 for f in results['findings'] if f['severity'] == 'high')}")
        print(f"    Medium: {sum(1 for f in results['findings'] if f['severity'] == 'medium')}")
