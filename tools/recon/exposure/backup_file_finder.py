#!/usr/bin/env python3
"""
Backup File Finder
Discovers exposed backup files, version control directories, configuration files,
and database dumps that may contain sensitive information
"""

import requests
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

class BackupFileFinder:
    """Scanner for exposed backup and sensitive files"""

    def __init__(self, target_url, threads=10, output_file=None):
        self.target_url = target_url
        self.threads = threads
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        # Parse base URL
        parsed = urlparse(target_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.domain = parsed.netloc.replace('www.', '')

    def scan(self):
        """Run backup file scanning"""
        print(f"[*] Starting backup file scanning on {self.target_url}")

        # Test common backup files
        self._test_backup_files()

        # Test version control directories
        self._test_version_control()

        # Test config files
        self._test_config_files()

        # Test database dumps
        self._test_database_dumps()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_backup_files(self):
        """Test for common backup file patterns"""
        print("[*] Testing for backup files...")

        # Common backup extensions and patterns
        backup_patterns = [
            '.bak',
            '.backup',
            '.old',
            '.orig',
            '.save',
            '.copy',
            '~',
            '.swp',
            '.swo',
            '.tmp',
            '.temp',
            '_backup',
            '_old',
            '.BAK',
            '.BACKUP',
        ]

        # Common file names
        common_files = [
            'index',
            'admin',
            'config',
            'database',
            'db',
            'backup',
            'data',
            'login',
            'user',
            'users',
            'account',
            'settings',
        ]

        # File extensions
        extensions = ['php', 'asp', 'aspx', 'jsp', 'js', 'html', 'htm', 'txt', 'sql', 'zip', 'tar', 'gz']

        test_urls = []

        # Generate test URLs
        for file_name in common_files:
            for ext in extensions:
                for backup_ext in backup_patterns:
                    test_urls.append(f'{self.base_url}/{file_name}.{ext}{backup_ext}')
                    test_urls.append(f'{self.base_url}/{file_name}{backup_ext}.{ext}')

        # Also test direct backup patterns
        for backup_ext in backup_patterns:
            test_urls.append(f'{self.base_url}/backup{backup_ext}')
            test_urls.append(f'{self.base_url}/web{backup_ext}')
            test_urls.append(f'{self.base_url}/www{backup_ext}')

        self._test_urls_threaded(test_urls, 'Backup File')

    def _test_version_control(self):
        """Test for exposed version control directories"""
        print("[*] Testing for version control directories...")

        vcs_paths = [
            # Git
            '.git/HEAD',
            '.git/config',
            '.git/index',
            '.git/logs/HEAD',
            '.git/refs/heads/master',
            '.git/refs/heads/main',
            '.git/COMMIT_EDITMSG',

            # SVN
            '.svn/entries',
            '.svn/wc.db',
            '.svn/all-wcprops',

            # Mercurial
            '.hg/requires',
            '.hg/store/00manifest.i',

            # Bazaar
            '.bzr/branch/last-revision',

            # CVS
            'CVS/Entries',
            'CVS/Root',
        ]

        test_urls = [urljoin(self.base_url, path) for path in vcs_paths]
        self._test_urls_threaded(test_urls, 'Version Control Exposure')

    def _test_config_files(self):
        """Test for exposed configuration files"""
        print("[*] Testing for configuration files...")

        config_files = [
            # Environment files
            '.env',
            '.env.local',
            '.env.development',
            '.env.production',
            '.env.backup',
            'env',
            'env.txt',

            # Configuration files
            'config.php',
            'config.inc.php',
            'configuration.php',
            'settings.php',
            'config.json',
            'config.xml',
            'config.yml',
            'config.yaml',
            'application.properties',
            'application.yml',
            'database.yml',
            'credentials.json',
            'secrets.json',

            # Web server configs
            'web.config',
            '.htaccess',
            '.htpasswd',
            'nginx.conf',
            'httpd.conf',

            # IDE and editor files
            '.vscode/settings.json',
            '.idea/workspace.xml',
            'nbproject/project.properties',

            # Docker and deployment
            'docker-compose.yml',
            'Dockerfile',
            '.dockerignore',

            # Package managers
            'composer.json',
            'package.json',
            'package-lock.json',
            'yarn.lock',
            'Gemfile',
            'requirements.txt',
        ]

        test_urls = [urljoin(self.base_url, f) for f in config_files]
        self._test_urls_threaded(test_urls, 'Configuration File')

    def _test_database_dumps(self):
        """Test for exposed database dumps"""
        print("[*] Testing for database dumps...")

        # Database dump files
        db_dumps = [
            'dump.sql',
            'backup.sql',
            'database.sql',
            'db.sql',
            'data.sql',
            'mysql.sql',
            'postgres.sql',
            'db_backup.sql',
            f'{self.domain}.sql',
            f'{self.domain.split(".")[0]}.sql',

            # SQLite
            'database.db',
            'db.sqlite',
            'db.sqlite3',
            'data.db',
            'app.db',

            # Compressed dumps
            'backup.sql.gz',
            'backup.sql.zip',
            'database.sql.gz',
            'db.sql.tar.gz',
            'dump.sql.bz2',

            # Other database files
            'backup.mdb',
            'database.mdb',
            'data.mdf',
        ]

        test_urls = [urljoin(self.base_url, f) for f in db_dumps]
        self._test_urls_threaded(test_urls, 'Database Dump')

    def _test_urls_threaded(self, urls, vuln_type):
        """Test multiple URLs in parallel"""
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._test_single_url, url, vuln_type): url for url in urls}

            for future in as_completed(futures):
                try:
                    future.result()
                except:
                    pass

    def _test_single_url(self, url, vuln_type):
        """Test a single URL for accessibility"""
        try:
            response = self.session.get(url, timeout=10, allow_redirects=False)

            # Check if file is accessible
            if response.status_code == 200:
                content_length = len(response.content)

                # Additional checks for specific file types
                severity = 'high'
                evidence = f'File accessible - {content_length} bytes'

                # Check for specific patterns
                if '.git' in url:
                    severity = 'critical'
                    evidence = 'Git repository exposed - source code disclosure'
                elif '.env' in url:
                    severity = 'critical'
                    evidence = 'Environment file exposed - credentials likely present'
                elif '.sql' in url or '.db' in url:
                    severity = 'critical'
                    evidence = f'Database dump accessible - {content_length} bytes'
                elif 'config' in url.lower():
                    severity = 'critical'
                    evidence = 'Configuration file accessible'
                elif url.endswith(('~', '.bak', '.backup', '.old')):
                    severity = 'high'
                    evidence = f'Backup file accessible - {content_length} bytes'

                # Additional validation - check content
                content_preview = response.text[:200]
                if 'password' in content_preview.lower() or 'secret' in content_preview.lower():
                    severity = 'critical'
                    evidence += ' - Contains passwords/secrets'

                vuln = {
                    'type': f'Exposed {vuln_type}',
                    'severity': severity,
                    'url': url,
                    'evidence': evidence,
                    'size': content_length,
                    'description': f'{vuln_type} is publicly accessible',
                    'cwe': 'CWE-200',
                    'impact': 'Information disclosure, source code exposure, credential leakage',
                    'remediation': 'Remove sensitive files from public web root'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] {severity.upper()}: Found {vuln_type} - {url}")

        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.ConnectionError:
            pass
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
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 backup_file_finder.py <url> [threads] [output_file]")
        print("\nExample:")
        print("  python3 backup_file_finder.py https://example.com")
        print("  python3 backup_file_finder.py https://example.com 20 results.json")
        print("\nScans for:")
        print("  - Backup files (.bak, .old, ~, .swp)")
        print("  - Version control (.git, .svn, .hg)")
        print("  - Configuration files (.env, config.php, web.config)")
        print("  - Database dumps (.sql, .db, .sqlite)")
        sys.exit(1)

    target = sys.argv[1]
    threads = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 10
    output = sys.argv[3] if len(sys.argv) > 3 else (sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].isdigit() else None)

    finder = BackupFileFinder(target, threads, output)
    results = finder.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
