#!/usr/bin/env python3
"""
Vulnerability Scanner Orchestrator
Automated testing for common web vulnerabilities
"""

import argparse
import subprocess
import threading
import time
import os
import json
from datetime import datetime
from pathlib import Path
import sys

# Add tools directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'tools'))

from vuln.xss_scanner import XSSScanner
from vuln.sqli_tester import SQLiTester
from vuln.ssrf_tester import SSRFTester
from vuln.cors_checker import CORSChecker
from vuln.api_scanner import APIScanner
from vuln.jwt_analyzer import JWTAnalyzer
from vuln.bola_tester import BOLATester
from vuln.graphql_scanner import GraphQLScanner

class Colors:
    """Terminal colors"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class VulnScanner:
    """Orchestrates vulnerability scanning"""

    def __init__(self, target, output_dir, config_file=None):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = {}
        self.threads = []
        self.vulnerabilities_found = []

    def print_banner(self):
        """Print banner"""
        banner = f"""
{Colors.FAIL}{'='*70}
  _    __      __         _____
 | |  / /_  __/ /___     / ___/_________ _____  ____  ___  _____
 | | / / / / / / __ \    \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 | |/ / /_/ / / / / /   ___/ / /__/ /_/ / / / / / / /  __/ /
 |___/\__,_/_/_/ /_/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/

    Target: {self.target}
    Output: {self.output_dir}
    Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
{'='*70}{Colors.ENDC}
"""
        print(banner)

    def run_xss_scan(self):
        """Run XSS vulnerability scanner"""
        print(f"{Colors.OKBLUE}[*] Starting XSS Scanner...{Colors.ENDC}")

        output_file = self.output_dir / "xss_results.json"
        scanner = XSSScanner(self.target, output_file)

        thread = threading.Thread(target=self._execute_scan, args=("XSS", scanner))
        thread.start()
        self.threads.append(thread)

    def run_sqli_scan(self):
        """Run SQL Injection scanner"""
        print(f"{Colors.OKBLUE}[*] Starting SQLi Scanner...{Colors.ENDC}")

        output_file = self.output_dir / "sqli_results.json"
        scanner = SQLiTester(self.target, output_file)

        thread = threading.Thread(target=self._execute_scan, args=("SQLi", scanner))
        thread.start()
        self.threads.append(thread)

    def run_ssrf_scan(self):
        """Run SSRF vulnerability scanner"""
        print(f"{Colors.OKBLUE}[*] Starting SSRF Scanner...{Colors.ENDC}")

        output_file = self.output_dir / "ssrf_results.json"
        scanner = SSRFTester(self.target, output_file)

        thread = threading.Thread(target=self._execute_scan, args=("SSRF", scanner))
        thread.start()
        self.threads.append(thread)

    def run_cors_check(self):
        """Check CORS misconfigurations"""
        print(f"{Colors.OKBLUE}[*] Starting CORS Checker...{Colors.ENDC}")

        output_file = self.output_dir / "cors_results.json"
        checker = CORSChecker(self.target, output_file)

        thread = threading.Thread(target=self._execute_scan, args=("CORS", checker))
        thread.start()
        self.threads.append(thread)

    def run_api_scan(self):
        """Run API vulnerability scanner"""
        print(f"{Colors.OKBLUE}[*] Starting API Scanner...{Colors.ENDC}")

        output_file = self.output_dir / "api_results.json"
        scanner = APIScanner(self.target, output_file)

        thread = threading.Thread(target=self._execute_scan, args=("API", scanner))
        thread.start()
        self.threads.append(thread)

    def run_bola_test(self, auth_token=None):
        """Run BOLA/IDOR tester"""
        print(f"{Colors.OKBLUE}[*] Starting BOLA/IDOR Tester...{Colors.ENDC}")

        output_file = self.output_dir / "bola_results.json"
        tester = BOLATester(self.target, auth_token, output_file)

        thread = threading.Thread(target=self._execute_scan, args=("BOLA", tester))
        thread.start()
        self.threads.append(thread)

    def run_graphql_scan(self):
        """Run GraphQL vulnerability scanner"""
        print(f"{Colors.OKBLUE}[*] Starting GraphQL Scanner...{Colors.ENDC}")

        output_file = self.output_dir / "graphql_results.json"
        scanner = GraphQLScanner(self.target, output_file)

        thread = threading.Thread(target=self._execute_scan, args=("GraphQL", scanner))
        thread.start()
        self.threads.append(thread)

    def run_jwt_analysis(self, token):
        """Run JWT token analysis"""
        print(f"{Colors.OKBLUE}[*] Starting JWT Analyzer...{Colors.ENDC}")

        output_file = self.output_dir / "jwt_results.json"
        analyzer = JWTAnalyzer(token, self.target, output_file)

        thread = threading.Thread(target=self._execute_scan, args=("JWT", analyzer))
        thread.start()
        self.threads.append(thread)

    def run_nuclei(self):
        """Run Nuclei for CVE scanning"""
        print(f"{Colors.OKBLUE}[*] Starting Nuclei CVE Scanner...{Colors.ENDC}")

        if not self._check_tool_installed('nuclei'):
            return

        output_file = self.output_dir / "nuclei_cve.json"
        cmd = f"nuclei -u {self.target} -o {output_file} -json -severity critical,high,medium"

        thread = threading.Thread(
            target=self._run_command,
            args=("Nuclei", cmd, output_file)
        )
        thread.start()
        self.threads.append(thread)

    def run_sqlmap(self):
        """Run SQLMap for advanced SQL injection"""
        print(f"{Colors.OKBLUE}[*] Starting SQLMap...{Colors.ENDC}")

        if not self._check_tool_installed('sqlmap'):
            return

        output_dir = self.output_dir / "sqlmap"
        output_dir.mkdir(exist_ok=True)

        cmd = f"sqlmap -u '{self.target}' --batch --random-agent --level=2 --risk=2 --output-dir={output_dir}"

        thread = threading.Thread(
            target=self._run_command,
            args=("SQLMap", cmd, output_dir / "sqlmap.log")
        )
        thread.start()
        self.threads.append(thread)

    def _execute_scan(self, name, scanner):
        """Execute a custom scanner"""
        start_time = time.time()
        try:
            results = scanner.scan()
            elapsed = time.time() - start_time

            if results and results.get('vulnerabilities'):
                self.vulnerabilities_found.extend(results['vulnerabilities'])
                print(f"{Colors.WARNING}[!] {name}: Found {len(results['vulnerabilities'])} potential vulnerabilities{Colors.ENDC}")
            else:
                print(f"{Colors.OKGREEN}[✓] {name}: No vulnerabilities found{Colors.ENDC}")

            self.results[name] = {
                'status': 'success',
                'duration': elapsed,
                'vulnerabilities': len(results.get('vulnerabilities', []))
            }
        except Exception as e:
            print(f"{Colors.FAIL}[✗] {name} failed: {str(e)}{Colors.ENDC}")
            self.results[name] = {'status': 'failed', 'error': str(e)}

    def _run_command(self, name, command, output_file):
        """Execute external tool command"""
        start_time = time.time()
        try:
            with open(output_file, 'w') as f:
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True
                )
                _, stderr = process.communicate(timeout=1800)  # 30 min timeout

                elapsed = time.time() - start_time

                if process.returncode == 0:
                    print(f"{Colors.OKGREEN}[✓] {name} completed in {elapsed:.2f}s{Colors.ENDC}")
                    self.results[name] = {'status': 'success', 'duration': elapsed}
                else:
                    print(f"{Colors.WARNING}[!] {name} finished with warnings{Colors.ENDC}")
                    self.results[name] = {'status': 'warning', 'duration': elapsed}
        except Exception as e:
            print(f"{Colors.FAIL}[✗] {name} failed: {str(e)}{Colors.ENDC}")
            self.results[name] = {'status': 'failed', 'error': str(e)}

    def _check_tool_installed(self, tool_name):
        """Check if tool is installed"""
        result = subprocess.run(
            ['which', tool_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        installed = result.returncode == 0
        if not installed:
            print(f"{Colors.WARNING}[!] {tool_name} not installed, skipping...{Colors.ENDC}")
        return installed

    def wait_for_completion(self):
        """Wait for all scans"""
        print(f"\n{Colors.OKBLUE}[*] Waiting for all scans to complete...{Colors.ENDC}\n")
        for thread in self.threads:
            thread.join()

    def generate_report(self):
        """Generate vulnerability report"""
        report_file = self.output_dir / f"vuln_report_{self.timestamp}.json"

        report = {
            'target': self.target,
            'timestamp': self.timestamp,
            'scan_results': self.results,
            'vulnerabilities': self.vulnerabilities_found,
            'summary': {
                'total_scans': len(self.results),
                'total_vulnerabilities': len(self.vulnerabilities_found),
                'critical': sum(1 for v in self.vulnerabilities_found if v.get('severity') == 'critical'),
                'high': sum(1 for v in self.vulnerabilities_found if v.get('severity') == 'high'),
                'medium': sum(1 for v in self.vulnerabilities_found if v.get('severity') == 'medium'),
                'low': sum(1 for v in self.vulnerabilities_found if v.get('severity') == 'low')
            }
        }

        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        # Print summary
        print(f"\n{Colors.FAIL if report['summary']['total_vulnerabilities'] > 0 else Colors.OKGREEN}{'='*70}")
        print(f"[✓] Vulnerability Scan Complete!")
        print(f"    Results: {self.output_dir}")
        print(f"    Report: {report_file}")
        print(f"\n    Vulnerabilities Found: {report['summary']['total_vulnerabilities']}")
        if report['summary']['total_vulnerabilities'] > 0:
            print(f"      Critical: {report['summary']['critical']}")
            print(f"      High:     {report['summary']['high']}")
            print(f"      Medium:   {report['summary']['medium']}")
            print(f"      Low:      {report['summary']['low']}")
        print(f"{'='*70}{Colors.ENDC}\n")

    def run_full_scan(self, jwt_token=None, auth_token=None):
        """Run all vulnerability scans"""
        self.print_banner()

        print(f"\n{Colors.HEADER}[Phase 1] Web Vulnerability Scanners{Colors.ENDC}")
        self.run_xss_scan()
        self.run_sqli_scan()
        self.run_ssrf_scan()
        self.run_cors_check()

        print(f"\n{Colors.HEADER}[Phase 2] API Security Testing{Colors.ENDC}")
        self.run_api_scan()
        self.run_bola_test(auth_token)
        self.run_graphql_scan()

        if jwt_token:
            self.run_jwt_analysis(jwt_token)

        print(f"\n{Colors.HEADER}[Phase 3] External Tool Scans{Colors.ENDC}")
        self.run_nuclei()
        self.run_sqlmap()

        self.wait_for_completion()
        self.generate_report()


def main():
    parser = argparse.ArgumentParser(
        description="Vulnerability scanner orchestrator with API security testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Full vulnerability scan:
    python3 vuln_scanner.py -u https://example.com -o results/vulns

  Specific scans:
    python3 vuln_scanner.py -u https://example.com -o results/vulns --xss --sqli

  API testing with authentication:
    python3 vuln_scanner.py -u https://api.example.com -o results/api --api --bola --token YOUR_JWT

  GraphQL testing:
    python3 vuln_scanner.py -u https://api.example.com/graphql -o results/gql --graphql
        """
    )

    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-o', '--output', required=True, help='Output directory')

    # Web vulnerability scans
    parser.add_argument('--xss', action='store_true', help='Run XSS scanner only')
    parser.add_argument('--sqli', action='store_true', help='Run SQLi scanner only')
    parser.add_argument('--ssrf', action='store_true', help='Run SSRF scanner only')
    parser.add_argument('--cors', action='store_true', help='Run CORS checker only')

    # API security scans
    parser.add_argument('--api', action='store_true', help='Run API vulnerability scanner')
    parser.add_argument('--bola', action='store_true', help='Run BOLA/IDOR tester')
    parser.add_argument('--graphql', action='store_true', help='Run GraphQL scanner')
    parser.add_argument('--jwt', action='store_true', help='Run JWT analyzer')

    # Authentication tokens
    parser.add_argument('--token', help='JWT or Bearer token for authenticated scans')
    parser.add_argument('--auth-token', help='Separate auth token for BOLA testing')

    args = parser.parse_args()

    scanner = VulnScanner(args.url, args.output)

    specific_scan = args.xss or args.sqli or args.ssrf or args.cors or args.api or args.bola or args.graphql or args.jwt

    if specific_scan:
        scanner.print_banner()
        if args.xss:
            scanner.run_xss_scan()
        if args.sqli:
            scanner.run_sqli_scan()
        if args.ssrf:
            scanner.run_ssrf_scan()
        if args.cors:
            scanner.run_cors_check()
        if args.api:
            scanner.run_api_scan()
        if args.bola:
            scanner.run_bola_test(args.auth_token or args.token)
        if args.graphql:
            scanner.run_graphql_scan()
        if args.jwt and args.token:
            scanner.run_jwt_analysis(args.token)
        elif args.jwt and not args.token:
            print(f"{Colors.WARNING}[!] --jwt requires --token parameter{Colors.ENDC}")

        scanner.wait_for_completion()
        scanner.generate_report()
    else:
        scanner.run_full_scan(jwt_token=args.token, auth_token=args.auth_token or args.token)


if __name__ == "__main__":
    main()
