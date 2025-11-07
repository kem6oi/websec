#!/usr/bin/env python3
"""
Reconnaissance Orchestrator
Multi-threaded security reconnaissance tool launcher
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

class Colors:
    """Terminal colors for output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ReconOrchestrator:
    """Orchestrates parallel execution of reconnaissance tools"""

    def __init__(self, target, output_dir, config_file=None):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = {}
        self.threads = []
        self.config = self.load_config(config_file)

    def load_config(self, config_file):
        """Load configuration from file or use defaults"""
        default_config = {
            "subdomain_wordlist": "wordlists/subdomains.txt",
            "directory_wordlist": "wordlists/directories.txt",
            "threads": 50,
            "timeout": 3600,
            "rate_limit": 100
        }

        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                return json.load(f)
        return default_config

    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{Colors.OKCYAN}{'='*70}
    ____                        ____
   / __ \___  _________  ____  / __ \________  ______  ___  _____
  / /_/ / _ \/ ___/ __ \/ __ \/ /_/ / ___/ / / / __ \/ _ \/ ___/
 / _, _/  __/ /__/ /_/ / / / / _, _/ /  / /_/ / / / /  __/ /
/_/ |_|\___/\___/\____/_/ /_/_/ |_/_/   \__,_/_/ /_/\___/_/

    Target: {self.target}
    Output: {self.output_dir}
    Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
{'='*70}{Colors.ENDC}
"""
        print(banner)

    def run_command(self, name, command, output_file):
        """Execute a command and capture output"""
        start_time = time.time()
        print(f"{Colors.OKBLUE}[*] Starting {name}...{Colors.ENDC}")

        try:
            with open(output_file, 'w') as f:
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True
                )
                _, stderr = process.communicate(timeout=self.config.get('timeout', 3600))

                elapsed = time.time() - start_time

                if process.returncode == 0:
                    print(f"{Colors.OKGREEN}[✓] {name} completed in {elapsed:.2f}s{Colors.ENDC}")
                    self.results[name] = {
                        'status': 'success',
                        'output_file': str(output_file),
                        'duration': elapsed
                    }
                else:
                    print(f"{Colors.WARNING}[!] {name} finished with errors{Colors.ENDC}")
                    self.results[name] = {
                        'status': 'error',
                        'output_file': str(output_file),
                        'error': stderr,
                        'duration': elapsed
                    }
        except subprocess.TimeoutExpired:
            print(f"{Colors.FAIL}[✗] {name} timed out{Colors.ENDC}")
            self.results[name] = {'status': 'timeout', 'output_file': str(output_file)}
        except Exception as e:
            print(f"{Colors.FAIL}[✗] {name} failed: {str(e)}{Colors.ENDC}")
            self.results[name] = {'status': 'failed', 'error': str(e)}

    def run_subdomain_enum(self):
        """Run subdomain enumeration tools"""
        output_dir = self.output_dir / "subdomains"
        output_dir.mkdir(exist_ok=True)

        # Subfinder
        if self.check_tool_installed('subfinder'):
            cmd = f"subfinder -d {self.target} -o {output_dir}/subfinder.txt -silent"
            thread = threading.Thread(
                target=self.run_command,
                args=("Subfinder", cmd, output_dir / "subfinder.txt")
            )
            thread.start()
            self.threads.append(thread)

        # Assetfinder
        if self.check_tool_installed('assetfinder'):
            cmd = f"assetfinder --subs-only {self.target} > {output_dir}/assetfinder.txt"
            thread = threading.Thread(
                target=self.run_command,
                args=("Assetfinder", cmd, output_dir / "assetfinder.txt")
            )
            thread.start()
            self.threads.append(thread)

        # crt.sh via curl
        cmd = f"curl -s 'https://crt.sh/?q=%.{self.target}&output=json' | jq -r '.[].name_value' | sort -u > {output_dir}/crtsh.txt"
        thread = threading.Thread(
            target=self.run_command,
            args=("crt.sh", cmd, output_dir / "crtsh.txt")
        )
        thread.start()
        self.threads.append(thread)

    def run_port_scan(self, targets_file=None):
        """Run port scanning"""
        output_dir = self.output_dir / "ports"
        output_dir.mkdir(exist_ok=True)

        target = targets_file if targets_file else self.target

        # Nmap
        if self.check_tool_installed('nmap'):
            cmd = f"nmap -sV -sC -oN {output_dir}/nmap_scan.txt {target}"
            thread = threading.Thread(
                target=self.run_command,
                args=("Nmap", cmd, output_dir / "nmap_scan.txt")
            )
            thread.start()
            self.threads.append(thread)

        # Rustscan (if available)
        if self.check_tool_installed('rustscan'):
            cmd = f"rustscan -a {target} --ulimit 5000 > {output_dir}/rustscan.txt"
            thread = threading.Thread(
                target=self.run_command,
                args=("Rustscan", cmd, output_dir / "rustscan.txt")
            )
            thread.start()
            self.threads.append(thread)

    def run_directory_scan(self, target_url):
        """Run directory/file enumeration"""
        output_dir = self.output_dir / "directories"
        output_dir.mkdir(exist_ok=True)

        wordlist = self.config.get('directory_wordlist', 'wordlists/directories.txt')

        # Gobuster
        if self.check_tool_installed('gobuster'):
            cmd = f"gobuster dir -u {target_url} -w {wordlist} -o {output_dir}/gobuster.txt -t 50 -q"
            thread = threading.Thread(
                target=self.run_command,
                args=("Gobuster", cmd, output_dir / "gobuster.txt")
            )
            thread.start()
            self.threads.append(thread)

        # Ffuf
        if self.check_tool_installed('ffuf'):
            cmd = f"ffuf -u {target_url}/FUZZ -w {wordlist} -o {output_dir}/ffuf.json -of json -s"
            thread = threading.Thread(
                target=self.run_command,
                args=("Ffuf", cmd, output_dir / "ffuf.json")
            )
            thread.start()
            self.threads.append(thread)

        # Dirsearch
        if self.check_tool_installed('dirsearch'):
            cmd = f"dirsearch -u {target_url} -w {wordlist} -o {output_dir}/dirsearch.txt --format=plain"
            thread = threading.Thread(
                target=self.run_command,
                args=("Dirsearch", cmd, output_dir / "dirsearch.txt")
            )
            thread.start()
            self.threads.append(thread)

    def run_web_probe(self, targets_file):
        """Run HTTP probing on list of domains"""
        output_dir = self.output_dir / "probes"
        output_dir.mkdir(exist_ok=True)

        # Httpx
        if self.check_tool_installed('httpx'):
            cmd = f"httpx -l {targets_file} -o {output_dir}/httpx.txt -title -status-code -tech-detect -silent"
            thread = threading.Thread(
                target=self.run_command,
                args=("Httpx", cmd, output_dir / "httpx.txt")
            )
            thread.start()
            self.threads.append(thread)

    def run_nuclei_scan(self, targets_file):
        """Run Nuclei vulnerability scanner"""
        output_dir = self.output_dir / "vulnerabilities"
        output_dir.mkdir(exist_ok=True)

        if self.check_tool_installed('nuclei'):
            cmd = f"nuclei -l {targets_file} -o {output_dir}/nuclei.txt -silent -severity critical,high,medium"
            thread = threading.Thread(
                target=self.run_command,
                args=("Nuclei", cmd, output_dir / "nuclei.txt")
            )
            thread.start()
            self.threads.append(thread)

    def check_tool_installed(self, tool_name):
        """Check if a tool is installed"""
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
        """Wait for all threads to complete"""
        print(f"\n{Colors.OKBLUE}[*] Waiting for all scans to complete...{Colors.ENDC}\n")
        for thread in self.threads:
            thread.join()

    def generate_report(self):
        """Generate summary report"""
        report_file = self.output_dir / f"report_{self.timestamp}.json"

        report = {
            'target': self.target,
            'timestamp': self.timestamp,
            'results': self.results,
            'summary': {
                'total': len(self.results),
                'successful': sum(1 for r in self.results.values() if r.get('status') == 'success'),
                'failed': sum(1 for r in self.results.values() if r.get('status') == 'failed'),
                'timeout': sum(1 for r in self.results.values() if r.get('status') == 'timeout')
            }
        }

        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n{Colors.OKGREEN}{'='*70}")
        print(f"[✓] Reconnaissance Complete!")
        print(f"    Results saved to: {self.output_dir}")
        print(f"    Report: {report_file}")
        print(f"    Successful: {report['summary']['successful']}/{report['summary']['total']}")
        print(f"{'='*70}{Colors.ENDC}\n")

    def run_full_recon(self):
        """Run complete reconnaissance suite"""
        self.print_banner()

        # Phase 1: Subdomain Enumeration
        print(f"\n{Colors.HEADER}[Phase 1] Subdomain Enumeration{Colors.ENDC}")
        self.run_subdomain_enum()

        # Wait for subdomain enum to complete
        for thread in self.threads:
            thread.join()

        # Merge subdomain results
        merged_subdomains = self.output_dir / "subdomains" / "all_subdomains.txt"
        self.merge_files(
            self.output_dir / "subdomains",
            merged_subdomains,
            ['subfinder.txt', 'assetfinder.txt', 'crtsh.txt']
        )

        # Phase 2: Web Probing
        if merged_subdomains.exists():
            print(f"\n{Colors.HEADER}[Phase 2] Web Probing{Colors.ENDC}")
            self.run_web_probe(merged_subdomains)

            for thread in self.threads[len(self.threads)-1:]:
                thread.join()

            # Phase 3: Vulnerability Scanning
            httpx_results = self.output_dir / "probes" / "httpx.txt"
            if httpx_results.exists():
                print(f"\n{Colors.HEADER}[Phase 3] Vulnerability Scanning{Colors.ENDC}")
                self.run_nuclei_scan(httpx_results)

        # Wait for all remaining threads
        self.wait_for_completion()

        # Generate report
        self.generate_report()

    def merge_files(self, directory, output_file, filenames):
        """Merge and deduplicate multiple files"""
        unique_lines = set()

        for filename in filenames:
            filepath = directory / filename
            if filepath.exists():
                with open(filepath, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            unique_lines.add(line)

        with open(output_file, 'w') as f:
            for line in sorted(unique_lines):
                f.write(f"{line}\n")

        print(f"{Colors.OKGREEN}[✓] Merged {len(unique_lines)} unique entries to {output_file.name}{Colors.ENDC}")


def main():
    parser = argparse.ArgumentParser(
        description="Multi-threaded reconnaissance orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Full reconnaissance:
    python3 recon_runner.py -d example.com -o results/example

  Subdomain enumeration only:
    python3 recon_runner.py -d example.com -o results/example --subdomains-only

  Directory scanning:
    python3 recon_runner.py -u https://example.com -o results/example --dirs-only
        """
    )

    parser.add_argument('-d', '--domain', help='Target domain')
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-o', '--output', required=True, help='Output directory')
    parser.add_argument('-c', '--config', help='Config file (JSON)')
    parser.add_argument('--subdomains-only', action='store_true', help='Only run subdomain enumeration')
    parser.add_argument('--dirs-only', action='store_true', help='Only run directory scanning')
    parser.add_argument('--ports-only', action='store_true', help='Only run port scanning')

    args = parser.parse_args()

    if not args.domain and not args.url:
        parser.error("Either --domain or --url is required")

    target = args.domain if args.domain else args.url
    orchestrator = ReconOrchestrator(target, args.output, args.config)

    if args.subdomains_only:
        orchestrator.print_banner()
        orchestrator.run_subdomain_enum()
        orchestrator.wait_for_completion()
        orchestrator.generate_report()
    elif args.dirs_only:
        if not args.url:
            parser.error("--url is required for directory scanning")
        orchestrator.print_banner()
        orchestrator.run_directory_scan(args.url)
        orchestrator.wait_for_completion()
        orchestrator.generate_report()
    elif args.ports_only:
        orchestrator.print_banner()
        orchestrator.run_port_scan()
        orchestrator.wait_for_completion()
        orchestrator.generate_report()
    else:
        # Full reconnaissance
        orchestrator.run_full_recon()


if __name__ == "__main__":
    main()
