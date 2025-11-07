# 🔒 WebSec - Web Security Testing Toolkit

A comprehensive, automated security testing and reconnaissance framework for bug bounty hunters and penetration testers. Built with Python, it orchestrates multiple security tools in parallel to maximize efficiency.

## 🎯 Features

### Reconnaissance Suite
- **Subdomain Enumeration**: subfinder, assetfinder, crt.sh integration
- **Web Probing**: httpx for live host detection with tech fingerprinting
- **Port Scanning**: nmap, rustscan integration
- **Directory Discovery**: gobuster, ffuf, dirsearch support
- **URL Collection**: waybackurls, gau, katana-compatible
- **Vulnerability Scanning**: Nuclei template-based scanning

### Vulnerability Testing
- **XSS Scanner**: Reflected, DOM-based, and stored XSS detection
- **SQL Injection**: Error-based, boolean-based, and time-based blind SQLi
- **SSRF Tester**: Cloud metadata endpoints, internal network access
- **CORS Checker**: Misconfiguration detection with credential testing
- **Integration**: SQLMap and Nuclei for advanced scanning

### API Security Testing (NEW! 🎉)
- **API Scanner**: OWASP API Security Top 10 vulnerabilities
- **JWT Analyzer**: Token decoding, weak secrets, algorithm confusion
- **BOLA/IDOR Tester**: Broken authorization and insecure direct object references
- **GraphQL Scanner**: Introspection, depth limits, batch queries, injection
- **Mass Assignment**: Parameter pollution and privilege escalation
- **Rate Limiting**: Resource exhaustion and DoS protection testing

### Advanced Features
- ⚡ **Parallel Execution**: Multi-threaded scanning with tmux sessions
- 📊 **Professional Reports**: HTML reports with severity classification
- 🎨 **Color-Coded Output**: Easy-to-read terminal output
- 🔧 **Configurable**: JSON-based configuration system
- 📝 **Comprehensive Logging**: Detailed logs for all operations
- 🎯 **Modular Design**: Easy to extend with custom modules

## 📁 Project Structure

```
websec/
├── orchestrator/
│   ├── recon_runner.py          # Main reconnaissance orchestrator
│   └── vuln_scanner.py          # Vulnerability scanner orchestrator
├── tools/
│   ├── recon/                   # Reconnaissance tools
│   ├── vuln/                    # Vulnerability testing modules
│   │   ├── xss_scanner.py      # XSS vulnerability scanner
│   │   ├── sqli_tester.py      # SQL injection tester
│   │   ├── ssrf_tester.py      # SSRF vulnerability scanner
│   │   ├── cors_checker.py     # CORS misconfiguration checker
│   │   ├── api_scanner.py      # API security scanner (NEW)
│   │   ├── jwt_analyzer.py     # JWT token analyzer (NEW)
│   │   ├── bola_tester.py      # BOLA/IDOR tester (NEW)
│   │   └── graphql_scanner.py  # GraphQL security scanner (NEW)
│   └── utils/                   # Utility tools
│       └── report_generator.py
├── wordlists/                   # Custom wordlists
│   ├── subdomains.txt
│   └── directories.txt
├── payloads/                    # Attack payloads
│   ├── xss_payloads.txt
│   └── sqli_payloads.txt
├── configs/                     # Configuration files
│   └── default_config.json
└── results/                     # Scan results output
```

## 🚀 Installation

### Prerequisites

```bash
# Python 3.8+
python3 --version

# Install Python dependencies
pip3 install requests beautifulsoup4 urllib3
```

### External Tools (Optional but Recommended)

```bash
# Subdomain enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest

# Web probing
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Vulnerability scanning
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# Directory enumeration
go install github.com/OJ/gobuster/v3@latest
go install github.com/ffuf/ffuf@latest

# Port scanning
sudo apt install nmap -y
cargo install rustscan

# SQL Injection
sudo apt install sqlmap -y

# Add Go bin to PATH
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Clone Repository

```bash
git clone <repository-url>
cd websec
chmod +x orchestrator/*.py tools/vuln/*.py
```

## 📖 Usage

### 1. Full Reconnaissance Suite

Run complete reconnaissance on a target domain:

```bash
python3 orchestrator/recon_runner.py -d example.com -o results/example
```

This will:
1. Enumerate subdomains (subfinder, assetfinder, crt.sh)
2. Probe live hosts (httpx)
3. Scan for vulnerabilities (nuclei)
4. Generate comprehensive report

### 2. Subdomain Enumeration Only

```bash
python3 orchestrator/recon_runner.py -d example.com -o results/example --subdomains-only
```

### 3. Directory Scanning

```bash
python3 orchestrator/recon_runner.py -u https://example.com -o results/example --dirs-only
```

### 4. Port Scanning

```bash
python3 orchestrator/recon_runner.py -d example.com -o results/example --ports-only
```

### 5. Vulnerability Scanning

Run all vulnerability tests:

```bash
python3 orchestrator/vuln_scanner.py -u https://example.com -o results/vulns
```

Run specific vulnerability tests:

```bash
# XSS only
python3 orchestrator/vuln_scanner.py -u https://example.com -o results/vulns --xss

# SQL Injection only
python3 orchestrator/vuln_scanner.py -u https://example.com -o results/vulns --sqli

# SSRF only
python3 orchestrator/vuln_scanner.py -u https://example.com -o results/vulns --ssrf

# CORS only
python3 orchestrator/vuln_scanner.py -u https://example.com -o results/vulns --cors
```

### 6. Individual Module Testing

Test XSS scanner directly:

```bash
python3 tools/vuln/xss_scanner.py "https://example.com/search?q=test"
```

Test SQL injection:

```bash
python3 tools/vuln/sqli_tester.py "https://example.com/product?id=1"
```

Test SSRF:

```bash
python3 tools/vuln/ssrf_tester.py "https://example.com/fetch?url=test"
```

Test CORS:

```bash
python3 tools/vuln/cors_checker.py "https://api.example.com"
```

### 6. API Security Testing

Test API vulnerabilities (OWASP API Top 10):

```bash
python3 tools/vuln/api_scanner.py "https://api.example.com/v1/users"
```

Analyze JWT tokens:

```bash
# Decode and analyze JWT
python3 tools/vuln/jwt_analyzer.py "eyJhbGciOiJIUzI1NiIs..."

# Test JWT on server
python3 tools/vuln/jwt_analyzer.py "eyJhbGciOiJIUzI1NiIs..." "https://api.example.com/user"
```

Test for BOLA/IDOR vulnerabilities:

```bash
# Without authentication
python3 tools/vuln/bola_tester.py "https://api.example.com/users/123"

# With JWT token
python3 tools/vuln/bola_tester.py "https://api.example.com/users/123" "eyJhbGciOiJIUzI1NiIs..."
```

Scan GraphQL endpoints:

```bash
python3 tools/vuln/graphql_scanner.py "https://api.example.com/graphql"
```

Run comprehensive API scan with authentication:

```bash
python3 orchestrator/vuln_scanner.py -u https://api.example.com -o results/api \
  --api --bola --graphql --jwt --token "eyJhbGciOiJIUzI1NiIs..."
```

### 7. Generate HTML Report

```bash
python3 tools/utils/report_generator.py results/example
```

## 🔧 Configuration

Edit `configs/default_config.json` to customize:

```json
{
  "reconnaissance": {
    "threads": 50,
    "timeout": 3600,
    "rate_limit": 100
  },
  "vulnerability_scanning": {
    "xss": {
      "enabled": true,
      "timeout": 10
    }
  }
}
```

Use custom config:

```bash
python3 orchestrator/recon_runner.py -d example.com -o results/example -c configs/custom.json
```

## 🎯 Reconnaissance Workflow

```
Target Domain
    │
    ├─► Subdomain Enumeration
    │   ├─► subfinder
    │   ├─► assetfinder
    │   └─► crt.sh
    │
    ├─► Merge & Deduplicate
    │
    ├─► Web Probing (httpx)
    │   └─► Live URLs
    │
    ├─► Vulnerability Scanning (nuclei)
    │
    └─► Generate Report
```

## 🐛 Vulnerability Testing Workflow

```
Target URL
    │
    ├─► XSS Scanner
    │   ├─► GET parameters
    │   ├─► POST forms
    │   └─► URL paths
    │
    ├─► SQL Injection
    │   ├─► Error-based
    │   ├─► Boolean-based blind
    │   └─► Time-based blind
    │
    ├─► SSRF Tester
    │   ├─► Internal IPs
    │   ├─► Cloud metadata
    │   └─► File protocols
    │
    ├─► CORS Checker
    │   ├─► Origin reflection
    │   ├─► Wildcard policies
    │   └─► Null origin
    │
    └─► Generate Report
```

## 🔐 API Security Testing Workflow

```
API Endpoint
    │
    ├─► API Scanner (OWASP API Top 10)
    │   ├─► Broken authentication
    │   ├─► Excessive data exposure
    │   ├─► Lack of rate limiting
    │   ├─► Mass assignment
    │   ├─► Security misconfiguration
    │   ├─► Injection flaws
    │   └─► HTTP verb tampering
    │
    ├─► JWT Analyzer
    │   ├─► Decode token
    │   ├─► Test 'none' algorithm
    │   ├─► Algorithm confusion
    │   ├─► Weak secret bruteforce
    │   ├─► Expiration check
    │   └─► Privilege escalation
    │
    ├─► BOLA/IDOR Tester
    │   ├─► Sequential ID enumeration
    │   ├─► UUID enumeration
    │   ├─► Horizontal escalation
    │   └─► Unauthorized access
    │
    ├─► GraphQL Scanner
    │   ├─► Introspection query
    │   ├─► Query depth limits
    │   ├─► Batch query limits
    │   ├─► Field suggestions
    │   └─► Injection testing
    │
    └─► Generate Report
```

## 📊 Output & Results

Results are organized by scan type:

```
results/example/
├── subdomains/
│   ├── subfinder.txt
│   ├── assetfinder.txt
│   ├── crtsh.txt
│   └── all_subdomains.txt
├── probes/
│   └── httpx.txt
├── vulnerabilities/
│   ├── nuclei.txt
│   ├── xss_results.json
│   ├── sqli_results.json
│   ├── ssrf_results.json
│   ├── cors_results.json
│   ├── api_results.json         # API security scan (NEW)
│   ├── jwt_results.json          # JWT analysis (NEW)
│   ├── bola_results.json         # BOLA/IDOR findings (NEW)
│   └── graphql_results.json      # GraphQL scan (NEW)
├── report_20231107_123456.json
└── report.html
```

## 🎨 Sample Report

The HTML report includes:
- **Executive Summary** with severity counts
- **Detailed Vulnerabilities** with PoC payloads
- **Discovered Assets** (subdomains, URLs)
- **Color-coded severity** (Critical, High, Medium, Low)
- **Professional formatting** for client delivery

## 🔐 Security & Ethics

### ⚠️ Important Warning

**This toolkit is for AUTHORIZED security testing ONLY.**

- ✅ Bug bounty programs with proper scope
- ✅ Penetration testing engagements with written authorization
- ✅ Your own applications and infrastructure
- ✅ CTF competitions and security labs
- ❌ Unauthorized testing on any target
- ❌ Production systems without permission

**Unauthorized access to computer systems is illegal.**

### Responsible Disclosure

When you find vulnerabilities:
1. Report to the organization's security team
2. Follow responsible disclosure timelines
3. Do not publicly disclose until patched
4. Provide clear reproduction steps
5. Suggest remediation where appropriate

## 🛠️ Tool Recommendations

### Essential Tools for Bug Hunting

**Reconnaissance:**
- [subfinder](https://github.com/projectdiscovery/subfinder) - Fast subdomain enumeration
- [amass](https://github.com/OWASP/Amass) - In-depth attack surface mapping
- [httpx](https://github.com/projectdiscovery/httpx) - Fast HTTP probe
- [nuclei](https://github.com/projectdiscovery/nuclei) - Template-based vulnerability scanning

**Web Discovery:**
- [gobuster](https://github.com/OJ/gobuster) - Directory/file brute-forcing
- [ffuf](https://github.com/ffuf/ffuf) - Fast fuzzer
- [feroxbuster](https://github.com/epi052/feroxbuster) - Recursive content discovery
- [katana](https://github.com/projectdiscovery/katana) - Web crawling

**Vulnerability Scanning:**
- [dalfox](https://github.com/hahwul/dalfox) - XSS scanner
- [sqlmap](https://sqlmap.org/) - SQL injection automation
- [XSStrike](https://github.com/s0md3v/XSStrike) - XSS detection

**Port Scanning:**
- [nmap](https://nmap.org/) - Network mapper
- [rustscan](https://github.com/RustScan/RustScan) - Fast port scanner
- [masscan](https://github.com/robertdavidgraham/masscan) - Mass IP scanner

## 🤝 Contributing

Contributions welcome! Add new modules:

1. Create new scanner in `tools/vuln/`
2. Implement `scan()` method returning results dict
3. Add to orchestrator
4. Update documentation

## 📝 Roadmap

- [ ] JWT token analyzer
- [ ] Open redirect finder
- [ ] CRLF injection tester
- [ ] API fuzzing module
- [ ] Webhook/callback integration for blind vulnerabilities
- [ ] Selenium-based DOM XSS detection
- [ ] NoSQL injection tester
- [ ] XXE vulnerability scanner
- [ ] Template injection detector
- [ ] Subdomain takeover checker
- [ ] Screenshot capture integration
- [ ] Slack/Discord notifications
- [ ] PDF report generation
- [ ] Database backend for results

## 📚 Resources

**Learning:**
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Bug Bounty Platforms](https://www.bugcrowd.com/)

**Practice:**
- [HackTheBox](https://www.hackthebox.eu/)
- [PentesterLab](https://pentesterlab.com/)
- [DVWA](http://www.dvwa.co.uk/)
- [WebGoat](https://owasp.org/www-project-webgoat/)

## 📄 License

This project is for educational and authorized security testing purposes only.

## 🙏 Credits

Built with ❤️ for the bug bounty and security community.

Integrates with amazing open-source tools by:
- ProjectDiscovery (nuclei, httpx, subfinder)
- OWASP
- And many other security researchers

## 📧 Contact

For questions, issues, or contributions, please open an issue on GitHub.

---

**Remember: With great power comes great responsibility. Happy (ethical) hacking! 🔒**
