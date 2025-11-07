#!/usr/bin/env python3
"""
Report Generator
Generates HTML and PDF reports from scan results
"""

import json
from pathlib import Path
from datetime import datetime
import os

class ReportGenerator:
    """Generate professional security reports"""

    def __init__(self, results_dir):
        self.results_dir = Path(results_dir)

    def generate_html_report(self, output_file='report.html'):
        """Generate HTML report from all results"""
        vulnerabilities = self._collect_vulnerabilities()
        recon_data = self._collect_recon_data()

        html = self._build_html(vulnerabilities, recon_data)

        output_path = self.results_dir / output_file
        with open(output_path, 'w') as f:
            f.write(html)

        print(f"[+] HTML report generated: {output_path}")
        return output_path

    def _collect_vulnerabilities(self):
        """Collect all vulnerability findings"""
        vulns = []

        # Check for vulnerability scan results
        vuln_files = [
            'xss_results.json',
            'sqli_results.json',
            'ssrf_results.json',
            'cors_results.json',
            'nuclei.txt'
        ]

        for filename in vuln_files:
            filepath = self.results_dir / filename
            if filepath.exists():
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                        if 'vulnerabilities' in data:
                            vulns.extend(data['vulnerabilities'])
                except:
                    pass

        return vulns

    def _collect_recon_data(self):
        """Collect reconnaissance data"""
        data = {
            'subdomains': [],
            'urls': [],
            'ports': []
        }

        # Collect subdomains
        subdomain_dir = self.results_dir / 'subdomains'
        if subdomain_dir.exists():
            all_subdomains = subdomain_dir / 'all_subdomains.txt'
            if all_subdomains.exists():
                with open(all_subdomains, 'r') as f:
                    data['subdomains'] = [line.strip() for line in f if line.strip()]

        # Collect URLs
        httpx_file = self.results_dir / 'probes' / 'httpx.txt'
        if httpx_file.exists():
            with open(httpx_file, 'r') as f:
                data['urls'] = [line.strip() for line in f if line.strip()]

        return data

    def _build_html(self, vulnerabilities, recon_data):
        """Build HTML report"""
        # Count severity
        severity_counts = {
            'critical': sum(1 for v in vulnerabilities if v.get('severity') == 'critical'),
            'high': sum(1 for v in vulnerabilities if v.get('severity') == 'high'),
            'medium': sum(1 for v in vulnerabilities if v.get('severity') == 'medium'),
            'low': sum(1 for v in vulnerabilities if v.get('severity') == 'low')
        }

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f4f4f4;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .meta {{
            opacity: 0.9;
            font-size: 1.1em;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .card h2 {{
            margin-bottom: 15px;
            color: #667eea;
        }}
        .severity-box {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            font-weight: bold;
        }}
        .critical {{ background: #ff4444; color: white; }}
        .high {{ background: #ff8800; color: white; }}
        .medium {{ background: #ffbb33; color: white; }}
        .low {{ background: #00C851; color: white; }}
        .vulnerability {{
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 10px;
            border-left: 5px solid #667eea;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .vuln-title {{
            font-size: 1.3em;
            font-weight: bold;
        }}
        .badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
        }}
        .detail-row {{
            margin: 10px 0;
            padding: 10px;
            background: #f9f9f9;
            border-radius: 5px;
        }}
        .label {{
            font-weight: bold;
            color: #667eea;
        }}
        code {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 2px 8px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        .recon-section {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .recon-list {{
            max-height: 300px;
            overflow-y: auto;
            background: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
        }}
        .recon-item {{
            padding: 5px;
            border-bottom: 1px solid #ddd;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Security Assessment Report</h1>
            <div class="meta">
                Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
                Target: {self.results_dir.name}
            </div>
        </header>

        <div class="summary">
            <div class="card">
                <h2>Executive Summary</h2>
                <div class="severity-box critical">
                    <span>Critical</span>
                    <span>{severity_counts['critical']}</span>
                </div>
                <div class="severity-box high">
                    <span>High</span>
                    <span>{severity_counts['high']}</span>
                </div>
                <div class="severity-box medium">
                    <span>Medium</span>
                    <span>{severity_counts['medium']}</span>
                </div>
                <div class="severity-box low">
                    <span>Low</span>
                    <span>{severity_counts['low']}</span>
                </div>
            </div>

            <div class="card">
                <h2>Reconnaissance Summary</h2>
                <p><strong>Subdomains Found:</strong> {len(recon_data['subdomains'])}</p>
                <p><strong>Live URLs:</strong> {len(recon_data['urls'])}</p>
                <p><strong>Total Vulnerabilities:</strong> {len(vulnerabilities)}</p>
            </div>
        </div>

        <div class="card">
            <h2>Vulnerabilities Detected</h2>
            {''.join(self._render_vulnerability(v) for v in vulnerabilities) if vulnerabilities else '<p>No vulnerabilities detected.</p>'}
        </div>

        <div class="recon-section">
            <h2>Discovered Assets</h2>
            {self._render_recon_data(recon_data)}
        </div>
    </div>
</body>
</html>
"""
        return html

    def _render_vulnerability(self, vuln):
        """Render a single vulnerability"""
        severity = vuln.get('severity', 'low')
        vuln_type = vuln.get('type', 'Unknown')
        url = vuln.get('url', 'N/A')
        param = vuln.get('parameter', 'N/A')
        payload = vuln.get('payload', 'N/A')
        evidence = vuln.get('evidence', 'N/A')

        return f"""
        <div class="vulnerability">
            <div class="vuln-header">
                <div class="vuln-title">{vuln_type}</div>
                <span class="badge {severity}">{severity.upper()}</span>
            </div>
            <div class="detail-row">
                <span class="label">URL:</span> <code>{url}</code>
            </div>
            <div class="detail-row">
                <span class="label">Parameter:</span> <code>{param}</code>
            </div>
            <div class="detail-row">
                <span class="label">Payload:</span> <code>{payload}</code>
            </div>
            <div class="detail-row">
                <span class="label">Evidence:</span> {evidence}
            </div>
        </div>
        """

    def _render_recon_data(self, data):
        """Render reconnaissance data"""
        html = ""

        if data['subdomains']:
            html += f"""
            <h3>Subdomains ({len(data['subdomains'])})</h3>
            <div class="recon-list">
                {''.join(f'<div class="recon-item">{s}</div>' for s in data['subdomains'][:100])}
                {f'<div class="recon-item"><em>... and {len(data["subdomains"]) - 100} more</em></div>' if len(data['subdomains']) > 100 else ''}
            </div>
            """

        if data['urls']:
            html += f"""
            <h3>Live URLs ({len(data['urls'])})</h3>
            <div class="recon-list">
                {''.join(f'<div class="recon-item">{u}</div>' for u in data['urls'][:100])}
                {f'<div class="recon-item"><em>... and {len(data["urls"]) - 100} more</em></div>' if len(data['urls']) > 100 else ''}
            </div>
            """

        return html if html else "<p>No reconnaissance data available.</p>"


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 report_generator.py <results_directory>")
        sys.exit(1)

    generator = ReportGenerator(sys.argv[1])
    generator.generate_html_report()
