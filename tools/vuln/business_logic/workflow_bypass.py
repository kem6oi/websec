#!/usr/bin/env python3
"""
Workflow Bypass Vulnerability Tester
Tests for workflow and state transition bypasses in multi-step processes
"""

import requests
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin

class WorkflowBypassTester:
    """Tester for workflow bypass vulnerabilities"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def scan(self):
        """Run workflow bypass tests"""
        print(f"[*] Starting workflow bypass testing on {self.target_url}")

        # Test payment step bypass
        self._test_payment_bypass()

        # Test multi-step manipulation
        self._test_multi_step_bypass()

        # Test state transition abuse
        self._test_state_transition()

        # Test direct access to final step
        self._test_direct_final_step()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_payment_bypass(self):
        """Test payment step bypass"""
        print("[*] Testing payment step bypass...")

        # Common checkout/order confirmation endpoints
        final_steps = [
            '/checkout/confirm',
            '/order/complete',
            '/checkout/success',
            '/order/confirmation',
            '/payment/success',
            '/checkout/thankyou',
            '/order/success',
        ]

        base_url = urlparse(self.target_url).scheme + "://" + urlparse(self.target_url).netloc

        for endpoint in final_steps:
            test_url = urljoin(base_url, endpoint)

            try:
                # Try to access final step directly without payment
                response = self.session.get(test_url, timeout=10, allow_redirects=False)

                if response.status_code == 200:
                    # Check if it shows success/confirmation
                    success_indicators = [
                        'order confirmed',
                        'thank you',
                        'order number',
                        'confirmation',
                        'order placed',
                        'purchase successful'
                    ]

                    if any(indicator in response.text.lower() for indicator in success_indicators):
                        vuln = {
                            'type': 'Workflow Bypass - Payment Step Skip',
                            'severity': 'critical',
                            'url': test_url,
                            'evidence': 'Accessed order confirmation without payment',
                            'description': 'Can access checkout success page without completing payment',
                            'cwe': 'CWE-840',
                            'impact': 'Complete orders without payment',
                            'remediation': 'Verify payment completion server-side before showing confirmation'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: Payment bypass at {endpoint}")
                        return

            except:
                pass

    def _test_multi_step_bypass(self):
        """Test multi-step process bypass"""
        print("[*] Testing multi-step workflow bypass...")

        # Try to jump to later steps
        workflow_steps = [
            ('/checkout/step1', '/checkout/step3'),
            ('/registration/step1', '/registration/step4'),
            ('/wizard/step1', '/wizard/complete'),
            ('/onboarding/step1', '/onboarding/finish'),
        ]

        base_url = urlparse(self.target_url).scheme + "://" + urlparse(self.target_url).netloc

        for first_step, final_step in workflow_steps:
            try:
                # Start the workflow
                step1_url = urljoin(base_url, first_step)
                self.session.get(step1_url, timeout=10)

                # Try to jump to final step
                final_url = urljoin(base_url, final_step)
                response = self.session.get(final_url, timeout=10, allow_redirects=False)

                if response.status_code == 200:
                    # Check if we successfully skipped steps
                    if 'complete' in response.text.lower() or 'success' in response.text.lower():
                        vuln = {
                            'type': 'Workflow Bypass - Step Skipping',
                            'severity': 'high',
                            'url': final_url,
                            'evidence': f'Jumped from {first_step} to {final_step}',
                            'description': 'Multi-step workflow allows skipping intermediate steps',
                            'cwe': 'CWE-840',
                            'impact': 'Bypass validation in skipped steps',
                            'remediation': 'Enforce sequential step completion server-side'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Workflow step bypass: {first_step} -> {final_step}")
                        return

            except:
                pass

    def _test_state_transition(self):
        """Test invalid state transitions"""
        print("[*] Testing state transition abuse...")

        # Common state transition endpoints
        state_endpoints = [
            '/api/order/status',
            '/api/payment/status',
            '/api/shipment/status',
            '/order/update-status',
        ]

        base_url = urlparse(self.target_url).scheme + "://" + urlparse(self.target_url).netloc

        # Invalid state transitions to test
        invalid_transitions = [
            {'status': 'delivered'},  # Skip to delivered
            {'state': 'completed'},
            {'order_status': 'shipped'},
            {'payment_status': 'paid'},
            {'status': 'refunded'},
        ]

        for endpoint in state_endpoints:
            test_url = urljoin(base_url, endpoint)

            for transition in invalid_transitions:
                try:
                    # Try to force state transition
                    response = self.session.post(test_url, json=transition, timeout=10)

                    if response.status_code in [200, 201]:
                        # Check if state change was accepted
                        if any(indicator in response.text.lower() for indicator in ['updated', 'success', 'changed']):
                            vuln = {
                                'type': 'Workflow Bypass - Invalid State Transition',
                                'severity': 'critical',
                                'url': test_url,
                                'payload': transition,
                                'evidence': 'Direct state manipulation accepted',
                                'description': 'Can force invalid state transitions',
                                'cwe': 'CWE-840',
                                'impact': 'Mark orders as delivered without shipping, bypass refund policies',
                                'remediation': 'Implement state machine with valid transition validation'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] CRITICAL: State transition abuse")
                            return

                except:
                    pass

    def _test_direct_final_step(self):
        """Test direct access to protected final steps"""
        print("[*] Testing direct access to final steps...")

        base_url = urlparse(self.target_url).scheme + "://" + urlparse(self.target_url).netloc

        # Final step endpoints that should require previous steps
        protected_endpoints = [
            '/api/checkout/finalize',
            '/api/order/submit',
            '/registration/complete',
            '/wizard/finish',
            '/setup/finalize',
            '/checkout/place-order',
        ]

        for endpoint in protected_endpoints:
            test_url = urljoin(base_url, endpoint)

            # Test with minimal data
            test_payloads = [
                {},  # Empty
                {'confirm': True},
                {'complete': True},
                {'finalize': True},
            ]

            for payload in test_payloads:
                try:
                    response = self.session.post(test_url, json=payload, timeout=10)

                    if response.status_code in [200, 201, 302]:
                        success_indicators = ['success', 'created', 'completed', 'confirmed']

                        if any(indicator in response.text.lower() for indicator in success_indicators):
                            vuln = {
                                'type': 'Workflow Bypass - Direct Final Step Access',
                                'severity': 'high',
                                'url': test_url,
                                'payload': payload,
                                'evidence': 'Final step accessible without prerequisites',
                                'description': 'Can directly access final workflow step',
                                'cwe': 'CWE-840',
                                'impact': 'Bypass all validation and prerequisites',
                                'remediation': 'Validate workflow completion before final step'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] Direct final step access at {endpoint}")
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
        print("Usage: python3 workflow_bypass.py <url> [output_file]")
        print("\nExample:")
        print("  python3 workflow_bypass.py https://example.com")
        print("\nTests for:")
        print("  - Payment step bypass")
        print("  - Multi-step workflow skipping")
        print("  - Invalid state transitions")
        print("  - Direct final step access")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    tester = WorkflowBypassTester(target, output)
    results = tester.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
