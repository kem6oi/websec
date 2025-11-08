#!/usr/bin/env python3
"""
Race Condition Vulnerability Tester
Tests for race conditions in critical business logic operations
"""

import requests
import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
import threading

class RaceConditionTester:
    """Tester for race condition vulnerabilities"""

    def __init__(self, target_url, output_file=None, threads=20):
        self.target_url = target_url
        self.output_file = output_file
        self.threads = threads
        self.vulnerabilities = []
        self.lock = threading.Lock()

    def scan(self):
        """Run race condition tests"""
        print(f"[*] Starting race condition testing on {self.target_url}")
        print(f"[*] Using {self.threads} concurrent threads")

        # Test coupon/discount reuse
        self._test_coupon_reuse()

        # Test duplicate request handling
        self._test_duplicate_requests()

        # Test concurrent balance operations
        self._test_concurrent_operations()

        # Test concurrent checkout
        self._test_concurrent_checkout()

        # Test limit bypass
        self._test_limit_bypass()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_coupon_reuse(self):
        """Test for coupon/discount code reuse via race condition"""
        print("[*] Testing coupon reuse race condition...")

        coupon_endpoints = [
            '/api/coupon/apply',
            '/api/discount/apply',
            '/apply-coupon',
            '/checkout/coupon',
            '/cart/discount',
        ]

        for endpoint in coupon_endpoints:
            test_url = urljoin(urlparse(self.target_url).scheme + "://" + urlparse(self.target_url).netloc, endpoint)

            # Test data
            test_data = {
                'coupon_code': 'TEST50',
                'discount_code': 'SAVE20',
                'promo_code': 'PROMO',
                'code': 'DISCOUNT'
            }

            results = self._send_concurrent_requests(test_url, test_data, method='POST')

            if results:
                # Check if multiple succeeded
                success_count = sum(1 for r in results if r.get('status_code') == 200 or 'success' in r.get('text', '').lower())

                if success_count > 1:
                    vuln = {
                        'type': 'Race Condition - Coupon Reuse',
                        'severity': 'critical',
                        'url': test_url,
                        'evidence': f'{success_count} out of {len(results)} concurrent requests succeeded',
                        'description': 'Coupon can be applied multiple times via race condition',
                        'cwe': 'CWE-362',
                        'impact': 'Unlimited discount abuse, financial loss',
                        'remediation': 'Implement atomic operations with database locks'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] CRITICAL: Coupon reuse race condition at {endpoint}")
                    return

    def _test_duplicate_requests(self):
        """Test for duplicate request handling (double spend)"""
        print("[*] Testing duplicate request race condition...")

        payment_endpoints = [
            '/api/payment/process',
            '/checkout/complete',
            '/order/create',
            '/transaction/submit',
            '/purchase',
        ]

        for endpoint in payment_endpoints:
            test_url = urljoin(urlparse(self.target_url).scheme + "://" + urlparse(self.target_url).netloc, endpoint)

            # Test data for payment/purchase
            test_data = {
                'amount': '100',
                'item_id': '12345',
                'quantity': '1',
                'payment_method': 'credit_card'
            }

            results = self._send_concurrent_requests(test_url, test_data, method='POST')

            if results:
                # Check if multiple payments processed
                success_count = sum(1 for r in results if r.get('status_code') in [200, 201] or 'success' in r.get('text', '').lower())

                if success_count > 1:
                    vuln = {
                        'type': 'Race Condition - Duplicate Payment Processing',
                        'severity': 'critical',
                        'url': test_url,
                        'evidence': f'{success_count} duplicate payments processed',
                        'description': 'Payment endpoint vulnerable to race condition',
                        'cwe': 'CWE-362',
                        'impact': 'Double spend attack, duplicate charges',
                        'remediation': 'Use idempotency keys and transaction locking'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] CRITICAL: Duplicate payment race condition")
                    return

    def _test_concurrent_operations(self):
        """Test concurrent balance/credit operations"""
        print("[*] Testing concurrent balance operations...")

        balance_endpoints = [
            '/api/balance/withdraw',
            '/api/credits/use',
            '/api/wallet/transfer',
            '/api/account/debit',
        ]

        for endpoint in balance_endpoints:
            test_url = urljoin(urlparse(self.target_url).scheme + "://" + urlparse(self.target_url).netloc, endpoint)

            # Test withdrawing same balance multiple times
            test_data = {
                'amount': '10',
                'credits': '10',
                'value': '10'
            }

            results = self._send_concurrent_requests(test_url, test_data, method='POST', count=10)

            if results:
                success_count = sum(1 for r in results if r.get('status_code') in [200, 201])

                # If more than 1 concurrent withdrawal succeeded
                if success_count > 1:
                    vuln = {
                        'type': 'Race Condition - Concurrent Balance Operations',
                        'severity': 'critical',
                        'url': test_url,
                        'evidence': f'{success_count} concurrent operations succeeded',
                        'description': 'Balance operations not properly synchronized',
                        'cwe': 'CWE-362',
                        'impact': 'Withdraw more than available balance, credit abuse',
                        'remediation': 'Use database row locking (SELECT FOR UPDATE)'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] CRITICAL: Concurrent balance operation race condition")
                    return

    def _test_concurrent_checkout(self):
        """Test concurrent checkout for limited items"""
        print("[*] Testing concurrent checkout race condition...")

        checkout_endpoints = [
            '/api/checkout',
            '/cart/purchase',
            '/order/submit',
        ]

        for endpoint in checkout_endpoints:
            test_url = urljoin(urlparse(self.target_url).scheme + "://" + urlparse(self.target_url).netloc, endpoint)

            # Try to checkout same limited item multiple times
            test_data = {
                'item_id': '99999',  # Potentially limited item
                'quantity': '1',
                'product_id': '99999'
            }

            results = self._send_concurrent_requests(test_url, test_data, method='POST', count=15)

            if results:
                success_count = sum(1 for r in results if r.get('status_code') in [200, 201, 302])

                # If many succeeded, might bypass stock limits
                if success_count > 5:
                    vuln = {
                        'type': 'Race Condition - Stock Limit Bypass',
                        'severity': 'high',
                        'url': test_url,
                        'evidence': f'{success_count} concurrent checkouts succeeded',
                        'description': 'Inventory limits can be bypassed via race condition',
                        'cwe': 'CWE-362',
                        'impact': 'Purchase more items than available, inventory issues',
                        'remediation': 'Implement pessimistic locking on inventory'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Stock limit bypass via race condition")
                    return

    def _test_limit_bypass(self):
        """Test rate limit bypass via race condition"""
        print("[*] Testing rate limit bypass...")

        # Endpoints that might have rate limits
        limited_endpoints = [
            '/api/send-sms',
            '/api/send-email',
            '/api/verify-code',
            '/api/forgot-password',
            '/api/resend-code',
        ]

        for endpoint in limited_endpoints:
            test_url = urljoin(urlparse(self.target_url).scheme + "://" + urlparse(self.target_url).netloc, endpoint)

            test_data = {
                'email': 'test@example.com',
                'phone': '+1234567890',
                'username': 'testuser'
            }

            # Send many concurrent requests
            results = self._send_concurrent_requests(test_url, test_data, method='POST', count=20)

            if results:
                success_count = sum(1 for r in results if r.get('status_code') in [200, 201])
                rate_limited = sum(1 for r in results if r.get('status_code') == 429)

                # If most succeeded despite rate limiting
                if success_count > 10 and rate_limited < 5:
                    vuln = {
                        'type': 'Race Condition - Rate Limit Bypass',
                        'severity': 'medium',
                        'url': test_url,
                        'evidence': f'{success_count} requests succeeded, only {rate_limited} rate limited',
                        'description': 'Rate limits can be bypassed via concurrent requests',
                        'cwe': 'CWE-362',
                        'impact': 'SMS/email flooding, resource exhaustion',
                        'remediation': 'Implement atomic rate limiting with Redis/memcached'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] Rate limit bypass via race condition")
                    return

    def _send_concurrent_requests(self, url, data, method='GET', count=None):
        """Send concurrent requests to test for race conditions"""
        if count is None:
            count = self.threads

        results = []
        session = requests.Session()

        def make_request():
            try:
                if method.upper() == 'POST':
                    response = session.post(url, json=data, timeout=10)
                else:
                    response = session.get(url, params=data, timeout=10)

                return {
                    'status_code': response.status_code,
                    'text': response.text[:500],  # First 500 chars
                    'headers': dict(response.headers)
                }
            except Exception as e:
                return {'error': str(e)}

        # Use ThreadPoolExecutor for truly concurrent requests
        with ThreadPoolExecutor(max_workers=count) as executor:
            futures = [executor.submit(make_request) for _ in range(count)]

            for future in as_completed(futures):
                try:
                    result = future.result()
                    with self.lock:
                        results.append(result)
                except Exception as e:
                    pass

        return results

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
        print("Usage: python3 race_condition_tester.py <url> [threads] [output_file]")
        print("\nExample:")
        print("  python3 race_condition_tester.py https://example.com")
        print("  python3 race_condition_tester.py https://example.com 30 results.json")
        print("\nTests for:")
        print("  - Coupon/discount code reuse")
        print("  - Duplicate payment processing")
        print("  - Concurrent balance operations")
        print("  - Stock limit bypass")
        print("  - Rate limit bypass")
        sys.exit(1)

    target = sys.argv[1]
    threads = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    output = sys.argv[3] if len(sys.argv) > 3 else None

    tester = RaceConditionTester(target, output, threads)
    results = tester.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
