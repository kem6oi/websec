#!/usr/bin/env python3
"""
Advanced GraphQL Security Scanner
Tests for GraphQL-specific vulnerabilities including batching abuse, depth limits,
introspection, and query complexity attacks
"""

import requests
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin

class AdvancedGraphQLScanner:
    """Advanced GraphQL vulnerability scanner"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Content-Type': 'application/json'
        })

    def scan(self):
        """Run advanced GraphQL tests"""
        print(f"[*] Starting advanced GraphQL testing on {self.target_url}")

        # Test introspection
        self._test_introspection()

        # Test batching abuse
        self._test_batching_abuse()

        # Test depth limits
        self._test_depth_limits()

        # Test alias abuse
        self._test_alias_abuse()

        # Test field suggestions
        self._test_field_suggestions()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities
        }

    def _test_introspection(self):
        """Test if GraphQL introspection is enabled"""
        print("[*] Testing GraphQL introspection...")

        introspection_query = {
            "query": """
                query IntrospectionQuery {
                    __schema {
                        queryType { name }
                        mutationType { name }
                        types {
                            name
                            kind
                            fields {
                                name
                                type {
                                    name
                                    kind
                                }
                            }
                        }
                    }
                }
            """
        }

        try:
            response = self.session.post(self.target_url, json=introspection_query, timeout=15)

            if response.status_code == 200:
                try:
                    data = response.json()

                    if 'data' in data and '__schema' in data['data']:
                        schema = data['data']['__schema']
                        types = schema.get('types', [])

                        vuln = {
                            'type': 'GraphQL Introspection Enabled',
                            'severity': 'medium',
                            'url': self.target_url,
                            'evidence': f'Full schema extracted: {len(types)} types found',
                            'description': 'GraphQL introspection is enabled in production',
                            'cwe': 'CWE-200',
                            'impact': 'Complete API schema disclosure, easier to find vulnerabilities',
                            'remediation': 'Disable introspection in production environments'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Introspection enabled - {len(types)} types discovered")
                        return
                except:
                    pass

        except:
            pass

    def _test_batching_abuse(self):
        """Test GraphQL batching for DoS"""
        print("[*] Testing GraphQL batching abuse...")

        # Create a batch of queries
        batch_sizes = [10, 50, 100]

        for batch_size in batch_sizes:
            # Simple query repeated many times
            batched_queries = []
            for i in range(batch_size):
                batched_queries.append({
                    "query": """
                        query {
                            __typename
                        }
                    """
                })

            try:
                import time
                start_time = time.time()
                response = self.session.post(self.target_url, json=batched_queries, timeout=30)
                elapsed = time.time() - start_time

                if response.status_code == 200:
                    try:
                        data = response.json()

                        # If batching is allowed
                        if isinstance(data, list) and len(data) > 1:
                            vuln = {
                                'type': 'GraphQL Batching Abuse',
                                'severity': 'high',
                                'url': self.target_url,
                                'evidence': f'Batch of {batch_size} queries processed in {elapsed:.2f}s',
                                'description': 'GraphQL allows unlimited query batching',
                                'cwe': 'CWE-770',
                                'impact': 'DoS via resource exhaustion, amplification attacks',
                                'remediation': 'Limit batch size to prevent abuse'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] Batching abuse possible - {batch_size} queries accepted")
                            return
                    except:
                        pass

            except:
                pass

    def _test_depth_limits(self):
        """Test query depth limits"""
        print("[*] Testing GraphQL depth limits...")

        # Create deeply nested query
        depths = [10, 20, 50]

        for depth in depths:
            # Build nested query
            query = "query {"
            for i in range(depth):
                query += f" level{i} {{"
            query += " __typename "
            for i in range(depth):
                query += "}"
            query += "}"

            graphql_query = {"query": query}

            try:
                response = self.session.post(self.target_url, json=graphql_query, timeout=15)

                if response.status_code == 200:
                    try:
                        data = response.json()

                        # If deep query succeeded
                        if 'data' in data and not data.get('errors'):
                            vuln = {
                                'type': 'GraphQL Depth Limit Bypass',
                                'severity': 'medium',
                                'url': self.target_url,
                                'evidence': f'Query with depth {depth} processed successfully',
                                'description': 'No depth limits on GraphQL queries',
                                'cwe': 'CWE-770',
                                'impact': 'DoS via deeply nested queries',
                                'remediation': 'Implement query depth limits'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] No depth limits - depth {depth} accepted")
                            return
                    except:
                        pass

            except:
                pass

    def _test_alias_abuse(self):
        """Test query complexity via aliases"""
        print("[*] Testing GraphQL alias abuse...")

        # Create query with many aliases
        alias_counts = [10, 50, 100]

        for alias_count in alias_counts:
            # Build query with many aliases
            aliases = []
            for i in range(alias_count):
                aliases.append(f"alias{i}: __typename")

            query = f"query {{ {' '.join(aliases)} }}"
            graphql_query = {"query": query}

            try:
                import time
                start_time = time.time()
                response = self.session.post(self.target_url, json=graphql_query, timeout=30)
                elapsed = time.time() - start_time

                if response.status_code == 200:
                    try:
                        data = response.json()

                        # If query with many aliases succeeded
                        if 'data' in data and len(data['data']) >= alias_count * 0.8:
                            vuln = {
                                'type': 'GraphQL Alias Abuse',
                                'severity': 'high',
                                'url': self.target_url,
                                'evidence': f'{alias_count} aliases processed in {elapsed:.2f}s',
                                'description': 'No limits on query aliases (complexity)',
                                'cwe': 'CWE-770',
                                'impact': 'DoS via query complexity amplification',
                                'remediation': 'Implement query complexity limits'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] Alias abuse possible - {alias_count} aliases accepted")
                            return
                    except:
                        pass

            except:
                pass

    def _test_field_suggestions(self):
        """Test field suggestions for information disclosure"""
        print("[*] Testing field suggestions...")

        # Query with typo to get suggestions
        suggestion_query = {
            "query": "query { userzzz { id } }"
        }

        try:
            response = self.session.post(self.target_url, json=suggestion_query, timeout=10)

            if response.status_code == 200:
                try:
                    data = response.json()

                    if 'errors' in data:
                        for error in data['errors']:
                            message = error.get('message', '')

                            # Check for field suggestions
                            if 'did you mean' in message.lower() or 'suggestions' in message.lower():
                                vuln = {
                                    'type': 'GraphQL Field Suggestions',
                                    'severity': 'low',
                                    'url': self.target_url,
                                    'evidence': f'Suggestions in error: {message}',
                                    'description': 'GraphQL provides field suggestions in errors',
                                    'cwe': 'CWE-200',
                                    'impact': 'Information disclosure, schema discovery',
                                    'remediation': 'Disable detailed error messages in production'
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"[!] Field suggestions enabled")
                                return
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
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high'),
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'medium'),
                'low': sum(1 for v in self.vulnerabilities if v['severity'] == 'low')
            }
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 graphql_advanced.py <graphql_url> [output_file]")
        print("\nExample:")
        print("  python3 graphql_advanced.py https://api.example.com/graphql")
        print("\nTests for:")
        print("  - Introspection enabled (schema extraction)")
        print("  - Batching abuse (DoS)")
        print("  - Query depth limits")
        print("  - Alias abuse (query complexity)")
        print("  - Field suggestions (info disclosure)")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    scanner = AdvancedGraphQLScanner(target, output)
    results = scanner.scan()

    print(f"\n[+] Scan complete!")
    print(f"    Total vulnerabilities: {len(results['vulnerabilities'])}")
    if len(results['vulnerabilities']) > 0:
        print(f"    High: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'high')}")
        print(f"    Medium: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'medium')}")
        print(f"    Low: {sum(1 for v in results['vulnerabilities'] if v['severity'] == 'low')}")
