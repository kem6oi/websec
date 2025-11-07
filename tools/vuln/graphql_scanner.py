#!/usr/bin/env python3
"""
GraphQL Vulnerability Scanner
Tests for GraphQL-specific security issues
"""

import requests
import json
from datetime import datetime
import re

class GraphQLScanner:
    """GraphQL vulnerability scanner"""

    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Content-Type': 'application/json'
        })
        self.schema = None

    def scan(self):
        """Run GraphQL security scan"""
        print(f"[*] Starting GraphQL scan on {self.target_url}")

        # Detect GraphQL endpoint
        if not self._detect_graphql():
            print("[!] Target doesn't appear to be a GraphQL endpoint")
            return None

        print("[+] GraphQL endpoint confirmed")

        # Run tests
        self._test_introspection()
        self._test_query_depth()
        self._test_field_suggestions()
        self._test_batch_queries()
        self._test_query_cost()
        self._test_authorization()
        self._test_injection()

        # Save results
        if self.output_file:
            self._save_results()

        return {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities,
            'schema': self.schema
        }

    def _detect_graphql(self):
        """Detect if endpoint is GraphQL"""
        # Try GraphQL query
        query = {'query': '{__typename}'}

        try:
            response = self.session.post(self.target_url, json=query, timeout=10)

            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'data' in data or 'errors' in data:
                        return True
                except:
                    pass

            # Try GET request
            response = self.session.get(self.target_url, timeout=10)
            if 'graphql' in response.text.lower():
                return True

        except Exception as e:
            pass

        return False

    def _test_introspection(self):
        """Test for introspection query vulnerability"""
        print("[*] Testing introspection queries...")

        introspection_query = {
            'query': '''
            {
                __schema {
                    types {
                        name
                        fields {
                            name
                            type {
                                name
                            }
                        }
                    }
                    queryType {
                        name
                    }
                    mutationType {
                        name
                    }
                }
            }
            '''
        }

        try:
            response = self.session.post(
                self.target_url,
                json=introspection_query,
                timeout=10
            )

            if response.status_code == 200:
                try:
                    data = response.json()

                    if 'data' in data and '__schema' in data['data']:
                        self.schema = data['data']['__schema']

                        vuln = {
                            'type': 'GraphQL Introspection Enabled',
                            'severity': 'medium',
                            'url': self.target_url,
                            'evidence': 'Schema introspection is enabled',
                            'impact': 'Attackers can discover entire API schema',
                            'cwe': 'CWE-200',
                            'types_found': len(self.schema.get('types', []))
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] Introspection enabled! Found {vuln['types_found']} types")

                        # Look for sensitive type names
                        self._analyze_schema()

                except json.JSONDecodeError:
                    pass

        except Exception as e:
            pass

    def _analyze_schema(self):
        """Analyze schema for sensitive information"""
        if not self.schema:
            return

        sensitive_keywords = [
            'password', 'secret', 'token', 'key', 'admin',
            'private', 'internal', 'credential', 'apikey'
        ]

        sensitive_types = []
        sensitive_fields = []

        for type_def in self.schema.get('types', []):
            type_name = type_def.get('name', '')

            # Check type name
            if any(keyword in type_name.lower() for keyword in sensitive_keywords):
                sensitive_types.append(type_name)

            # Check field names
            for field in type_def.get('fields', []) or []:
                field_name = field.get('name', '')
                if any(keyword in field_name.lower() for keyword in sensitive_keywords):
                    sensitive_fields.append(f"{type_name}.{field_name}")

        if sensitive_types or sensitive_fields:
            vuln = {
                'type': 'GraphQL Sensitive Schema Exposure',
                'severity': 'high',
                'url': self.target_url,
                'evidence': 'Schema contains sensitive types/fields',
                'sensitive_types': sensitive_types,
                'sensitive_fields': sensitive_fields[:10],  # Limit output
                'cwe': 'CWE-200'
            }
            self.vulnerabilities.append(vuln)
            print(f"[!] Sensitive schema elements found!")

    def _test_query_depth(self):
        """Test for excessive query depth (nested queries)"""
        print("[*] Testing query depth limits...")

        # Create deeply nested query
        nested_query = "query { "
        for i in range(50):
            nested_query += f"field{i} {{ "

        nested_query += "__typename "

        for i in range(50):
            nested_query += "} "

        nested_query += "}"

        payload = {'query': nested_query}

        try:
            response = self.session.post(self.target_url, json=payload, timeout=15)

            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'errors' not in data:
                        vuln = {
                            'type': 'GraphQL No Query Depth Limit',
                            'severity': 'high',
                            'url': self.target_url,
                            'evidence': 'Server accepts deeply nested queries (50+ levels)',
                            'impact': 'Potential DoS via resource exhaustion',
                            'cwe': 'CWE-400'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"[!] No query depth limit!")

                except json.JSONDecodeError:
                    pass

        except requests.exceptions.Timeout:
            vuln = {
                'type': 'GraphQL Query DoS',
                'severity': 'critical',
                'url': self.target_url,
                'evidence': 'Deeply nested query caused timeout',
                'impact': 'DoS vulnerability confirmed',
                'cwe': 'CWE-400'
            }
            self.vulnerabilities.append(vuln)
            print(f"[!] CRITICAL: Query caused DoS!")

        except Exception as e:
            pass

    def _test_field_suggestions(self):
        """Test for field suggestion information disclosure"""
        print("[*] Testing field suggestions...")

        # Query with typo
        query = {'query': '{ userz { id } }'}  # Intentional typo

        try:
            response = self.session.post(self.target_url, json=query, timeout=10)

            if response.status_code == 200:
                try:
                    data = response.json()

                    if 'errors' in data:
                        error_msg = str(data['errors'])

                        # Check if suggestions are provided
                        if 'did you mean' in error_msg.lower() or 'suggestion' in error_msg.lower():
                            vuln = {
                                'type': 'GraphQL Field Suggestions',
                                'severity': 'low',
                                'url': self.target_url,
                                'evidence': 'Field suggestions leak schema information',
                                'error_message': error_msg[:200],
                                'cwe': 'CWE-200'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] Field suggestions enabled")

                except json.JSONDecodeError:
                    pass

        except Exception as e:
            pass

    def _test_batch_queries(self):
        """Test for batch query limits"""
        print("[*] Testing batch query limits...")

        # Create batch of queries
        batch_queries = []
        for i in range(100):
            batch_queries.append({
                'query': f'query Q{i} {{ __typename }}'
            })

        try:
            response = self.session.post(self.target_url, json=batch_queries, timeout=15)

            if response.status_code == 200:
                vuln = {
                    'type': 'GraphQL No Batch Query Limit',
                    'severity': 'medium',
                    'url': self.target_url,
                    'evidence': 'Server accepts large batch queries (100+)',
                    'impact': 'Potential DoS via resource exhaustion',
                    'cwe': 'CWE-770'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] No batch query limit!")

        except Exception as e:
            pass

    def _test_query_cost(self):
        """Test for query cost analysis"""
        print("[*] Testing query cost limits...")

        # Create expensive query with aliases
        expensive_query = "query { "
        for i in range(50):
            expensive_query += f"alias{i}: __typename "
        expensive_query += "}"

        payload = {'query': expensive_query}

        try:
            response = self.session.post(self.target_url, json=payload, timeout=15)

            if response.status_code == 200:
                vuln = {
                    'type': 'GraphQL No Query Cost Limit',
                    'severity': 'medium',
                    'url': self.target_url,
                    'evidence': 'Server accepts queries with many aliases',
                    'impact': 'Potential resource exhaustion',
                    'cwe': 'CWE-770'
                }
                self.vulnerabilities.append(vuln)
                print(f"[!] No query cost limit!")

        except Exception as e:
            pass

    def _test_authorization(self):
        """Test for missing authorization"""
        print("[*] Testing authorization...")

        # Common GraphQL queries
        test_queries = [
            '{ users { id email } }',
            '{ user(id: 1) { id email password } }',
            '{ admin { id username } }',
            '{ listUsers { id email } }'
        ]

        for query_str in test_queries:
            query = {'query': query_str}

            try:
                response = self.session.post(self.target_url, json=query, timeout=10)

                if response.status_code == 200:
                    try:
                        data = response.json()

                        if 'data' in data and data['data']:
                            vuln = {
                                'type': 'GraphQL Missing Authorization',
                                'severity': 'critical',
                                'url': self.target_url,
                                'evidence': f'Query executed without authorization: {query_str}',
                                'query': query_str,
                                'cwe': 'CWE-862'
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"[!] CRITICAL: Missing authorization!")
                            return

                    except json.JSONDecodeError:
                        pass

            except Exception as e:
                pass

    def _test_injection(self):
        """Test for injection vulnerabilities"""
        print("[*] Testing for injection vulnerabilities...")

        injection_payloads = [
            "1' OR '1'='1",
            "1; DROP TABLE users--",
            "../../../etc/passwd",
            "${7*7}",
            "{{7*7}}"
        ]

        for payload in injection_payloads:
            query = {
                'query': f'{{ user(id: "{payload}") {{ id }} }}'
            }

            try:
                response = self.session.post(self.target_url, json=query, timeout=10)

                if response.status_code == 200:
                    try:
                        data = response.json()

                        if 'errors' in data:
                            error_msg = str(data['errors']).lower()

                            # Check for SQL errors
                            if any(err in error_msg for err in ['sql', 'mysql', 'postgresql', 'syntax error']):
                                vuln = {
                                    'type': 'GraphQL SQL Injection',
                                    'severity': 'critical',
                                    'url': self.target_url,
                                    'payload': payload,
                                    'evidence': 'SQL error message in GraphQL response',
                                    'cwe': 'CWE-89'
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"[!] CRITICAL: SQL injection possible!")
                                return

                    except json.JSONDecodeError:
                        pass

            except Exception as e:
                pass

    def _save_results(self):
        """Save results to file"""
        results = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities,
            'schema_types': len(self.schema.get('types', [])) if self.schema else 0,
            'summary': {
                'total': len(self.vulnerabilities),
                'critical': sum(1 for v in self.vulnerabilities if v['severity'] == 'critical'),
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
        print("Usage: python3 graphql_scanner.py <graphql_url>")
        print("\nExample:")
        print("  python3 graphql_scanner.py https://api.example.com/graphql")
        sys.exit(1)

    scanner = GraphQLScanner(sys.argv[1])
    results = scanner.scan()

    if results:
        print(f"\n[+] Scan complete!")
        print(f"    Vulnerabilities found: {len(results['vulnerabilities'])}")
