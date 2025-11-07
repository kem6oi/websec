#!/usr/bin/env python3
"""
Notification System
Send alerts to Slack, Discord, or custom webhooks
"""

import requests
import json
from datetime import datetime

class Notifier:
    """Send vulnerability notifications to various platforms"""

    def __init__(self, webhook_url=None, webhook_type='slack'):
        """
        Initialize notifier

        Args:
            webhook_url: Webhook URL (Slack or Discord)
            webhook_type: Type of webhook ('slack', 'discord', or 'custom')
        """
        self.webhook_url = webhook_url
        self.webhook_type = webhook_type.lower()

    def send_vulnerability_alert(self, vulnerability):
        """Send alert for a single vulnerability"""
        if not self.webhook_url:
            return False

        if self.webhook_type == 'slack':
            return self._send_slack(vulnerability)
        elif self.webhook_type == 'discord':
            return self._send_discord(vulnerability)
        else:
            return self._send_custom(vulnerability)

    def send_scan_complete(self, target, total_vulns, summary):
        """Send scan completion notification"""
        if not self.webhook_url:
            return False

        message = {
            'type': 'scan_complete',
            'target': target,
            'total_vulnerabilities': total_vulns,
            'summary': summary,
            'timestamp': datetime.now().isoformat()
        }

        if self.webhook_type == 'slack':
            return self._send_slack_scan_complete(message)
        elif self.webhook_type == 'discord':
            return self._send_discord_scan_complete(message)
        else:
            return self._send_custom(message)

    def _send_slack(self, vulnerability):
        """Send vulnerability alert to Slack"""
        severity = vulnerability.get('severity', 'medium')
        vuln_type = vulnerability.get('type', 'Unknown')
        url = vulnerability.get('url', 'N/A')
        evidence = vulnerability.get('evidence', 'No evidence')

        # Color based on severity
        color_map = {
            'critical': 'danger',
            'high': 'warning',
            'medium': '#FF9900',
            'low': '#36a64f'
        }

        payload = {
            'text': f'🚨 *New Vulnerability Detected!*',
            'attachments': [
                {
                    'color': color_map.get(severity, 'warning'),
                    'fields': [
                        {
                            'title': 'Type',
                            'value': vuln_type,
                            'short': True
                        },
                        {
                            'title': 'Severity',
                            'value': severity.upper(),
                            'short': True
                        },
                        {
                            'title': 'URL',
                            'value': url,
                            'short': False
                        },
                        {
                            'title': 'Evidence',
                            'value': evidence[:500],
                            'short': False
                        }
                    ],
                    'footer': 'WebSec Toolkit',
                    'ts': int(datetime.now().timestamp())
                }
            ]
        }

        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            print(f"[!] Failed to send Slack notification: {e}")
            return False

    def _send_discord(self, vulnerability):
        """Send vulnerability alert to Discord"""
        severity = vulnerability.get('severity', 'medium')
        vuln_type = vulnerability.get('type', 'Unknown')
        url = vulnerability.get('url', 'N/A')
        evidence = vulnerability.get('evidence', 'No evidence')

        # Color based on severity (decimal color)
        color_map = {
            'critical': 15158332,  # Red
            'high': 16098851,      # Orange
            'medium': 16776960,    # Yellow
            'low': 3066993         # Green
        }

        payload = {
            'embeds': [
                {
                    'title': '🚨 New Vulnerability Detected',
                    'color': color_map.get(severity, 16098851),
                    'fields': [
                        {
                            'name': 'Type',
                            'value': vuln_type,
                            'inline': True
                        },
                        {
                            'name': 'Severity',
                            'value': severity.upper(),
                            'inline': True
                        },
                        {
                            'name': 'URL',
                            'value': url[:1024],  # Discord field limit
                            'inline': False
                        },
                        {
                            'name': 'Evidence',
                            'value': evidence[:1024],
                            'inline': False
                        }
                    ],
                    'footer': {
                        'text': 'WebSec Toolkit'
                    },
                    'timestamp': datetime.now().isoformat()
                }
            ]
        }

        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            return response.status_code == 204 or response.status_code == 200
        except Exception as e:
            print(f"[!] Failed to send Discord notification: {e}")
            return False

    def _send_slack_scan_complete(self, message):
        """Send scan completion to Slack"""
        summary = message['summary']

        payload = {
            'text': f'✅ *Scan Complete: {message["target"]}*',
            'attachments': [
                {
                    'color': 'danger' if summary.get('critical', 0) > 0 else 'good',
                    'fields': [
                        {
                            'title': 'Total Vulnerabilities',
                            'value': str(message['total_vulnerabilities']),
                            'short': True
                        },
                        {
                            'title': 'Critical',
                            'value': str(summary.get('critical', 0)),
                            'short': True
                        },
                        {
                            'title': 'High',
                            'value': str(summary.get('high', 0)),
                            'short': True
                        },
                        {
                            'title': 'Medium',
                            'value': str(summary.get('medium', 0)),
                            'short': True
                        }
                    ],
                    'footer': 'WebSec Toolkit',
                    'ts': int(datetime.now().timestamp())
                }
            ]
        }

        try:
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            return response.status_code == 200
        except Exception as e:
            return False

    def _send_discord_scan_complete(self, message):
        """Send scan completion to Discord"""
        summary = message['summary']

        color = 3066993  # Green
        if summary.get('critical', 0) > 0:
            color = 15158332  # Red
        elif summary.get('high', 0) > 0:
            color = 16098851  # Orange

        payload = {
            'embeds': [
                {
                    'title': f'✅ Scan Complete: {message["target"]}',
                    'color': color,
                    'fields': [
                        {
                            'name': 'Total Vulnerabilities',
                            'value': str(message['total_vulnerabilities']),
                            'inline': True
                        },
                        {
                            'name': 'Critical',
                            'value': str(summary.get('critical', 0)),
                            'inline': True
                        },
                        {
                            'name': 'High',
                            'value': str(summary.get('high', 0)),
                            'inline': True
                        },
                        {
                            'name': 'Medium',
                            'value': str(summary.get('medium', 0)),
                            'inline': True
                        }
                    ],
                    'footer': {
                        'text': 'WebSec Toolkit'
                    },
                    'timestamp': datetime.now().isoformat()
                }
            ]
        }

        try:
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            return response.status_code == 204 or response.status_code == 200
        except Exception as e:
            return False

    def _send_custom(self, data):
        """Send to custom webhook"""
        try:
            response = requests.post(
                self.webhook_url,
                json=data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            print(f"[!] Failed to send custom webhook: {e}")
            return False


# Testing
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python3 notifier.py <webhook_url> <type>")
        print("\nTypes: slack, discord")
        print("\nExample:")
        print("  python3 notifier.py https://hooks.slack.com/... slack")
        sys.exit(1)

    webhook_url = sys.argv[1]
    webhook_type = sys.argv[2]

    notifier = Notifier(webhook_url, webhook_type)

    # Send test vulnerability
    test_vuln = {
        'type': 'XSS',
        'severity': 'high',
        'url': 'https://example.com/search?q=test',
        'evidence': 'Reflected XSS in search parameter'
    }

    print("[*] Sending test notification...")
    if notifier.send_vulnerability_alert(test_vuln):
        print("[+] Notification sent successfully!")
    else:
        print("[!] Failed to send notification")
