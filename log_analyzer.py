#!/usr/bin/env python3
"""
Security Log Analyzer - Detect suspicious activity in server log files.

Parses Apache/Nginx access logs and auth logs to identify potential
security threats such as brute-force attacks, directory traversal,
SQL injection attempts, and suspicious user agents.

Usage:
    python log_analyzer.py <logfile> [options]
    python log_analyzer.py access.log --top 20
    python log_analyzer.py auth.log --format auth

Author: SebMRX
"""

import re
import argparse
import sys
import json
from collections import Counter, defaultdict
from datetime import datetime


# Suspicious patterns for web attack detection
ATTACK_PATTERNS = {
    "SQL Injection": [
        r"(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|drop\s+table|insert\s+into|select\s+from)",
        r"(?i)(;\s*drop|--\s*$|/\*.*\*/|benchmark\s*\(|sleep\s*\()",
    ],
    "XSS (Cross-Site Scripting)": [
        r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|eval\s*\()",
        r"(?i)(alert\s*\(|document\.cookie|document\.location)",
    ],
    "Directory Traversal": [
        r"(\.\./|\.\.\\|%2e%2e|%252e%252e)",
        r"(?i)(/etc/passwd|/etc/shadow|/proc/self|/windows/system32)",
    ],
    "Command Injection": [
        r"(;\s*cat\s|;\s*ls\s|;\s*wget\s|;\s*curl\s|\|\s*bash)",
        r"(?i)(\$\(|`.*`|;\s*rm\s|;\s*chmod|;\s*nc\s)",
    ],
    "Path Probing": [
        r"(?i)(\.env|\.git/|\.htaccess|wp-admin|wp-login|phpmyadmin)",
        r"(?i)(admin\.php|config\.php|setup\.php|install\.php|\.bak|\.sql)",
    ],
    "Scanner/Bot Activity": [
        r"(?i)(nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz|burpsuite)",
        r"(?i)(havij|acunetix|nessus|openvas|w3af)",
    ],
}

# Suspicious HTTP status codes
SUSPICIOUS_STATUS = {
    "400": "Bad Request",
    "401": "Unauthorized",
    "403": "Forbidden",
    "404": "Not Found (Probing)",
    "405": "Method Not Allowed",
    "500": "Server Error",
}

# Apache/Nginx combined log format regex
ACCESS_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"'
)

# Auth log pattern (Linux)
AUTH_LOG_PATTERN = re.compile(
    r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+'
    r'(?P<host>\S+)\s+(?P<service>\S+?)(?:\[\d+\])?:\s+'
    r'(?P<message>.*)'
)


class LogAnalyzer:
    def __init__(self):
        self.entries = []
        self.ip_counter = Counter()
        self.path_counter = Counter()
        self.status_counter = Counter()
        self.ua_counter = Counter()
        self.attacks = defaultdict(list)
        self.failed_logins = defaultdict(int)
        self.hourly_traffic = Counter()

    def parse_access_log(self, filepath):
        """Parse Apache/Nginx access log file."""
        line_count = 0
        parsed = 0

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line_count += 1
                match = ACCESS_LOG_PATTERN.match(line.strip())
                if match:
                    entry = match.groupdict()
                    self.entries.append(entry)
                    self.ip_counter[entry["ip"]] += 1
                    self.path_counter[entry["path"]] += 1
                    self.status_counter[entry["status"]] += 1
                    self.ua_counter[entry["user_agent"]] += 1

                    # Parse hour for traffic analysis
                    try:
                        ts = datetime.strptime(
                            entry["timestamp"], "%d/%b/%Y:%H:%M:%S %z"
                        )
                        self.hourly_traffic[ts.strftime("%Y-%m-%d %H:00")] += 1
                    except ValueError:
                        pass

                    # Check for attack patterns
                    self._check_attacks(entry)
                    parsed += 1

        return line_count, parsed

    def parse_auth_log(self, filepath):
        """Parse Linux auth log for failed login attempts."""
        line_count = 0
        parsed = 0

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line_count += 1
                match = AUTH_LOG_PATTERN.match(line.strip())
                if match:
                    entry = match.groupdict()
                    message = entry["message"]
                    parsed += 1

                    # Failed SSH login
                    failed = re.search(
                        r"Failed password for (?:invalid user )?(\S+) from (\S+)",
                        message,
                    )
                    if failed:
                        user, ip = failed.groups()
                        self.failed_logins[ip] += 1
                        self.attacks["Brute Force (SSH)"].append(
                            {
                                "ip": ip,
                                "detail": f"Failed login for user '{user}'",
                                "timestamp": entry["timestamp"],
                            }
                        )

                    # Invalid user attempts
                    invalid = re.search(
                        r"Invalid user (\S+) from (\S+)", message
                    )
                    if invalid:
                        user, ip = invalid.groups()
                        self.attacks["Invalid User Enumeration"].append(
                            {
                                "ip": ip,
                                "detail": f"Tried non-existent user '{user}'",
                                "timestamp": entry["timestamp"],
                            }
                        )

        return line_count, parsed

    def _check_attacks(self, entry):
        """Check a log entry against known attack patterns."""
        path = entry["path"]
        ua = entry["user_agent"]
        check_text = f"{path} {ua}"

        for attack_type, patterns in ATTACK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, check_text):
                    self.attacks[attack_type].append(
                        {
                            "ip": entry["ip"],
                            "path": path,
                            "status": entry["status"],
                            "user_agent": ua[:80],
                        }
                    )
                    break

    def detect_brute_force(self, threshold=50):
        """Detect IPs with abnormally high request counts."""
        suspects = []
        for ip, count in self.ip_counter.most_common():
            if count >= threshold:
                # Count 401/403 responses for this IP
                auth_fails = sum(
                    1
                    for e in self.entries
                    if e["ip"] == ip and e["status"] in ("401", "403")
                )
                suspects.append(
                    {"ip": ip, "total_requests": count, "auth_failures": auth_fails}
                )
        return suspects

    def generate_report(self, top_n=10):
        """Generate a complete analysis report."""
        report = {}

        report["summary"] = {
            "total_entries": len(self.entries),
            "unique_ips": len(self.ip_counter),
            "unique_paths": len(self.path_counter),
            "attack_types_detected": len(self.attacks),
            "total_suspicious_events": sum(len(v) for v in self.attacks.values()),
        }

        report["top_ips"] = [
            {"ip": ip, "count": count}
            for ip, count in self.ip_counter.most_common(top_n)
        ]

        report["top_paths"] = [
            {"path": path, "count": count}
            for path, count in self.path_counter.most_common(top_n)
        ]

        report["status_codes"] = dict(self.status_counter.most_common())

        report["attacks"] = {
            attack_type: {
                "count": len(events),
                "unique_ips": len(set(e["ip"] for e in events)),
                "samples": events[:5],
            }
            for attack_type, events in sorted(
                self.attacks.items(), key=lambda x: len(x[1]), reverse=True
            )
        }

        report["brute_force_suspects"] = self.detect_brute_force()

        if self.failed_logins:
            report["failed_logins"] = dict(
                Counter(self.failed_logins).most_common(top_n)
            )

        return report


def display_report(report):
    """Display formatted analysis report."""
    red = "\033[91m"
    yellow = "\033[93m"
    green = "\033[92m"
    bold = "\033[1m"
    reset = "\033[0m"

    s = report["summary"]

    print()
    print("=" * 65)
    print(f"  {bold}SECURITY LOG ANALYSIS REPORT{reset}")
    print("=" * 65)

    # Summary
    print(f"\n  {bold}[Summary]{reset}")
    print(f"  Total entries      : {s['total_entries']:,}")
    print(f"  Unique IPs         : {s['unique_ips']:,}")
    print(f"  Unique paths       : {s['unique_paths']:,}")
    print(f"  Attack types found : {s['attack_types_detected']}")
    print(f"  Suspicious events  : {s['total_suspicious_events']:,}")

    # Top IPs
    print(f"\n  {bold}[Top Source IPs]{reset}")
    for item in report["top_ips"]:
        print(f"    {item['ip']:<20} {item['count']:>6} requests")

    # Status codes
    print(f"\n  {bold}[HTTP Status Codes]{reset}")
    for code, count in sorted(report["status_codes"].items()):
        label = SUSPICIOUS_STATUS.get(code, "")
        marker = f" {yellow}⚠{reset}" if code in SUSPICIOUS_STATUS else ""
        print(f"    {code} : {count:>6}{marker}  {label}")

    # Attacks
    if report["attacks"]:
        print(f"\n  {bold}{red}[Detected Attacks]{reset}")
        for attack_type, data in report["attacks"].items():
            print(f"\n    {red}▸ {attack_type}{reset}")
            print(f"      Events: {data['count']}  |  Unique IPs: {data['unique_ips']}")
            for sample in data["samples"][:3]:
                ip = sample.get("ip", "?")
                detail = sample.get("path", sample.get("detail", ""))
                print(f"      - [{ip}] {detail[:70]}")
    else:
        print(f"\n  {green}[+] No known attack patterns detected{reset}")

    # Brute force suspects
    if report["brute_force_suspects"]:
        print(f"\n  {bold}{yellow}[Brute Force Suspects]{reset}")
        for suspect in report["brute_force_suspects"]:
            print(
                f"    {suspect['ip']:<20} "
                f"{suspect['total_requests']:>5} requests  |  "
                f"{suspect['auth_failures']:>4} auth failures"
            )

    # Failed logins (auth log)
    if "failed_logins" in report:
        print(f"\n  {bold}{red}[Failed SSH Logins by IP]{reset}")
        for ip, count in report["failed_logins"].items():
            marker = " ← LIKELY BRUTE FORCE" if count >= 10 else ""
            print(f"    {ip:<20} {count:>5} failures{red}{marker}{reset}")

    print()
    print("=" * 65)
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer - Detect suspicious activity in log files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_analyzer.py /var/log/apache2/access.log
  python log_analyzer.py access.log --top 20
  python log_analyzer.py /var/log/auth.log --format auth
  python log_analyzer.py access.log --json report.json
        """,
    )
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument(
        "--format",
        choices=["access", "auth"],
        default="access",
        help="Log format: access (Apache/Nginx) or auth (syslog) [default: access]",
    )
    parser.add_argument(
        "--top", type=int, default=10, help="Number of top entries to show [default: 10]"
    )
    parser.add_argument(
        "--json", metavar="FILE", help="Export report as JSON to specified file"
    )

    args = parser.parse_args()

    analyzer = LogAnalyzer()

    print(f"\n[*] Analyzing: {args.logfile}")
    print(f"[*] Format: {args.format}")

    if args.format == "access":
        total, parsed = analyzer.parse_access_log(args.logfile)
    else:
        total, parsed = analyzer.parse_auth_log(args.logfile)

    print(f"[*] Processed {parsed:,}/{total:,} lines")

    report = analyzer.generate_report(top_n=args.top)
    display_report(report)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[+] Report saved to {args.json}")


if __name__ == "__main__":
    main()
