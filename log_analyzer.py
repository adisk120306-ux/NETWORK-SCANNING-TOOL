#!/usr/bin/env python3

import argparse
import json
import re
from collections import Counter
from datetime import datetime
from html import escape


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

FAILED_PATTERNS = [
    r"failed password",
    r"authentication failure",
    r"login failed",
    r"failed login",
    r"invalid user",
]

SUCCESS_PATTERNS = [
    r"accepted password",
    r"accepted publickey",
    r"login successful",
    r"successful login",
]


def find_ips(line):
    return IP_RE.findall(line)


def contains_any(line, patterns):
    line_lower = line.lower()
    return any(re.search(pattern, line_lower) for pattern in patterns)


def analyze_log(filename):
    failed_ips = Counter()
    successful_ips = Counter()
    all_ips = Counter()

    status_codes = Counter()
    total_lines = 0
    failed_logins = 0
    successful_logins = 0

    with open(filename, "r", errors="replace") as f:
        for line in f:
            total_lines += 1

            ips = find_ips(line)

            for ip in ips:
                all_ips[ip] += 1

            if contains_any(line, FAILED_PATTERNS):
                failed_logins += 1
                for ip in ips:
                    failed_ips[ip] += 1

            if contains_any(line, SUCCESS_PATTERNS):
                successful_logins += 1
                for ip in ips:
                    successful_ips[ip] += 1

            # HTTP status codes such as 200, 404, 500
            matches = re.findall(
                r"\s([1-5][0-9]{2})\s",
                line
            )

            for code in matches:
                status_codes[code] += 1

    return {
        "file": filename,
        "analyzed_at": datetime.now().isoformat(),
        "total_lines": total_lines,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "top_failed_ips": failed_ips.most_common(20),
        "top_successful_ips": successful_ips.most_common(20),
        "top_ips": all_ips.most_common(20),
        "http_status_codes": status_codes.most_common(),
    }


def print_report(data):
    print("\n" + "=" * 60)
    print("              LOG ANALYZER REPORT")
    print("=" * 60)

    print(f"\nFile: {data['file']}")
    print(f"Lines analyzed: {data['total_lines']}")
    print(f"Failed logins: {data['failed_logins']}")
    print(f"Successful logins: {data['successful_logins']}")

    print("\nTop IPs:")
    for ip, count in data["top_ips"]:
        print(f"  {ip:<20} {count}")

    print("\nIPs with failed logins:")
    for ip, count in data["top_failed_ips"]:
        print(f"  {ip:<20} {count}")

    print("\nHTTP status codes:")
    for code, count in data["http_status_codes"]:
        print(f"  {code}: {count}")

    print("\n" + "=" * 60)


def save_json(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)


def save_html(data, filename):
    rows_ips = ""

    for ip, count in data["top_ips"]:
        rows_ips += f"<tr><td>{escape(ip)}</td><td>{count}</td></tr>"

    rows_failed = ""

    for ip, count in data["top_failed_ips"]:
        rows_failed += f"<tr><td>{escape(ip)}</td><td>{count}</td></tr>"

    rows_status = ""

    for code, count in data["http_status_codes"]:
        rows_status += f"<tr><td>{escape(str(code))}</td><td>{count}</td></tr>"

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Log Analyzer Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background: #111827;
    color: #f9fafb;
    margin: 40px;
}}

.card {{
    background: #1f2937;
    padding: 20px;
    margin-bottom: 20px;
    border-radius: 10px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th, td {{
    padding: 10px;
    border-bottom: 1px solid #374151;
    text-align: left;
}}

th {{
    color: #60a5fa;
}}

.warning {{
    color: #f87171;
}}
</style>
</head>

<body>

<h1>Log Analyzer Report</h1>

<div class="card">
<h2>Summary</h2>
<p>File: {escape(data["file"])}</p>
<p>Lines analyzed: {data["total_lines"]}</p>
<p>Failed logins: <span class="warning">{data["failed_logins"]}</span></p>
<p>Successful logins: {data["successful_logins"]}</p>
</div>

<div class="card">
<h2>Top IP Addresses</h2>
<table>
<tr><th>IP Address</th><th>Occurrences</th></tr>
{rows_ips}
</table>
</div>

<div class="card">
<h2>Failed Login Sources</h2>
<table>
<tr><th>IP Address</th><th>Failures</th></tr>
{rows_failed}
</table>
</div>

<div class="card">
<h2>HTTP Status Codes</h2>
<table>
<tr><th>Status</th><th>Count</th></tr>
{rows_status}
</table>
</div>

</body>
</html>
"""

    with open(filename, "w") as f:
        f.write(html)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze authorized security/server logs."
    )

    parser.add_argument(
        "logfile",
        help="Path to the log file"
    )

    parser.add_argument(
        "--json",
        help="Save JSON report"
    )

    parser.add_argument(
        "--html",
        help="Save HTML report"
    )

    args = parser.parse_args()

    try:
        data = analyze_log(args.logfile)

        print_report(data)

        if args.json:
            save_json(data, args.json)
            print(f"\nJSON report saved to: {args.json}")

        if args.html:
            save_html(data, args.html)
            print(f"HTML report saved to: {args.html}")

    except FileNotFoundError:
        print(f"Error: log file not found: {args.logfile}")
    except PermissionError:
        print(f"Error: permission denied: {args.logfile}")


if __name__ == "__main__":
    main()
