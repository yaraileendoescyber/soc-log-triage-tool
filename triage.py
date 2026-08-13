#!/usr/bin/env python3
"""
SOC Log Triage Tool
--------------------
Parses authentication log data (CSV) and flags suspicious activity a
Tier-1 SOC analyst would need to triage: brute-force login attempts,
off-hours access, and logins from IPs seen across multiple accounts
(credential-stuffing indicator).

Findings are scored by severity and mapped to MITRE ATT&CK techniques
so results can be handed straight to an incident report.

Usage:
    python3 triage.py sample_auth_logs.csv
    python3 triage.py sample_auth_logs.csv --brute-threshold 5 --window 10

Author: Yaraileen Gonzalez-Sanchez
"""

import argparse
import csv
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# --- MITRE ATT&CK technique references used by this tool -------------------
MITRE_MAP = {
    "brute_force": ("T1110", "Brute Force"),
    "credential_stuffing": ("T1110.004", "Credential Stuffing"),
    "off_hours_login": ("T1078", "Valid Accounts (anomalous usage)"),
    "impossible_travel": ("T1078.002", "Valid Accounts: Domain Accounts (geo anomaly)"),
}

BUSINESS_HOURS_START = 6   # 6 AM
BUSINESS_HOURS_END = 20    # 8 PM


def load_events(filepath):
    """Load auth log CSV. Expected columns:
    timestamp,username,src_ip,status,geo_country
    status must be 'success' or 'failure'
    """
    events = []
    with open(filepath, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["timestamp"] = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
            events.append(row)
    events.sort(key=lambda r: r["timestamp"])
    return events


def detect_brute_force(events, threshold=5, window_minutes=10):
    """Flag source IPs with >= threshold failed logins within a rolling window."""
    findings = []
    by_ip = defaultdict(list)
    for e in events:
        if e["status"] == "failure":
            by_ip[e["src_ip"]].append(e)

    for ip, fails in by_ip.items():
        fails.sort(key=lambda r: r["timestamp"])
        for i in range(len(fails)):
            window_end = fails[i]["timestamp"] + timedelta(minutes=window_minutes)
            burst = [x for x in fails[i:] if x["timestamp"] <= window_end]
            if len(burst) >= threshold:
                targeted_accounts = sorted(set(x["username"] for x in burst))
                findings.append({
                    "type": "brute_force",
                    "src_ip": ip,
                    "attempt_count": len(burst),
                    "window_minutes": window_minutes,
                    "start": burst[0]["timestamp"],
                    "end": burst[-1]["timestamp"],
                    "accounts_targeted": targeted_accounts,
                    "severity": "High" if len(targeted_accounts) == 1 else "Critical",
                })
                break  # one finding per IP is enough for the report
    return findings


def detect_credential_stuffing(events, min_accounts=4, window_minutes=15):
    """Flag a single IP attempting logins against many distinct accounts
    in a short window — classic credential-stuffing pattern rather than
    a brute force against one account."""
    findings = []
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["src_ip"]].append(e)

    for ip, attempts in by_ip.items():
        attempts.sort(key=lambda r: r["timestamp"])
        for i in range(len(attempts)):
            window_end = attempts[i]["timestamp"] + timedelta(minutes=window_minutes)
            burst = [x for x in attempts[i:] if x["timestamp"] <= window_end]
            accounts = set(x["username"] for x in burst)
            if len(accounts) >= min_accounts:
                findings.append({
                    "type": "credential_stuffing",
                    "src_ip": ip,
                    "distinct_accounts": len(accounts),
                    "accounts": sorted(accounts),
                    "start": burst[0]["timestamp"],
                    "end": burst[-1]["timestamp"],
                    "severity": "Critical",
                })
                break
    return findings


def detect_off_hours_success(events):
    """Flag successful logins outside normal business hours."""
    findings = []
    for e in events:
        if e["status"] == "success":
            hour = e["timestamp"].hour
            if hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END:
                findings.append({
                    "type": "off_hours_login",
                    "username": e["username"],
                    "src_ip": e["src_ip"],
                    "timestamp": e["timestamp"],
                    "severity": "Medium",
                })
    return findings


def detect_impossible_travel(events, max_hours_between=3):
    """Flag same-user successful logins from different countries within
    an implausible time window."""
    findings = []
    by_user = defaultdict(list)
    for e in events:
        if e["status"] == "success":
            by_user[e["username"]].append(e)

    for user, logins in by_user.items():
        logins.sort(key=lambda r: r["timestamp"])
        for a, b in zip(logins, logins[1:]):
            if a["geo_country"] != b["geo_country"]:
                gap = (b["timestamp"] - a["timestamp"]).total_seconds() / 3600
                if gap <= max_hours_between:
                    findings.append({
                        "type": "impossible_travel",
                        "username": user,
                        "from_country": a["geo_country"],
                        "to_country": b["geo_country"],
                        "hours_apart": round(gap, 2),
                        "src_ip_a": a["src_ip"],
                        "src_ip_b": b["src_ip"],
                        "severity": "Critical",
                    })
    return findings


def build_report(events, findings, args):
    lines = []
    lines.append("=" * 72)
    lines.append("SOC TRIAGE REPORT")
    lines.append("=" * 72)
    lines.append(f"Log source analyzed : {args.filepath}")
    lines.append(f"Events parsed        : {len(events)}")
    lines.append(f"Time range            : {events[0]['timestamp']} -> {events[-1]['timestamp']}")
    lines.append(f"Total findings        : {sum(len(v) for v in findings.values())}")
    lines.append("")

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    all_findings = []
    for category, items in findings.items():
        for item in items:
            item["_category"] = category
            all_findings.append(item)
    all_findings.sort(key=lambda x: severity_order.get(x["severity"], 9))

    if not all_findings:
        lines.append("No suspicious activity met detection thresholds.")
        return "\n".join(lines)

    for i, f in enumerate(all_findings, 1):
        technique_id, technique_name = MITRE_MAP[f["type"]]
        lines.append(f"[{i}] {f['severity'].upper()}  --  {f['type'].replace('_', ' ').title()}")
        lines.append(f"    MITRE ATT&CK: {technique_id} ({technique_name})")

        if f["type"] == "brute_force":
            lines.append(f"    Source IP     : {f['src_ip']}")
            lines.append(f"    Attempts      : {f['attempt_count']} failed logins in {f['window_minutes']} min")
            lines.append(f"    Window        : {f['start']} -> {f['end']}")
            lines.append(f"    Account(s)    : {', '.join(f['accounts_targeted'])}")
            lines.append(f"    Recommendation: Block/rate-limit {f['src_ip']}; force password reset on targeted account(s); check for successful login immediately after burst.")

        elif f["type"] == "credential_stuffing":
            lines.append(f"    Source IP     : {f['src_ip']}")
            lines.append(f"    Accounts hit  : {f['distinct_accounts']} distinct usernames")
            lines.append(f"    Accounts      : {', '.join(f['accounts'])}")
            lines.append(f"    Window        : {f['start']} -> {f['end']}")
            lines.append(f"    Recommendation: Block {f['src_ip']} at perimeter; check breached-credential exposure for targeted accounts; enforce MFA.")

        elif f["type"] == "off_hours_login":
            lines.append(f"    User          : {f['username']}")
            lines.append(f"    Source IP     : {f['src_ip']}")
            lines.append(f"    Timestamp     : {f['timestamp']} (outside {BUSINESS_HOURS_START}:00-{BUSINESS_HOURS_END}:00)")
            lines.append(f"    Recommendation: Verify with user/manager; check for VPN/on-call justification.")

        elif f["type"] == "impossible_travel":
            lines.append(f"    User          : {f['username']}")
            lines.append(f"    Geo change    : {f['from_country']} -> {f['to_country']} in {f['hours_apart']}h")
            lines.append(f"    Source IPs    : {f['src_ip_a']} -> {f['src_ip_b']}")
            lines.append(f"    Recommendation: High-confidence account compromise indicator; force session termination + password reset + MFA re-enrollment.")

        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="SOC authentication log triage tool")
    parser.add_argument("filepath", help="Path to auth log CSV (timestamp,username,src_ip,status,geo_country)")
    parser.add_argument("--brute-threshold", type=int, default=5, help="Failed attempts to flag as brute force")
    parser.add_argument("--window", type=int, default=10, help="Rolling window in minutes for brute-force detection")
    parser.add_argument("--out", default=None, help="Optional path to write the report to a file")
    args = parser.parse_args()

    events = load_events(args.filepath)

    findings = {
        "brute_force": detect_brute_force(events, args.brute_threshold, args.window),
        "credential_stuffing": detect_credential_stuffing(events),
        "off_hours_login": detect_off_hours_success(events),
        "impossible_travel": detect_impossible_travel(events),
    }

    report = build_report(events, findings, args)
    print(report)

    if args.out:
        with open(args.out, "w") as f:
            f.write(report)
        print(f"\n[+] Report written to {args.out}")


if __name__ == "__main__":
    sys.exit(main())
