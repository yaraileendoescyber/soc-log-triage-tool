# SOC Log Triage Tool

A Python tool that ingests authentication logs (CSV) and automatically flags the behaviors a Tier-1 SOC analyst is expected to catch on shift: brute-force attempts, credential-stuffing bursts, off-hours logins, and impossible-travel account compromise indicators. Each finding is severity-scored and mapped to a MITRE ATT&CK technique so the output can be dropped straight into an incident ticket.

## Objective / Scenario

Manually eyeballing authentication logs for suspicious patterns doesn't scale past a few hundred rows. This tool automates the first-pass triage a SOC analyst does at the start of a shift or during an alert investigation — turning a raw log export into a prioritized, MITRE-mapped findings list in seconds.

## Tools Used

- Python 3 (standard library only — `csv`, `datetime`, `argparse`, `collections`)
- MITRE ATT&CK framework for technique mapping
- Synthetic authentication log data modeled on real-world log schemas (timestamp, username, source IP, status, geo-country)

## Methodology

The tool runs four independent detections over the log set:

| Detection | Logic | MITRE ATT&CK |
|---|---|---|
| **Brute force** | ≥5 failed logins from one source IP within a 10-minute rolling window | T1110 |
| **Credential stuffing** | One source IP attempting logins against ≥4 distinct usernames in a 15-minute window | T1110.004 |
| **Off-hours login** | Successful login outside 06:00–20:00 | T1078 |
| **Impossible travel** | Same user, successful logins from two different countries within 3 hours | T1078.002 |

Findings are de-duplicated per IP/user, sorted by severity (Critical → High → Medium), and rendered into a report with a recommended response action for each finding — the same structure I'd use writing up a real ticket.

## How to Run It

```bash
python3 triage.py sample_auth_logs.csv --out triage_report.txt
```

Optional flags:
- `--brute-threshold` — failed attempts required to flag brute force (default: 5)
- `--window` — rolling window in minutes for brute-force detection (default: 10)

## Sample Findings (from `sample_auth_logs.csv`)

Running the tool against the included synthetic dataset (60 auth events over ~30 hours) surfaced **7 findings**, including:

- **Critical — Credential stuffing** from `45.155.205.88`: 7 distinct accounts targeted in under 3 minutes (T1110.004)
- **Critical — Impossible travel** on user `tpatel`: login from the US followed by a login from Vietnam 1.67 hours later (T1078.002)
- **Critical — Impossible travel** on user `rgarcia`: US → Romania → US within 20 minutes, immediately following a brute-force burst against the same account — a strong signal the brute force succeeded (T1110 → T1078.002 chain)
- **High — Brute force** from `185.220.101.47`: 9 failed attempts against a single account in under 6 minutes, followed by a successful login (T1110)
- **Medium — Off-hours login**: successful authentication at 02:14 local time outside normal business hours (T1078)

Full output: [`triage_report.txt`](./triage_report.txt)

## What I'd Recommend (Response Actions)

1. Block/rate-limit `45.155.205.88` and `185.220.101.47` at the perimeter — both show automated attack patterns (regular timing intervals, no legitimate browsing behavior)
2. Force password reset + MFA re-enrollment for `rgarcia` — the brute-force success followed immediately by cross-country logins is a high-confidence compromise chain, not two unrelated events
3. Confirm with `tpatel` and `mwong` directly whether the flagged logins were legitimate (VPN, travel, on-call) before closing those tickets
4. Feed both malicious IPs into the threat intel blocklist for future correlation

## Lessons Learned / Design Notes

- Chaining findings matters more than flagging them in isolation — the `rgarcia` case only becomes "critical, escalate now" when you connect the brute-force alert to the impossible-travel alert that follows it. A tool (or analyst) that reports these as two unrelated low-priority items misses the real story.
- Rolling-window detection (rather than fixed time buckets) avoids missing bursts that straddle a bucket boundary — a common false-negative in simpler log-counting approaches.
- Kept the dependency footprint to the Python standard library so the tool runs anywhere without setup friction, which matters when you need to run it fast during an active investigation.

## Next Steps

- Add a Sigma rule export so findings can be ported directly into a SIEM
- Extend geo-distance logic to use actual lat/long + plausible travel speed instead of a flat country-change check
- Add a `--format json` output mode for pipeline integration

---
*Part of my cybersecurity portfolio — built while transitioning into a SOC Analyst role. See my other projects at [your GitHub/portfolio link].*
