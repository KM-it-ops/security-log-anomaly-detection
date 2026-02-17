# Security Log Anomaly Detection

A rule-based and statistical anomaly detection system that analyzes system/network logs to identify security threats including brute force attacks, port scans, off-hours sensitive file access, and privilege escalation attempts.

## Goal

Demonstrate the ability to build a security monitoring system that establishes a behavioral baseline of "normal" activity and detects deviations that indicate potential attacks or policy violations — a core SOC analyst skill.

## Tools & Technologies

- **Python 3.10+**
- **pandas** — Log parsing, time-series aggregation, filtering
- **NumPy** — Statistical calculations (z-scores, thresholds)
- **collections / datetime** — Event counting, time-window analysis

## Architecture

```
System Logs (7 days, ~700+ events)
    │
    ├──► Baseline Profiler
    │       • Auth failure rate (mean/std per hour)
    │       • Event volume distribution
    │       • Known IP addresses
    │       • Business hours definition
    │       • Sensitive file list
    │
    └──► Anomaly Detection Engine
            │
            ├── Rule: Brute Force (>10 failures/IP/10min)
            ├── Rule: Port Scan (>15 unique ports/IP/5min)
            ├── Rule: Off-Hours Sensitive Access
            ├── Rule: Unknown IP Activity
            ├── Rule: Privilege Escalation
            └── Statistical: Event Volume Spike (z-score)
                    │
                    ▼
              Alert Report
              • Severity classification (CRITICAL/HIGH/MEDIUM)
              • Timeline of detections
              • Detection accuracy vs. ground truth
```

## How to Run

```bash
# Install dependencies
pip install pandas numpy

# Run the full detection pipeline
python anomaly_detector.py
```

This will:
1. Generate 7 days of synthetic system logs (~700+ events with injected anomalies)
2. Build a baseline profile from clean (non-anomalous) activity
3. Run 6 detection rules against the full log dataset
4. Generate a detailed alert report with severity classifications
5. Calculate detection accuracy against known ground truth
6. Save all results to `results/anomaly_report.json` and logs to `data/system_logs.csv`

## Detection Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| Brute Force | >10 auth failures from same IP in 10 minutes | HIGH |
| Port Scan | >15 unique ports from same IP in 5 minutes | HIGH |
| Off-Hours Sensitive Access | Sensitive file (/etc/shadow, etc.) accessed outside 7 AM–7 PM | CRITICAL |
| Unknown IP | Activity from IP not in baseline known-IP list | MEDIUM |
| Privilege Escalation | sudo usage, especially with dangerous commands | CRITICAL |
| Event Volume Spike | Hourly event count exceeds z-score threshold of 2.5 | MEDIUM |

## What "Normal" Looks Like (Baseline)

The system establishes normal behavior by profiling clean log data:

- **Authentication failures**: ~1–3 per hour (typos, expired sessions)
- **Active hours**: Most activity between 7 AM and 7 PM
- **Known IPs**: Internal subnet 10.0.1.x
- **Port connections**: Limited to common services (22, 80, 443, 3306, 8080)
- **File access**: Normal working files, not system-critical paths

Anything that deviates significantly from these patterns triggers an alert.

## Example Detections

**Brute Force Attack (Day 3, 2:15 AM)**
- 50 failed authentication attempts from 185.220.101.42 in 5 minutes
- Targeted users: admin, root, test, mkurdi, jsmith
- Severity: HIGH

**Port Scan (Day 5, 3:42 AM)**
- 40 unique ports scanned from external IP in under 2 minutes
- Classic reconnaissance behavior
- Severity: HIGH

**Off-Hours Sensitive File Access (Day 4, 1:33 AM)**
- User mkurdi accessed /etc/shadow at 1:33 AM
- Could indicate compromised credentials or insider threat
- Severity: CRITICAL

## Limitations

- **Synthetic data**: Uses generated logs rather than real SIEM output. Production systems would ingest from Splunk, ELK Stack, or QRadar.
- **Rule-based only**: No machine learning models. A production system would layer ML anomaly detection (Isolation Forest, autoencoders) on top of rules for catching novel attack patterns.
- **No correlation engine**: Each rule operates independently. Real SOC tools correlate alerts across rules (e.g., port scan followed by brute force = coordinated attack).
- **Static baseline**: The baseline is computed once. Production systems use rolling baselines that adapt to changing patterns.
- **No alert fatigue management**: Does not prioritize or deduplicate overlapping alerts.

## Lessons Learned

1. **Baselines are foundational**: You cannot detect anomalies without first defining what "normal" looks like. This mirrors real SOC operations where baseline profiling is a critical first step.
2. **Rule-based detection is powerful for known threats**: Simple threshold rules caught 90%+ of injected anomalies. For known attack patterns (brute force, port scans), rules are fast, explainable, and reliable.
3. **Time-window analysis matters**: The same event can be normal in isolation but anomalous in context. 3 failed logins per hour is normal; 50 in 10 minutes from one IP is an attack.
4. **Severity classification drives response**: Not all anomalies require the same urgency. Structuring alerts by severity helps SOC analysts prioritize their response.

## Author

Michael Kurdi — [LinkedIn](https://www.linkedin.com/in/michael-kurdi) | CompTIA Security+ | B.S. Information Technology (Cybersecurity), SNHU
