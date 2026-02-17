"""
Security Log Anomaly Detection
===============================
A rule-based and statistical anomaly detection system that analyzes
system/network logs to flag unusual behavior such as failed login
spikes, port scans, and off-hours access.

Author: Michael Kurdi
Project: Portfolio — Cybersecurity
Tools: Python, pandas, NumPy, statistics
"""

import os
import json
import csv
import random
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# 1. SYNTHETIC LOG GENERATION
# ---------------------------------------------------------------------------
# Generates realistic system logs with injected anomalies.
# In production, these would come from SIEM tools (Splunk, ELK, QRadar).
# ---------------------------------------------------------------------------

LOG_TYPES = {
    "auth_success": "Authentication successful for user {user} from {ip}",
    "auth_failure": "Authentication failure for user {user} from {ip}",
    "ssh_login": "SSH session opened for user {user} from {ip}",
    "ssh_logout": "SSH session closed for user {user}",
    "file_access": "User {user} accessed {file}",
    "privilege_escalation": "User {user} executed sudo command: {command}",
    "port_connection": "Connection from {ip} to port {port}",
    "service_start": "Service {service} started",
    "service_stop": "Service {service} stopped",
    "firewall_block": "Firewall blocked connection from {ip} to port {port}",
}

NORMAL_USERS = ["mkurdi", "jsmith", "agarcia", "tchang", "bwilson"]
NORMAL_IPS = ["10.0.1.50", "10.0.1.51", "10.0.1.52", "10.0.1.53", "10.0.1.54"]
ATTACKER_IPS = ["185.220.101.42", "103.75.201.18", "45.33.32.156"]
SENSITIVE_FILES = ["/etc/shadow", "/etc/passwd", "/var/log/auth.log", "/root/.ssh/authorized_keys"]
NORMAL_FILES = ["/home/user/report.pdf", "/var/www/html/index.html", "/tmp/data.csv"]
SERVICES = ["sshd", "nginx", "mysql", "cron", "postfix"]
SUDO_COMMANDS = ["apt update", "systemctl restart nginx", "cat /etc/shadow", "chmod 777 /tmp/exploit"]
COMMON_PORTS = [22, 80, 443, 3306, 8080]
SCAN_PORTS = list(range(1, 1025))


def generate_logs(n_days: int = 7, seed: int = 42) -> pd.DataFrame:
    """Generate synthetic system logs with injected anomalies."""
    rng = random.Random(seed)
    np_rng = np.random.default_rng(seed)
    logs = []
    start_date = datetime(2026, 2, 1, 0, 0, 0)

    for day in range(n_days):
        current_date = start_date + timedelta(days=day)

        # --- Normal activity (business hours: 8 AM - 6 PM) ---
        n_normal_events = rng.randint(80, 120)
        for _ in range(n_normal_events):
            hour = rng.choices(
                range(24),
                weights=[1,1,1,1,1,1,2,5,10,10,10,10,10,10,10,10,8,5,3,2,1,1,1,1],
                k=1
            )[0]
            minute = rng.randint(0, 59)
            second = rng.randint(0, 59)
            timestamp = current_date.replace(hour=hour, minute=minute, second=second)

            user = rng.choice(NORMAL_USERS)
            ip = rng.choice(NORMAL_IPS)

            # Mostly successful auth, some normal failures
            event_type = rng.choices(
                ["auth_success", "auth_failure", "ssh_login", "ssh_logout",
                 "file_access", "port_connection", "service_start"],
                weights=[30, 3, 10, 10, 20, 15, 5],
                k=1
            )[0]

            log_entry = {
                "timestamp": timestamp.isoformat(),
                "event_type": event_type,
                "user": user if "user" in LOG_TYPES[event_type] else "-",
                "source_ip": ip if "ip" in LOG_TYPES[event_type] else "-",
                "target": "-",
                "severity": "INFO",
                "is_anomaly": False,
                "anomaly_type": "-",
            }

            if event_type == "file_access":
                log_entry["target"] = rng.choice(NORMAL_FILES)
            elif event_type == "port_connection":
                log_entry["target"] = f"port:{rng.choice(COMMON_PORTS)}"

            logs.append(log_entry)

        # --- Injected Anomalies ---

        # ANOMALY 1: Brute force attack (day 3) — many failed logins from one IP
        if day == 2:
            attacker_ip = rng.choice(ATTACKER_IPS)
            base_time = current_date.replace(hour=2, minute=15)
            for i in range(50):
                timestamp = base_time + timedelta(seconds=rng.randint(0, 300))
                logs.append({
                    "timestamp": timestamp.isoformat(),
                    "event_type": "auth_failure",
                    "user": rng.choice(NORMAL_USERS + ["admin", "root", "test"]),
                    "source_ip": attacker_ip,
                    "target": "-",
                    "severity": "WARNING",
                    "is_anomaly": True,
                    "anomaly_type": "brute_force",
                })

        # ANOMALY 2: Port scan (day 5) — rapid connections to many ports
        if day == 4:
            attacker_ip = rng.choice(ATTACKER_IPS)
            base_time = current_date.replace(hour=3, minute=42)
            scanned_ports = rng.sample(SCAN_PORTS, 40)
            for i, port in enumerate(scanned_ports):
                timestamp = base_time + timedelta(seconds=i * 2)
                logs.append({
                    "timestamp": timestamp.isoformat(),
                    "event_type": "port_connection",
                    "user": "-",
                    "source_ip": attacker_ip,
                    "target": f"port:{port}",
                    "severity": "WARNING",
                    "is_anomaly": True,
                    "anomaly_type": "port_scan",
                })

        # ANOMALY 3: Off-hours sensitive file access (day 4)
        if day == 3:
            timestamp = current_date.replace(hour=1, minute=33, second=12)
            logs.append({
                "timestamp": timestamp.isoformat(),
                "event_type": "file_access",
                "user": "mkurdi",
                "source_ip": "10.0.1.50",
                "target": "/etc/shadow",
                "severity": "CRITICAL",
                "is_anomaly": True,
                "anomaly_type": "sensitive_file_offhours",
            })

        # ANOMALY 4: Privilege escalation attempt (day 6)
        if day == 5:
            timestamp = current_date.replace(hour=23, minute=47, second=8)
            logs.append({
                "timestamp": timestamp.isoformat(),
                "event_type": "privilege_escalation",
                "user": "jsmith",
                "source_ip": "10.0.1.51",
                "target": "chmod 777 /tmp/exploit",
                "severity": "CRITICAL",
                "is_anomaly": True,
                "anomaly_type": "privilege_escalation",
            })

    df = pd.DataFrame(logs)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


# ---------------------------------------------------------------------------
# 2. BASELINE PROFILING
# ---------------------------------------------------------------------------

class BaselineProfiler:
    """Establish what 'normal' looks like for the system."""

    def __init__(self, df: pd.DataFrame):
        self.df = df.copy()
        self.df["hour"] = self.df["timestamp"].dt.hour
        self.df["date"] = self.df["timestamp"].dt.date

    def compute_baseline(self) -> dict:
        """Compute baseline statistics from the log data."""
        baseline = {}

        # Auth failure rate per hour (mean and std)
        failures = self.df[self.df["event_type"] == "auth_failure"]
        hourly_failures = failures.groupby([self.df["date"], self.df["hour"]]).size()
        baseline["auth_failure_hourly_mean"] = float(hourly_failures.mean()) if len(hourly_failures) > 0 else 0
        baseline["auth_failure_hourly_std"] = float(hourly_failures.std()) if len(hourly_failures) > 1 else 1

        # Unique ports connected per hour (mean and std)
        port_events = self.df[self.df["event_type"] == "port_connection"]
        if len(port_events) > 0:
            hourly_ports = port_events.groupby([port_events["timestamp"].dt.date, port_events["timestamp"].dt.hour])["target"].nunique()
            baseline["unique_ports_hourly_mean"] = float(hourly_ports.mean())
            baseline["unique_ports_hourly_std"] = float(hourly_ports.std()) if len(hourly_ports) > 1 else 1
        else:
            baseline["unique_ports_hourly_mean"] = 0
            baseline["unique_ports_hourly_std"] = 1

        # Normal business hours
        baseline["business_hours_start"] = 7
        baseline["business_hours_end"] = 19

        # Known IPs
        baseline["known_ips"] = list(self.df[~self.df["is_anomaly"]]["source_ip"].unique())

        # Sensitive files
        baseline["sensitive_files"] = SENSITIVE_FILES

        # Events per hour distribution
        events_per_hour = self.df.groupby([self.df["date"], self.df["hour"]]).size()
        baseline["events_hourly_mean"] = float(events_per_hour.mean())
        baseline["events_hourly_std"] = float(events_per_hour.std()) if len(events_per_hour) > 1 else 1

        return baseline


# ---------------------------------------------------------------------------
# 3. ANOMALY DETECTION ENGINE
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """Rule-based + statistical anomaly detection on system logs."""

    def __init__(self, baseline: dict, z_threshold: float = 2.5):
        self.baseline = baseline
        self.z_threshold = z_threshold

    def detect(self, df: pd.DataFrame) -> list[dict]:
        """Run all detection rules against the log DataFrame."""
        alerts = []
        alerts.extend(self._detect_brute_force(df))
        alerts.extend(self._detect_port_scan(df))
        alerts.extend(self._detect_offhours_sensitive_access(df))
        alerts.extend(self._detect_unknown_ip(df))
        alerts.extend(self._detect_privilege_escalation(df))
        alerts.extend(self._detect_event_volume_spike(df))
        return alerts

    def _detect_brute_force(self, df: pd.DataFrame) -> list[dict]:
        """Rule: >10 auth failures from same IP within 10 minutes."""
        alerts = []
        failures = df[df["event_type"] == "auth_failure"].copy()

        for ip in failures["source_ip"].unique():
            ip_failures = failures[failures["source_ip"] == ip].sort_values("timestamp")
            if len(ip_failures) < 10:
                continue

            # Sliding window: 10-minute intervals
            for i in range(len(ip_failures)):
                window_start = ip_failures.iloc[i]["timestamp"]
                window_end = window_start + timedelta(minutes=10)
                window = ip_failures[
                    (ip_failures["timestamp"] >= window_start) &
                    (ip_failures["timestamp"] <= window_end)
                ]
                if len(window) >= 10:
                    alerts.append({
                        "rule": "BRUTE_FORCE",
                        "severity": "HIGH",
                        "timestamp": window_start.isoformat(),
                        "source_ip": ip,
                        "details": f"{len(window)} failed auth attempts in 10 min from {ip}",
                        "targeted_users": list(window["user"].unique()),
                    })
                    break  # One alert per IP per cluster

        return alerts

    def _detect_port_scan(self, df: pd.DataFrame) -> list[dict]:
        """Rule: >15 unique ports from same IP within 5 minutes."""
        alerts = []
        connections = df[df["event_type"] == "port_connection"].copy()

        for ip in connections["source_ip"].unique():
            ip_conns = connections[connections["source_ip"] == ip].sort_values("timestamp")
            if len(ip_conns) < 15:
                continue

            for i in range(len(ip_conns)):
                window_start = ip_conns.iloc[i]["timestamp"]
                window_end = window_start + timedelta(minutes=5)
                window = ip_conns[
                    (ip_conns["timestamp"] >= window_start) &
                    (ip_conns["timestamp"] <= window_end)
                ]
                unique_ports = window["target"].nunique()
                if unique_ports >= 15:
                    alerts.append({
                        "rule": "PORT_SCAN",
                        "severity": "HIGH",
                        "timestamp": window_start.isoformat(),
                        "source_ip": ip,
                        "details": f"{unique_ports} unique ports scanned in 5 min from {ip}",
                        "ports_scanned": sorted(window["target"].unique().tolist()),
                    })
                    break

        return alerts

    def _detect_offhours_sensitive_access(self, df: pd.DataFrame) -> list[dict]:
        """Rule: Sensitive file access outside business hours (7 AM - 7 PM)."""
        alerts = []
        file_events = df[df["event_type"] == "file_access"].copy()
        file_events["hour"] = file_events["timestamp"].dt.hour

        offhours = file_events[
            (file_events["hour"] < self.baseline["business_hours_start"]) |
            (file_events["hour"] >= self.baseline["business_hours_end"])
        ]

        for _, row in offhours.iterrows():
            if row["target"] in self.baseline["sensitive_files"]:
                alerts.append({
                    "rule": "OFFHOURS_SENSITIVE_ACCESS",
                    "severity": "CRITICAL",
                    "timestamp": row["timestamp"].isoformat(),
                    "source_ip": row["source_ip"],
                    "details": f"User {row['user']} accessed {row['target']} at {row['timestamp'].strftime('%H:%M')} (outside business hours)",
                    "user": row["user"],
                    "file": row["target"],
                })

        return alerts

    def _detect_unknown_ip(self, df: pd.DataFrame) -> list[dict]:
        """Rule: Activity from IP not in baseline known IPs."""
        alerts = []
        known = set(self.baseline["known_ips"])
        unknown_events = df[
            (~df["source_ip"].isin(known)) &
            (df["source_ip"] != "-")
        ]

        for ip in unknown_events["source_ip"].unique():
            ip_events = unknown_events[unknown_events["source_ip"] == ip]
            alerts.append({
                "rule": "UNKNOWN_IP",
                "severity": "MEDIUM",
                "timestamp": ip_events.iloc[0]["timestamp"].isoformat(),
                "source_ip": ip,
                "details": f"Unknown IP {ip} generated {len(ip_events)} events",
                "event_count": len(ip_events),
            })

        return alerts

    def _detect_privilege_escalation(self, df: pd.DataFrame) -> list[dict]:
        """Rule: Any privilege escalation event (sudo usage)."""
        alerts = []
        priv_events = df[df["event_type"] == "privilege_escalation"]

        for _, row in priv_events.iterrows():
            severity = "CRITICAL" if any(
                cmd in str(row["target"]) for cmd in ["shadow", "exploit", "777"]
            ) else "MEDIUM"

            alerts.append({
                "rule": "PRIVILEGE_ESCALATION",
                "severity": severity,
                "timestamp": row["timestamp"].isoformat(),
                "source_ip": row["source_ip"],
                "details": f"User {row['user']} ran: {row['target']}",
                "user": row["user"],
                "command": row["target"],
            })

        return alerts

    def _detect_event_volume_spike(self, df: pd.DataFrame) -> list[dict]:
        """Statistical: Z-score on hourly event volume."""
        alerts = []
        df_copy = df.copy()
        df_copy["hour_bucket"] = df_copy["timestamp"].dt.floor("h")
        hourly_counts = df_copy.groupby("hour_bucket").size()

        mean = self.baseline["events_hourly_mean"]
        std = self.baseline["events_hourly_std"]

        if std == 0:
            return alerts

        for hour_bucket, count in hourly_counts.items():
            z_score = (count - mean) / std
            if z_score > self.z_threshold:
                alerts.append({
                    "rule": "EVENT_VOLUME_SPIKE",
                    "severity": "MEDIUM",
                    "timestamp": hour_bucket.isoformat(),
                    "source_ip": "-",
                    "details": f"Event volume spike: {count} events (z-score: {z_score:.2f}, threshold: {self.z_threshold})",
                    "event_count": int(count),
                    "z_score": round(z_score, 2),
                })

        return alerts


# ---------------------------------------------------------------------------
# 4. REPORTING
# ---------------------------------------------------------------------------

def generate_report(alerts: list[dict], df: pd.DataFrame, baseline: dict, output_dir: str = "results"):
    """Generate a summary report of detected anomalies."""
    os.makedirs(output_dir, exist_ok=True)

    print("\n" + "=" * 60)
    print("SECURITY LOG ANOMALY DETECTION — REPORT")
    print("=" * 60)

    # Summary
    print(f"\n  Log Period:     {df['timestamp'].min()} to {df['timestamp'].max()}")
    print(f"  Total Events:   {len(df)}")
    print(f"  Total Alerts:   {len(alerts)}")

    # Alerts by severity
    severity_counts = Counter(a["severity"] for a in alerts)
    print(f"\n  Alerts by Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in severity_counts:
            print(f"    {sev:<12} {severity_counts[sev]}")

    # Alerts by rule
    rule_counts = Counter(a["rule"] for a in alerts)
    print(f"\n  Alerts by Rule:")
    for rule, count in rule_counts.most_common():
        print(f"    {rule:<30} {count}")

    # Detail each alert
    print(f"\n  --- ALERT DETAILS ---")
    for i, alert in enumerate(sorted(alerts, key=lambda x: x["timestamp"]), 1):
        print(f"\n  Alert #{i}")
        print(f"    Rule:      {alert['rule']}")
        print(f"    Severity:  {alert['severity']}")
        print(f"    Time:      {alert['timestamp']}")
        print(f"    Source IP:  {alert['source_ip']}")
        print(f"    Details:   {alert['details']}")

    # Baseline summary
    print(f"\n  --- BASELINE ('NORMAL') PROFILE ---")
    print(f"    Auth failures per hour (mean):  {baseline['auth_failure_hourly_mean']:.2f}")
    print(f"    Auth failures per hour (std):   {baseline['auth_failure_hourly_std']:.2f}")
    print(f"    Events per hour (mean):         {baseline['events_hourly_mean']:.2f}")
    print(f"    Events per hour (std):          {baseline['events_hourly_std']:.2f}")
    print(f"    Business hours:                 {baseline['business_hours_start']}:00 - {baseline['business_hours_end']}:00")
    print(f"    Known IPs:                      {', '.join(baseline['known_ips'])}")

    # Detection accuracy (since we have ground truth labels)
    actual_anomalies = set(df[df["is_anomaly"]].index)
    detected_timestamps = set()
    for alert in alerts:
        alert_time = pd.Timestamp(alert["timestamp"])
        # Match alerts to log entries within 10-minute window
        matches = df[
            (df["timestamp"] >= alert_time - timedelta(minutes=10)) &
            (df["timestamp"] <= alert_time + timedelta(minutes=10)) &
            (df["is_anomaly"] == True)
        ]
        detected_timestamps.update(matches.index)

    if actual_anomalies:
        detection_rate = len(detected_timestamps) / len(actual_anomalies) * 100
        print(f"\n  --- DETECTION ACCURACY ---")
        print(f"    Injected anomalies:  {len(actual_anomalies)}")
        print(f"    Detected:            {len(detected_timestamps)}")
        print(f"    Detection rate:      {detection_rate:.1f}%")

    # Save results
    report_data = {
        "log_period": {
            "start": df["timestamp"].min().isoformat(),
            "end": df["timestamp"].max().isoformat(),
        },
        "total_events": len(df),
        "total_alerts": len(alerts),
        "severity_breakdown": dict(severity_counts),
        "rule_breakdown": dict(rule_counts),
        "alerts": alerts,
        "baseline": {k: v for k, v in baseline.items() if k != "known_ips"},
        "detection_rate": round(detection_rate, 1) if actual_anomalies else None,
    }

    with open(os.path.join(output_dir, "anomaly_report.json"), "w") as f:
        json.dump(report_data, f, indent=2, default=str)

    print(f"\n  Full report saved to {output_dir}/anomaly_report.json")


# ---------------------------------------------------------------------------
# 5. MAIN
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("SECURITY LOG ANOMALY DETECTION SYSTEM")
    print("=" * 60)

    # Generate logs
    print("\n[1/4] Generating synthetic system logs (7 days)...")
    df = generate_logs(n_days=7)

    os.makedirs("data", exist_ok=True)
    df.to_csv("data/system_logs.csv", index=False)
    print(f"  Generated {len(df)} log entries")
    print(f"  Injected anomalies: {df['is_anomaly'].sum()}")
    print(f"  Logs saved to data/system_logs.csv")

    # Build baseline
    print("\n[2/4] Building baseline profile from normal activity...")
    # Use only non-anomalous data for baseline (simulating learning from clean history)
    clean_df = df[~df["is_anomaly"]]
    profiler = BaselineProfiler(clean_df)
    baseline = profiler.compute_baseline()

    # Detect anomalies
    print("\n[3/4] Running anomaly detection rules...")
    detector = AnomalyDetector(baseline, z_threshold=2.5)
    alerts = detector.detect(df)

    # Generate report
    print("\n[4/4] Generating report...")
    generate_report(alerts, df, baseline)

    print("\n" + "=" * 60)
    print("Analysis complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
