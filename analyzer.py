import json
from datetime import datetime

# -----------------------------
# Placeholder AI summarizer
# -----------------------------
def ai_summary(report):
    """
    Simulates an AI-generated summary.
    In a real workflow, this could call an LLM API.
    """
    summary = []

    if report["failed_logins"] > 3:
        summary.append("Multiple failed login attempts detected.")

    if report["suspicious_ips"]:
        summary.append(f"Activity from unfamiliar IPs: {report['suspicious_ips']}.")

    if report["rapid_attempts"] > 0:
        summary.append("Rapid login retries suggest possible brute-force behavior.")

    if not summary:
        return "No anomalies detected. Directory activity appears normal."

    return " ".join(summary)


# -----------------------------
# Log Analyzer
# -----------------------------
def analyze_logs(log_file):
    failed_logins = 0
    suspicious_ips = set()
    rapid_attempts = 0
    timestamps = []

    with open(log_file, "r") as f:
        for line in f:
            parts = line.strip().split(" | ")
            if len(parts) < 3:
                continue

            timestamp, event_type, details = parts
            timestamps.append(timestamp)

            if "FAILED_LOGIN" in event_type:
                failed_logins += 1

            if "IP=" in details:
                ip = details.split("IP=")[1]
                if ip.startswith("192.168.1.44"):
                    suspicious_ips.add(ip)

            if "RETRY" in event_type:
                rapid_attempts += 1

    report = {
        "total_entries": len(timestamps),
        "failed_logins": failed_logins,
        "suspicious_ips": list(suspicious_ips),
        "rapid_attempts": rapid_attempts
    }

    return report


# -----------------------------
# Main Execution
# -----------------------------
if __name__ == "__main__":
    report = analyze_logs("logs/sample_logs.txt")
    print(json.dumps(report, indent=4))

    print("\nAI Summary:")
    print(ai_summary(report))
