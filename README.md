# linux-security-scripts

Detect malware, backdoors, and exploitation attempts on Linux servers.

## Scripts

| Script | Purpose |
|--------|---------|
| `security-scan.sh` | Find malware, suspicious processes, persistence mechanisms |
| `forensic-analysis.sh` | Find successful attacks by matching HTTP requests with file creation |

## Install

```bash
git clone https://github.com/YOUR_USERNAME/linux-security-scripts.git
cd linux-security-scripts
chmod +x *.sh
```

## Usage

```bash
# Quick security scan
./security-scan.sh --quick

# Full security scan
./security-scan.sh

# Analyze last 7 days of web logs
sudo ./forensic-analysis.sh

# Analyze last 30 days
sudo ./forensic-analysis.sh --days 30

# Custom log path
sudo ./forensic-analysis.sh --logs /var/log/httpd/access_log

# Save report
./security-scan.sh -o report.txt
```

## What They Detect

**security-scan.sh:**
- Known malware (cryptominers, backdoors)
- Suspicious binaries in /tmp, /boot, home dirs
- Malicious systemd services
- World-writable executables (777)
- Processes running from deleted files
- Suspicious cron jobs
- Shell profile backdoors
- Mining pool connections

**forensic-analysis.sh:**
- Attack tools (python-requests, curl, zgrab, masscan)
- POST requests to root (RCE attacks)
- Files created at same time as suspicious requests
- Top attacker IPs

## Requirements

- Linux (any distro)
- bash
- Standard tools: find, grep, ps, file
- Root recommended for full scan

## Safe to Run

Both scripts are **read-only**. They don't delete, modify, or change anything.

## License

MIT
