#!/bin/bash
#
# Security Scanner for CVE-2025-55182 and Similar Compromises
# Detects malicious binaries, persistence mechanisms, and indicators of compromise
#
# Usage: ./security-scan.sh [OPTIONS]
#   -q, --quick     Quick scan (skip slow checks)
#   -v, --verbose   Verbose output
#   -o, --output    Output file for report
#   -h, --help      Show help
#
# Compatibility: Any Linux distro (Debian/Ubuntu/RHEL/CentOS/Arch/Alpine)
# Requirements: bash, find, grep, ps, file (standard on all Linux)
#
# Run as root for complete results, but works without root for basic checks.

set -uo pipefail

# Auto-detect home directories
if [[ -d /home ]]; then
    HOME_DIRS="/home"
else
    HOME_DIRS=""
fi
[[ -d /root ]] && HOME_DIRS="$HOME_DIRS /root"

# Colors (disable if not terminal)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    GREEN='\033[0;32m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' YELLOW='' GREEN='' BLUE='' BOLD='' NC=''
fi

# Globals
VERBOSE=0
QUICK=0
OUTPUT=""
FINDINGS=0
CRITICAL=0
WARNINGS=0

# Known malicious hashes (add more as needed)
MALICIOUS_HASHES=(
    "e76f54b7b98ba3a08f39392e6886a9cb3e97d57b8a076e6b948968d0be392ed8"  # httd cryptominer
)

# Suspicious systemd service names (generic/misleading names used by malware)
SUSPICIOUS_SERVICES=(
    "linux.service"
    "system-update.service"
    "kernel-helper.service"
    "dbus-daemon.service"
    "system-service.service"
    "update-manager.service"
    "cron-update.service"
)

# Suspicious binary names
SUSPICIOUS_BINARIES=(
    "httd" "httpd" "kworkerds" "kdevtmpfsi" "kinsing" "xmrig" "minerd"
    "cryptonight" "ld-linux" "bioset" "carbon" "tsm" "ksoftirqds"
)

# Suspicious paths
SUSPICIOUS_PATHS=(
    "/tmp" "/var/tmp" "/dev/shm" "/boot" "/usr/local/bin"
)

usage() {
    head -17 "$0" | tail -10
    exit 0
}

log() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_verbose() {
    [[ $VERBOSE -eq 1 ]] && echo -e "${BLUE}[*]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[!] WARNING:${NC} $1"
    ((WARNINGS++)) || true
    ((FINDINGS++)) || true
}

critical() {
    echo -e "${RED}${BOLD}[!!!] CRITICAL:${NC} $1"
    ((CRITICAL++)) || true
    ((FINDINGS++)) || true
}

ok() {
    echo -e "${GREEN}[✓]${NC} $1"
}

separator() {
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -q|--quick) QUICK=1; shift ;;
        -v|--verbose) VERBOSE=1; shift ;;
        -o|--output) OUTPUT="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# Redirect output if specified
if [[ -n "$OUTPUT" ]]; then
    exec > >(tee -a "$OUTPUT") 2>&1
fi

echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║          SECURITY SCANNER - Compromise Detection              ║${NC}"
echo -e "${BOLD}║     Detects CVE-2025-55182 and similar attack artifacts       ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Scan started: $(date)"
echo "Hostname: $(hostname)"
echo "User: $(whoami)"
echo "Running as root: $([[ $EUID -eq 0 ]] && echo 'Yes' || echo 'No (some checks limited)')"
echo ""

# ============================================================================
# CHECK 1: Suspicious Binaries by Name
# ============================================================================
separator "CHECK 1: Scanning for Known Malicious Binary Names"

for binary in "${SUSPICIOUS_BINARIES[@]}"; do
    found=$(find / -name "$binary" -type f 2>/dev/null | head -10)
    if [[ -n "$found" ]]; then
        while IFS= read -r file; do
            # Skip legitimate httpd
            if [[ "$file" == "/usr/sbin/httpd" ]] || [[ "$file" == "/usr/sbin/apache2" ]]; then
                continue
            fi
            critical "Suspicious binary found: $file"
            if command -v file &>/dev/null; then
                echo "         Type: $(file -b "$file" 2>/dev/null || echo 'unknown')"
            fi
            if [[ -r "$file" ]]; then
                echo "         Size: $(stat --printf='%s' "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null) bytes"
                echo "         Hash: $(sha256sum "$file" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$file" 2>/dev/null | cut -d' ' -f1)"
            fi
        done <<< "$found"
    fi
done
log "Completed suspicious binary name scan"

# ============================================================================
# CHECK 2: Files with Known Malicious Hashes
# ============================================================================
separator "CHECK 2: Checking for Known Malicious File Hashes"

if [[ $QUICK -eq 0 ]]; then
    for path in "${SUSPICIOUS_PATHS[@]}" "/home" "/root"; do
        [[ -d "$path" ]] || continue
        log_verbose "Scanning $path for known malicious hashes..."
        while IFS= read -r file; do
            [[ -f "$file" && -r "$file" ]] || continue
            hash=$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$file" 2>/dev/null | cut -d' ' -f1)
            for malicious in "${MALICIOUS_HASHES[@]}"; do
                if [[ "$hash" == "$malicious" ]]; then
                    critical "Known malicious file: $file (hash: $hash)"
                fi
            done
        done < <(find "$path" -type f -size +1M -size -50M 2>/dev/null | head -500)
    done
else
    log "Skipped (quick mode)"
fi

# ============================================================================
# CHECK 3: Suspicious Systemd Services
# ============================================================================
separator "CHECK 3: Scanning Systemd Services for Persistence"

SYSTEMD_PATHS=(
    "/lib/systemd/system"
    "/etc/systemd/system"
    "/usr/lib/systemd/system"
    "/run/systemd/system"
)

# Check for known suspicious service names
for service in "${SUSPICIOUS_SERVICES[@]}"; do
    for path in "${SYSTEMD_PATHS[@]}"; do
        if [[ -f "$path/$service" ]]; then
            critical "Suspicious systemd service: $path/$service"
            echo "         Contents:"
            cat "$path/$service" 2>/dev/null | sed 's/^/         /'
        fi
    done
done

# Check for recently created services (last 7 days)
log "Checking for recently created systemd services..."
for path in "${SYSTEMD_PATHS[@]}"; do
    [[ -d "$path" ]] || continue
    while IFS= read -r service; do
        [[ -z "$service" ]] && continue
        # Skip common legitimate services
        basename_svc=$(basename "$service")
        if [[ "$basename_svc" =~ ^(snap\.|docker\.|containerd|netplan|systemd-) ]]; then
            continue
        fi
        warning "Recently modified systemd service: $service"
        if [[ -r "$service" ]]; then
            execstart=$(grep -i "ExecStart" "$service" 2>/dev/null | head -1)
            [[ -n "$execstart" ]] && echo "         $execstart"
        fi
    done < <(find "$path" -maxdepth 1 -type f -name "*.service" -mtime -7 2>/dev/null)
done

# Check for executable systemd files (should never be executable)
for path in "${SYSTEMD_PATHS[@]}"; do
    [[ -d "$path" ]] || continue
    while IFS= read -r service; do
        [[ -z "$service" ]] && continue
        warning "Executable systemd service file (suspicious): $service"
    done < <(find "$path" -maxdepth 1 -type f -name "*.service" -perm /111 2>/dev/null)
done

# ============================================================================
# CHECK 4: Suspicious Files in Sensitive Directories
# ============================================================================
separator "CHECK 4: Checking Sensitive Directories for Anomalies"

# Check /boot for unexpected files
log "Scanning /boot..."
if [[ -d /boot ]]; then
    while IFS= read -r file; do
        if [[ ! "$file" =~ \.(img|cfg|conf|txt|old|bak|map|efi|EFI)$ ]] && \
           [[ ! "$file" =~ ^/boot/(vmlinuz|initrd|grub|efi|System\.map|config-) ]]; then
            if file "$file" 2>/dev/null | grep -qiE "(executable|ELF|script)"; then
                critical "Suspicious executable in /boot: $file"
            fi
        fi
    done < <(find /boot -type f -mtime -30 2>/dev/null)
fi

# Check /tmp, /var/tmp, /dev/shm for executables
for tmpdir in /tmp /var/tmp /dev/shm; do
    [[ -d "$tmpdir" ]] || continue
    log "Scanning $tmpdir..."
    while IFS= read -r file; do
        # Skip known legitimate temp files
        [[ "$file" =~ node-gyp ]] && continue
        [[ "$file" =~ \.npm ]] && continue
        [[ "$file" =~ yarn ]] && continue
        [[ "$file" =~ puppeteer ]] && continue
        filetype=$(file -b "$file" 2>/dev/null || echo "unknown")
        # Only flag ELF binaries (not shell scripts which are common)
        if [[ "$filetype" =~ ELF ]]; then
            warning "ELF binary in temp directory: $file"
            echo "         Type: $filetype"
            echo "         Owner: $(stat -c '%U' "$file" 2>/dev/null || stat -f '%Su' "$file" 2>/dev/null)"
        fi
    done < <(find "$tmpdir" -type f -perm /111 2>/dev/null | head -50)
done

# ============================================================================
# CHECK 5: World-Writable Executables (777)
# ============================================================================
separator "CHECK 5: Checking for World-Writable Executables (777)"

log "Scanning for 777 permission executables..."
while IFS= read -r file; do
    [[ -f "$file" ]] || continue
    # Skip common false positive paths
    [[ "$file" =~ ^(/tmp|/var/tmp|/dev/shm|/proc|/sys) ]] && continue
    [[ "$file" =~ /node_modules/ ]] && continue
    [[ "$file" =~ /\.cache/ ]] && continue
    [[ "$file" =~ /\.npm/ ]] && continue
    [[ "$file" =~ /\.bun/ ]] && continue
    warning "World-writable executable: $file"
    echo "         Owner: $(stat -c '%U:%G' "$file" 2>/dev/null || stat -f '%Su:%Sg' "$file" 2>/dev/null)"
done < <(find / -type f -perm 0777 ! -path "*/node_modules/*" ! -path "*/.cache/*" 2>/dev/null | head -100)

# ============================================================================
# CHECK 6: Recently Created Go/Rust Binaries (Common Malware)
# ============================================================================
separator "CHECK 6: Scanning for Suspicious Statically-Linked Binaries"

if [[ $QUICK -eq 0 ]]; then
    log "Scanning home directories for suspicious binaries..."
    for homedir in /home/* /root; do
        [[ -d "$homedir" ]] || continue
        while IFS= read -r file; do
            filetype=$(file -b "$file" 2>/dev/null || echo "")
            if [[ "$filetype" =~ "statically linked" ]] && [[ "$filetype" =~ "ELF" ]]; then
                # Check if it's a Go binary (common for cryptominers)
                if [[ "$filetype" =~ "Go BuildID" ]] || strings "$file" 2>/dev/null | grep -q "go.buildid"; then
                    warning "Statically-linked Go binary in user directory: $file"
                    echo "         Created: $(stat -c '%y' "$file" 2>/dev/null || stat -f '%Sm' "$file" 2>/dev/null)"
                    echo "         Size: $(stat -c '%s' "$file" 2>/dev/null || stat -f '%z' "$file" 2>/dev/null) bytes"
                fi
            fi
        done < <(find "$homedir" -type f -size +1M -size -50M ! -path "*/node_modules/*" ! -path "*/.cache/*" ! -path "*/.local/*" 2>/dev/null | head -100)
    done
else
    log "Skipped (quick mode)"
fi

# ============================================================================
# CHECK 7: Cron Persistence
# ============================================================================
separator "CHECK 7: Checking Cron for Persistence Mechanisms"

# User crontabs
log "Checking user crontabs..."
for user in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
    crontab=$(crontab -l -u "$user" 2>/dev/null || true)
    if [[ -n "$crontab" ]] && [[ ! "$crontab" =~ "no crontab" ]]; then
        # Check for suspicious entries
        if echo "$crontab" | grep -qiE "(curl|wget|python|perl|bash.*http|/tmp/|/dev/shm|base64)"; then
            warning "Suspicious cron entry for user $user:"
            echo "$crontab" | grep -iE "(curl|wget|python|perl|bash.*http|/tmp/|/dev/shm|base64)" | sed 's/^/         /'
        fi
    fi
done

# System cron directories
for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$crondir" ]] || continue
    while IFS= read -r file; do
        if [[ -f "$file" ]] && [[ ! "$(basename "$file")" =~ ^\.placeholder$ ]]; then
            # Check for suspicious content
            if grep -qiE "(curl|wget|/tmp/|/dev/shm|base64.*decode|python.*-c)" "$file" 2>/dev/null; then
                warning "Suspicious cron file: $file"
                grep -iE "(curl|wget|/tmp/|/dev/shm|base64|python.*-c)" "$file" 2>/dev/null | head -5 | sed 's/^/         /'
            fi
        fi
    done < <(find "$crondir" -type f -mtime -7 2>/dev/null)
done

# ============================================================================
# CHECK 8: Shell Profile Persistence
# ============================================================================
separator "CHECK 8: Checking Shell Profiles for Persistence"

PROFILE_FILES=(
    ".bashrc" ".bash_profile" ".profile" ".zshrc" ".zprofile"
    ".bash_login" ".bash_logout"
)

for homedir in /home/* /root; do
    [[ -d "$homedir" ]] || continue
    user=$(basename "$homedir")
    for profile in "${PROFILE_FILES[@]}"; do
        file="$homedir/$profile"
        [[ -f "$file" ]] || continue
        # Check for suspicious entries
        if grep -qiE "(curl|wget|python.*-c|base64.*decode|/dev/tcp|nc -|ncat|socat)" "$file" 2>/dev/null; then
            warning "Suspicious entry in $file:"
            grep -iE "(curl|wget|python.*-c|base64.*decode|/dev/tcp|nc -|ncat|socat)" "$file" 2>/dev/null | head -3 | sed 's/^/         /'
        fi
    done
done

# ============================================================================
# CHECK 9: Suspicious Network Connections
# ============================================================================
separator "CHECK 9: Checking Network Connections"

log "Checking for suspicious outbound connections..."
if command -v ss &>/dev/null; then
    # Check for connections to known mining pools ports
    suspicious_ports=$(ss -ntp 2>/dev/null | grep -E ":(3333|4444|5555|7777|8888|9999|14433|14444)" | head -10)
    if [[ -n "$suspicious_ports" ]]; then
        critical "Connections to known mining pool ports detected:"
        echo "$suspicious_ports" | sed 's/^/         /'
    fi

    # Check for unusual high-port outbound connections
    outbound=$(ss -ntp state established 2>/dev/null | grep -v "127.0.0.1" | wc -l)
    log_verbose "Active outbound connections: $outbound"
elif command -v netstat &>/dev/null; then
    suspicious_ports=$(netstat -ntp 2>/dev/null | grep -E ":(3333|4444|5555|7777|8888|9999|14433|14444)" | head -10)
    if [[ -n "$suspicious_ports" ]]; then
        critical "Connections to known mining pool ports detected:"
        echo "$suspicious_ports" | sed 's/^/         /'
    fi
fi

# ============================================================================
# CHECK 10: Suspicious Processes
# ============================================================================
separator "CHECK 10: Checking Running Processes"

log "Scanning for suspicious processes..."

# Check for processes with deleted binaries
while IFS= read -r proc; do
    if [[ -n "$proc" ]]; then
        warning "Process running with deleted binary: $proc"
    fi
done < <(ls -la /proc/*/exe 2>/dev/null | grep "(deleted)" | head -10)

# Check for processes with suspicious names
ps aux 2>/dev/null | while read -r line; do
    for binary in "${SUSPICIOUS_BINARIES[@]}"; do
        if echo "$line" | grep -qw "$binary"; then
            critical "Suspicious process running: $line"
        fi
    done
done

# Check for high CPU processes (potential cryptominer)
log "Checking for high CPU usage (cryptominer indicator)..."
high_cpu=$(ps aux --sort=-%cpu 2>/dev/null | awk 'NR>1 && $3>80 {print $0}' | head -5)
if [[ -n "$high_cpu" ]]; then
    warning "High CPU processes detected (>80%):"
    echo "$high_cpu" | sed 's/^/         /'
fi

# ============================================================================
# CHECK 11: SSH Authorized Keys
# ============================================================================
separator "CHECK 11: Checking SSH Authorized Keys"

for homedir in /home/* /root; do
    [[ -d "$homedir" ]] || continue
    authkeys="$homedir/.ssh/authorized_keys"
    [[ -f "$authkeys" ]] || continue

    # Check for recently modified authorized_keys
    if [[ $(find "$authkeys" -mtime -7 2>/dev/null) ]]; then
        warning "Recently modified SSH authorized_keys: $authkeys"
    fi

    # Check for suspicious key comments
    if grep -qiE "(compromised|hack|backdoor|test@|root@kali)" "$authkeys" 2>/dev/null; then
        warning "Suspicious SSH key comment in $authkeys"
    fi

    # Count keys
    keycount=$(grep -c "^ssh-" "$authkeys" 2>/dev/null || echo 0)
    log_verbose "$authkeys has $keycount keys"
done

# ============================================================================
# CHECK 12: Web Application Directories
# ============================================================================
separator "CHECK 12: Checking Web Application Directories"

WEB_DIRS=(
    "/var/www"
    "/home/*/public_html"
    "/home/*/.next"
    "/home/*/node_modules/.bin"
)

for pattern in "${WEB_DIRS[@]}"; do
    for webdir in $pattern; do
        [[ -d "$webdir" ]] || continue
        log_verbose "Scanning $webdir..."

        # Check for PHP shells
        while IFS= read -r file; do
            if grep -qiE "(eval\s*\(\s*base64_decode|system\s*\(\s*\\\$_(GET|POST|REQUEST)|shell_exec|passthru)" "$file" 2>/dev/null; then
                critical "Potential webshell: $file"
            fi
        done < <(find "$webdir" -name "*.php" -type f -mtime -7 2>/dev/null | head -50)

        # Check for suspicious JS files
        while IFS= read -r file; do
            if grep -qiE "(child_process.*exec|require.*child_process|eval\(atob)" "$file" 2>/dev/null; then
                warning "Suspicious JavaScript file: $file"
            fi
        done < <(find "$webdir" -name "*.js" -type f -mtime -7 ! -path "*/node_modules/*" 2>/dev/null | head -50)
    done
done

# ============================================================================
# CHECK 13: File Timestamps Anomalies
# ============================================================================
separator "CHECK 13: Checking for Timestamp Anomalies"

log "Looking for files with future or very old timestamps that were recently accessed..."
# Files with modification times far in past but accessed recently (timestamp manipulation)
while IFS= read -r file; do
    mtime=$(stat -c %Y "$file" 2>/dev/null || stat -f %m "$file" 2>/dev/null)
    atime=$(stat -c %X "$file" 2>/dev/null || stat -f %a "$file" 2>/dev/null)
    btime=$(stat -c %W "$file" 2>/dev/null || echo "0")

    # If birth time is recent but mtime is old, suspicious
    if [[ "$btime" != "0" ]] && [[ "$btime" -gt 0 ]]; then
        now=$(date +%s)
        age_mtime=$((now - mtime))
        age_btime=$((now - btime))

        # Born in last 7 days but mtime says older than 30 days
        if [[ $age_btime -lt 604800 ]] && [[ $age_mtime -gt 2592000 ]]; then
            warning "Timestamp anomaly (possible backdating): $file"
            echo "         Birth: $(date -d @$btime 2>/dev/null || date -r $btime 2>/dev/null)"
            echo "         Modified: $(date -d @$mtime 2>/dev/null || date -r $mtime 2>/dev/null)"
        fi
    fi
done < <(find /home /tmp /var/tmp /root -type f -size +100k 2>/dev/null | head -200)

# ============================================================================
# SUMMARY
# ============================================================================
separator "SCAN COMPLETE - SUMMARY"

echo ""
echo "Scan completed: $(date)"
echo ""

if [[ $CRITICAL -gt 0 ]]; then
    echo -e "${RED}${BOLD}CRITICAL FINDINGS: $CRITICAL${NC}"
fi
if [[ $WARNINGS -gt 0 ]]; then
    echo -e "${YELLOW}WARNINGS: $WARNINGS${NC}"
fi

if [[ $FINDINGS -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}✓ No suspicious findings detected${NC}"
    exit 0
else
    echo ""
    echo -e "${BOLD}RECOMMENDED ACTIONS:${NC}"
    if [[ $CRITICAL -gt 0 ]]; then
        echo "  1. Investigate and remove all CRITICAL findings immediately"
        echo "  2. Check system logs around the time suspicious files were created"
        echo "  3. Rotate all credentials (SSH keys, API keys, passwords)"
        echo "  4. Consider rebuilding the system from a known-good backup"
    fi
    if [[ $WARNINGS -gt 0 ]]; then
        echo "  - Review all WARNING findings for false positives"
        echo "  - Monitor system for unusual activity"
    fi
    echo ""
    exit 1
fi
