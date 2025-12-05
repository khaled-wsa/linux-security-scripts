#!/bin/bash
#
# Forensic Analysis Script - Correlate Suspicious Requests with File Changes
# Finds successful exploitation attempts by matching attack patterns with file creation times
#
# Usage: ./forensic-analysis.sh [OPTIONS]
#   -d, --days N      Analyze last N days of logs (default: 7)
#   -l, --logs PATH   Custom log directory (auto-detects nginx/apache)
#   -o, --output FILE Output results to file
#   -v, --verbose     Verbose output
#   -h, --help        Show help
#
# Compatibility: Any Linux distro (Debian/Ubuntu/RHEL/CentOS/Arch/Alpine)
# Requirements: bash, find, grep, zgrep (standard on all Linux)
#

# Colors
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

# Defaults
DAYS=7
OUTPUT=""
VERBOSE=0
TEMP_DIR=$(mktemp -d)
FINDINGS=0
CUSTOM_LOGS=""

# Auto-detect web server log locations (works on any Linux distro)
detect_log_paths() {
    local logs=""

    # Nginx locations (Debian/Ubuntu, RHEL/CentOS, Arch, Alpine)
    for path in /var/log/nginx /var/log/httpd /var/log/apache2 /var/log/apache; do
        if [[ -d "$path" ]]; then
            logs="$logs $path/access.log* $path/*access*.log*"
        fi
    done

    # Fallback: search common locations
    if [[ -z "$logs" ]]; then
        logs=$(find /var/log -name "*access*log*" -type f 2>/dev/null | head -5 | tr '\n' ' ')
    fi

    echo "$logs"
}

# Auto-detect home directories
detect_home_dirs() {
    local dirs=""
    [[ -d /home ]] && dirs="/home"
    [[ -d /root ]] && dirs="$dirs /root"
    echo "$dirs"
}

# Suspicious user agents (automated attack tools)
SUSPICIOUS_UA_PATTERNS=(
    "python-requests"
    "python-urllib"
    "curl/"
    "wget/"
    "Go-http-client"
    "Java/"
    "libwww-perl"
    "Scrapy"
    "sqlmap"
    "nikto"
    "masscan"
    "zgrab"
    "httpx"
    "nuclei"
    "gobuster"
    "dirbuster"
)

# Suspicious request patterns
SUSPICIOUS_REQUEST_PATTERNS=(
    "POST / HTTP"
    "POST /api HTTP"
    "_rsc=.*base64"
    "__nextaction"
    "\.\./"
    "/etc/passwd"
    "/proc/self"
    "cmd="
    "exec="
    "eval("
    "base64"
    "shell"
    "<script"
    "UNION.*SELECT"
)

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

usage() {
    head -11 "$0" | tail -8
    exit 0
}

log() {
    echo -e "${BLUE}[*]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    ((FINDINGS++)) || true
}

critical() {
    echo -e "${RED}${BOLD}[!!!]${NC} $1"
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
        -d|--days) DAYS="$2"; shift 2 ;;
        -l|--logs) CUSTOM_LOGS="$2"; shift 2 ;;
        -o|--output) OUTPUT="$2"; shift 2 ;;
        -v|--verbose) VERBOSE=1; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# Set log paths (custom or auto-detect)
if [[ -n "$CUSTOM_LOGS" ]]; then
    WEB_LOGS="$CUSTOM_LOGS"
else
    WEB_LOGS=$(detect_log_paths)
fi

if [[ -z "$WEB_LOGS" ]]; then
    echo -e "${RED}Error: No web server logs found.${NC}"
    echo "Specify log path with: $0 --logs /path/to/access.log"
    exit 1
fi

# Redirect output if specified
if [[ -n "$OUTPUT" ]]; then
    exec > >(tee -a "$OUTPUT") 2>&1
fi

echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║     FORENSIC ANALYSIS - Attack Correlation Scanner           ║${NC}"
echo -e "${BOLD}║  Correlates suspicious requests with filesystem changes      ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Analysis started: $(date)"
echo "Analyzing last $DAYS days of logs"
echo "Hostname: $(hostname)"
echo ""

# ============================================================================
# PHASE 1: Extract Suspicious Requests from Logs
# ============================================================================
separator "PHASE 1: Extracting Suspicious HTTP Requests"

SUSPICIOUS_REQUESTS="$TEMP_DIR/suspicious_requests.txt"

log "Scanning web server logs for suspicious patterns..."
log "Log paths: $WEB_LOGS"

# Build grep pattern for user agents
UA_PATTERN=$(printf "|%s" "${SUSPICIOUS_UA_PATTERNS[@]}")
UA_PATTERN="${UA_PATTERN:1}"  # Remove leading |

# Extract suspicious requests
{
    # Automated tools / suspicious user agents
    sudo zgrep -hiE "($UA_PATTERN)" $WEB_LOGS 2>/dev/null || true

    # POST requests to root or suspicious endpoints
    sudo zgrep -hiE "\"POST / HTTP|\"POST /api HTTP" $WEB_LOGS 2>/dev/null || true

    # Requests with suspicious patterns
    sudo zgrep -hiE "(cmd=|exec=|eval\(|base64|\.\.\/|\/etc\/passwd)" $WEB_LOGS 2>/dev/null || true

} | sort -u > "$SUSPICIOUS_REQUESTS"

TOTAL_SUSPICIOUS=$(wc -l < "$SUSPICIOUS_REQUESTS")
log "Found $TOTAL_SUSPICIOUS suspicious requests"

# ============================================================================
# PHASE 2: Extract Unique Attacker IPs and Timestamps
# ============================================================================
separator "PHASE 2: Analyzing Attacker IPs and Timestamps"

ATTACKER_DATA="$TEMP_DIR/attacker_data.txt"

# Parse log entries: extract IP, timestamp, request, user-agent
log "Parsing attacker information..."

while IFS= read -r line; do
    # Extract IP (first field)
    ip=$(echo "$line" | awk '{print $1}')

    # Extract timestamp [05/Dec/2025:10:17:59 +0000]
    timestamp=$(echo "$line" | grep -oE '\[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}' | tr -d '[')

    # Extract user agent (last quoted field)
    ua=$(echo "$line" | grep -oE '"[^"]*"$' | tr -d '"')

    # Extract request method and path
    request=$(echo "$line" | grep -oE '"(GET|POST|PUT|DELETE|HEAD|OPTIONS) [^"]*"' | head -1)

    if [[ -n "$ip" && -n "$timestamp" ]]; then
        echo "$ip|$timestamp|$request|$ua"
    fi
done < "$SUSPICIOUS_REQUESTS" | sort -u > "$ATTACKER_DATA"

# Get unique IPs
UNIQUE_IPS="$TEMP_DIR/unique_ips.txt"
cut -d'|' -f1 "$ATTACKER_DATA" | sort | uniq -c | sort -rn > "$UNIQUE_IPS"

echo ""
echo "Top Suspicious IPs by Request Count:"
echo "────────────────────────────────────"
head -20 "$UNIQUE_IPS" | while read count ip; do
    # Try to get country info if geoiplookup is available
    country=""
    if command -v geoiplookup &>/dev/null; then
        country=$(geoiplookup "$ip" 2>/dev/null | head -1 | cut -d: -f2 | xargs)
    fi
    printf "  %-15s  %5d requests  %s\n" "$ip" "$count" "$country"
done
echo ""

# ============================================================================
# PHASE 3: Find Files Created During Attack Windows
# ============================================================================
separator "PHASE 3: Correlating Attacks with File System Changes"

log "Searching for files created in the last $DAYS days..."

# Find recently created files (excluding common paths)
RECENT_FILES="$TEMP_DIR/recent_files.txt"
find /home /tmp /var/tmp /root /boot /usr/local 2>/dev/null \
    -type f -mtime -"$DAYS" \
    ! -path "*/node_modules/*" \
    ! -path "*/.next/*" \
    ! -path "*/.cache/*" \
    ! -path "*/.npm/*" \
    ! -path "*/.bun/*" \
    ! -path "*/.pm2/*" \
    ! -path "*/.git/*" \
    ! -path "*/logs/*" \
    ! -path "*claude*" \
    ! -name "*.log" \
    ! -name "*.md" \
    ! -name "*.txt" \
    ! -name "*.json" \
    ! -name "*.ts" \
    ! -name "*.tsx" \
    ! -name "*.js" \
    ! -name "*.css" \
    -printf "%T@ %Tc %p\n" 2>/dev/null | sort -rn > "$RECENT_FILES"

log "Found $(wc -l < "$RECENT_FILES") recently modified files"

# ============================================================================
# PHASE 4: Correlate Timestamps - Find Successful Exploits
# ============================================================================
separator "PHASE 4: Finding Successful Exploitation (File Creation Matches)"

CORRELATIONS="$TEMP_DIR/correlations.txt"
> "$CORRELATIONS"

log "Cross-referencing attack times with file creation times..."
echo ""

# For each suspicious request, check if files were created within 60 seconds
while IFS='|' read -r ip timestamp request ua; do
    [[ -z "$timestamp" ]] && continue

    # Convert log timestamp to epoch
    # Format: 05/Dec/2025:10:17:59
    attack_epoch=$(date -d "$(echo "$timestamp" | sed 's/:/ /' | sed 's/\// /g')" +%s 2>/dev/null)
    [[ -z "$attack_epoch" ]] && continue

    # Search for files created within 60 seconds of attack
    while read -r file_epoch file_date filepath; do
        [[ -z "$file_epoch" ]] && continue
        file_epoch_int=${file_epoch%.*}

        # Check if file was created within 60 seconds of attack
        diff=$((file_epoch_int - attack_epoch))
        if [[ $diff -ge -10 && $diff -le 60 ]]; then
            # Potential correlation found!
            echo "$ip|$timestamp|$filepath|$diff|$ua" >> "$CORRELATIONS"
        fi
    done < "$RECENT_FILES"

done < "$ATTACKER_DATA"

# Remove duplicates and display correlations
if [[ -s "$CORRELATIONS" ]]; then
    sort -u "$CORRELATIONS" | while IFS='|' read -r ip timestamp filepath timediff ua; do
        critical "POTENTIAL SUCCESSFUL EXPLOIT DETECTED"
        echo ""
        echo "  Attacker IP:    $ip"
        echo "  Attack Time:    $timestamp"
        echo "  User Agent:     $ua"
        echo "  File Created:   $filepath"
        echo "  Time Delta:     ${timediff}s after request"

        # Get file details
        if [[ -f "$filepath" ]]; then
            echo "  File Type:      $(file -b "$filepath" 2>/dev/null | head -c 60)"
            echo "  File Size:      $(stat -c %s "$filepath" 2>/dev/null) bytes"
            echo "  File Hash:      $(sha256sum "$filepath" 2>/dev/null | cut -d' ' -f1)"
        else
            echo "  File Status:    DELETED (was detected but no longer exists)"
        fi
        echo ""
        echo "  ─────────────────────────────────────────────────────────"
        echo ""
    done
else
    ok "No direct timestamp correlations found between attacks and file creation"
fi

# ============================================================================
# PHASE 5: Analyze Attack Patterns by User Agent
# ============================================================================
separator "PHASE 5: Attack Pattern Analysis"

echo "Attacks by User Agent:"
echo "──────────────────────"
cut -d'|' -f4 "$ATTACKER_DATA" | sort | uniq -c | sort -rn | head -15 | while read count ua; do
    printf "  %5d  %s\n" "$count" "${ua:0:70}"
done
echo ""

echo "Attacks by Hour (last $DAYS days):"
echo "───────────────────────────────────"
cut -d'|' -f2 "$ATTACKER_DATA" | cut -d: -f2 | sort | uniq -c | sort -k2n | while read count hour; do
    bar=$(printf '%*s' "$((count/5))" '' | tr ' ' '█')
    # Use %d instead of %02d to avoid octal interpretation
    printf "  %s:00  %4d  %s\n" "$hour" "$count" "$bar"
done
echo ""

# ============================================================================
# PHASE 6: Check for Known Malicious Indicators
# ============================================================================
separator "PHASE 6: Checking Known Malicious Indicators"

# Check for specific attacker IP from our incident
KNOWN_ATTACKER="192.238.129.36"
log "Checking for known attacker IP: $KNOWN_ATTACKER"

KNOWN_ATTACKS=$(grep "$KNOWN_ATTACKER" "$SUSPICIOUS_REQUESTS" 2>/dev/null | wc -l)
if [[ $KNOWN_ATTACKS -gt 0 ]]; then
    warning "Found $KNOWN_ATTACKS requests from known attacker $KNOWN_ATTACKER:"
    grep "$KNOWN_ATTACKER" "$SUSPICIOUS_REQUESTS" | head -10 | while read line; do
        echo "    $line" | cut -c1-120
    done
fi

# Check for python-requests specifically (common exploit tool)
PYTHON_ATTACKS=$(grep -c "python-requests" "$SUSPICIOUS_REQUESTS" 2>/dev/null || echo 0)
if [[ $PYTHON_ATTACKS -gt 0 ]]; then
    echo ""
    log "Found $PYTHON_ATTACKS requests from python-requests (automated tool)"
    echo ""
    echo "  Python-requests attack sources:"
    grep "python-requests" "$SUSPICIOUS_REQUESTS" | awk '{print $1}' | sort | uniq -c | sort -rn | head -10 | while read count ip; do
        country=""
        if command -v geoiplookup &>/dev/null; then
            country=$(geoiplookup "$ip" 2>/dev/null | head -1 | cut -d: -f2 | xargs)
        fi
        printf "    %-15s  %5d requests  %s\n" "$ip" "$count" "$country"
    done
fi

# ============================================================================
# PHASE 7: Check for Suspicious POST Requests to Root
# ============================================================================
separator "PHASE 7: Analyzing POST / Requests (RCE Attack Vector)"

ROOT_POSTS="$TEMP_DIR/root_posts.txt"
sudo zgrep -h '"POST / HTTP' $WEB_LOGS 2>/dev/null | grep -v "200\|301\|302" > "$ROOT_POSTS"

ROOT_POST_COUNT=$(wc -l < "$ROOT_POSTS")
if [[ $ROOT_POST_COUNT -gt 0 ]]; then
    warning "Found $ROOT_POST_COUNT suspicious POST / requests (non-redirect responses)"
    echo ""
    echo "  Unique IPs making POST / requests:"
    awk '{print $1}' "$ROOT_POSTS" | sort | uniq -c | sort -rn | head -10 | while read count ip; do
        status=$(grep "^$ip" "$ROOT_POSTS" | head -1 | awk '{print $9}')
        printf "    %-15s  %5d requests  HTTP %s\n" "$ip" "$count" "$status"
    done
else
    ok "No suspicious POST / requests found"
fi

# ============================================================================
# SUMMARY
# ============================================================================
separator "ANALYSIS COMPLETE - SUMMARY"

echo ""
echo "Analysis completed: $(date)"
echo ""
echo "Statistics:"
echo "───────────"
echo "  Total suspicious requests analyzed: $TOTAL_SUSPICIOUS"
echo "  Unique attacker IPs:               $(cut -d'|' -f1 "$ATTACKER_DATA" | sort -u | wc -l)"
echo "  Files checked for correlation:     $(wc -l < "$RECENT_FILES")"
echo "  Potential successful exploits:     $(wc -l < "$CORRELATIONS" 2>/dev/null || echo 0)"
echo ""

if [[ $FINDINGS -gt 0 ]]; then
    echo -e "${RED}${BOLD}FINDINGS: $FINDINGS issues require investigation${NC}"
    echo ""
    echo "Recommended Actions:"
    echo "  1. Investigate all CRITICAL findings immediately"
    echo "  2. Block suspicious IPs at firewall level"
    echo "  3. Check identified files for malware"
    echo "  4. Review system for persistence mechanisms"
    echo "  5. Rotate credentials if exploitation confirmed"
else
    echo -e "${GREEN}${BOLD}No definitive exploitation evidence found${NC}"
    echo ""
    echo "Note: This does not guarantee system is clean."
    echo "Run ./security-scan.sh for additional checks."
fi

echo ""

# Export attacker IPs for blocking
BLOCK_LIST="$TEMP_DIR/ips_to_block.txt"
cut -d'|' -f1 "$ATTACKER_DATA" | sort -u > "$BLOCK_LIST"
echo "Suspicious IPs exported to: $BLOCK_LIST"
echo "To block these IPs:"
echo "  while read ip; do sudo iptables -A INPUT -s \$ip -j DROP; done < $BLOCK_LIST"
echo ""

exit $([[ $FINDINGS -gt 0 ]] && echo 1 || echo 0)
