#!/usr/bin/env bash
#===============================================================================
#  lib/logger.sh — Logging Engine
#  
#  Provides: log_info, log_warn, log_error, log_success, log_debug,
#            log_step, log_cmd, log_result, tc_log
#  
#  All output goes to both console AND log files simultaneously.
#===============================================================================

# Global verbosity flag (0 or 1)
VERBOSE_MODE=${VERBOSE_MODE:-0}

# Clear any pending characters in stdin to prevent leakage into subsequent prompts or logs
clear_stdin() {
    # Only if it's a terminal and not in headless mode
    if [[ -t 0 ]] && [[ "${HEADLESS_MODE:-0}" == "0" ]]; then
        # More aggressive clearing: use a while loop with a very short timeout
        local discard
        while read -rs -t 0.001 -n 10000 discard 2>/dev/null; do :; done
    fi
}

# Disable terminal echoing of keystrokes
disable_echo() {
    [[ -t 0 ]] && [[ "${HEADLESS_MODE:-0}" == "0" ]] && stty -echo 2>/dev/null
}

# Enable terminal echoing of keystrokes
enable_echo() {
    [[ -t 0 ]] && [[ "${HEADLESS_MODE:-0}" == "0" ]] && stty echo 2>/dev/null
}

#--- Internal: Write to log file ---
_log_to_file() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Master log
    if [[ -n "${SESSION_LOG_DIR:-}" && -d "${SESSION_LOG_DIR:-}" ]]; then
        echo "[${timestamp}] [${level}] ${message}" >> "${SESSION_LOG_DIR}/master.log"
    fi
    
    # Per-TC log
    if [[ -n "${CURRENT_TC:-}" && -n "${SESSION_LOG_DIR:-}" && -d "${SESSION_LOG_DIR:-}" ]]; then
        local tc_log_file="${SESSION_LOG_DIR}/${CURRENT_TC,,}.log"
        echo "[${timestamp}] [${level}] ${message}" >> "$tc_log_file"
    fi
}

#--- Console + File Loggers ---

log_info() {
    local msg="$1"
    echo -e "${C_BLUE}[ℹ]${C_RESET} ${msg}" >&2
    _log_to_file "INFO" "$msg"
}

log_warn() {
    local msg="$1"
    echo -e "${C_YELLOW}[⚠]${C_RESET} ${msg}" >&2
    _log_to_file "WARN" "$msg"
}

log_error() {
    local msg="$1"
    echo -e "${C_RED}[✗]${C_RESET} ${msg}" >&2
    _log_to_file "ERROR" "$msg"
}

log_success() {
    local msg="$1"
    echo -e "${C_GREEN}[✓]${C_RESET} ${msg}" >&2
    _log_to_file "SUCCESS" "$msg"
}

log_debug() {
    local msg="$1"
    # Print to console if verbose mode is enabled
    if [[ "${VERBOSE_MODE:-0}" == "1" ]]; then
        echo -e "${C_GRAY}[DEBUG]${C_RESET} ${msg}" >&2
    fi
    # Always log to file
    _log_to_file "DEBUG" "$msg"
}

log_critical() {
    local msg="$1"
    echo -e "${C_BG_RED}${C_WHITE}[!!!]${C_RESET} ${C_RED}${C_BOLD}${msg}${C_RESET}" >&2
    _log_to_file "CRITICAL" "$msg"
}

#--- Structured Logging for Test Cases ---

# Log a test step header
# Usage: log_step 1 6 "Scanning 10.0.0.0/8 with ${TOOL_PATHS[masscan]}"
log_step() {
    local current="$1"
    local total="$2"
    local description="$3"
    local tc_label="${CURRENT_TC:-SYSTEM}"
    
    # Clear any pending characters in stdin before showing a major step header
    clear_stdin
    
    echo "" >&2
    echo -e "${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}" >&2
    echo -e "${C_CYAN}  [${tc_label}] Step ${current}/${total}: ${description}${C_RESET}" >&2
    echo -e "${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}" >&2
    echo "" >&2
    _log_to_file "STEP" "[${tc_label}] Step ${current}/${total}: ${description}"
}

# Log a command being executed
# Usage: log_cmd "${TOOL_PATHS[nmap]} -sV -p 161 10.0.0.1"
log_cmd() {
    local cmd="$1"
    echo -e "  ${C_GRAY}▶ Running: ${C_DIM}${cmd}${C_RESET}" >&2
    _log_to_file "CMD" "$cmd"

    # Per-TC commands file (evidence)
    if [[ -n "${TC_COMMANDS_FILE:-}" ]]; then
        printf '%s\t%s\n' "$(date -Iseconds)" "$cmd" >>"$TC_COMMANDS_FILE" 2>/dev/null || true
    fi

    # Also echo command into per-TC tool output (so it's never empty even when tools redirect output)
    if [[ -n "${TC_TOOL_OUTPUT_FILE:-}" ]]; then
        {
            echo "============================================================"
            echo "ts: $(date -Iseconds)"
            echo "cmd: $cmd"
        } >>"$TC_TOOL_OUTPUT_FILE" 2>/dev/null || true
    fi
}

# Log a finding/result
# Usage: log_result "FINDING" "WLC admin panel accessible at https://10.0.0.1:443"
# Usage: log_result "SECURE" "No SNMP services detected"
log_result() {
    local type="$1"   # FINDING, SECURE, NEUTRAL
    local msg="$2"

    case "$type" in
        "FINDING"|"VULN"|"CRITICAL")
            echo -e "  ${C_RED}${C_BOLD}  ${ICON_FAIL} FINDING: ${msg}${C_RESET}" >&2
            _log_to_file "FINDING" "$msg"
            ;;
        "SECURE"|"PASS")
            echo -e "  ${C_GREEN}${C_BOLD}  ${ICON_DONE} SECURE: ${msg}${C_RESET}" >&2
            _log_to_file "SECURE" "$msg"
            ;;
        "NEUTRAL"|"INFO")
            echo -e "  ${C_YELLOW}  ${ICON_INFO} INFO: ${msg}${C_RESET}" >&2
            _log_to_file "INFO" "$msg"
            ;;
    esac
}

# Log raw command output (indented, dimmed)
log_output() {
    local output="$1"
    while IFS= read -r line; do
        echo -e "  ${C_DIM}  │ ${line}${C_RESET}" >&2
    done <<< "$output"
    _log_to_file "OUTPUT" "$output"
}

# Separator line
log_separator() {
    echo -e "${C_GRAY}──────────────────────────────────────────────────────────────────${C_RESET}" >&2
}

# TC Start Banner
log_tc_start() {
    local tc_id="$1"
    local tc_name
    tc_name=$(get_tc_field "$tc_id" "name")
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Clear any pending characters in stdin before showing the start banner
    clear_stdin
    
    echo "" >&2
    echo -e "${C_BOLD}${C_CYAN}╔══════════════════════════════════════════════════════════════════╗${C_RESET}" >&2
    echo -e "${C_BOLD}${C_CYAN}║  ${ICON_RUNNING}  RUNNING: ${tc_id} — ${tc_name}${C_RESET}" >&2
    echo -e "${C_BOLD}${C_CYAN}║  Started: ${timestamp}${C_RESET}" >&2
    echo -e "${C_BOLD}${C_CYAN}║  Abort: Ctrl+\\   │   Exit Script: Ctrl+C${C_RESET}" >&2
    echo -e "${C_BOLD}${C_CYAN}╚══════════════════════════════════════════════════════════════════╝${C_RESET}" >&2
    echo "" >&2
    _log_to_file "TC-START" "${tc_id} — ${tc_name}"
}

# TC End Banner
log_tc_end() {
    local tc_id="$1"
    local status="$2"    # done, failed, aborted
    local duration="$3"
    local tc_name
    tc_name=$(get_tc_field "$tc_id" "name")
    
    local status_icon status_color status_text
    case "$status" in
        "done")    status_icon="${C_GREEN}${ICON_DONE}${C_RESET}${status_color}"; status_color="$C_GREEN"; status_text="COMPLETED" ;;
        "failed")  status_icon="${C_RED}${ICON_FAIL}${C_RESET}${status_color}"; status_color="$C_RED";   status_text="FAILED" ;;
        "aborted") status_icon="${C_YELLOW}${ICON_WARN}${C_RESET}${status_color}"; status_color="$C_YELLOW"; status_text="ABORTED" ;;
    esac
    
    echo "" >&2
    echo -e "${C_BOLD}${status_color}╔══════════════════════════════════════════════════════════════════╗${C_RESET}" >&2
    echo -e "${C_BOLD}${status_color}║  ${status_icon}  ${status_text}: ${tc_id} — ${tc_name}${C_RESET}" >&2
    echo -e "${C_BOLD}${status_color}║  Duration: ${duration}${C_RESET}" >&2
    echo -e "${C_BOLD}${status_color}╚══════════════════════════════════════════════════════════════════╝${C_RESET}" >&2
    echo "" >&2
    _log_to_file "TC-END" "${tc_id} — ${status_text} — Duration: ${duration}"

    # Append any generated text evidence directly into the log file for completeness
    if [[ "$status" == "done" && -n "${SESSION_LOG_DIR:-}" && -d "${SESSION_LOG_DIR:-}" && -d "${SESSION_EVIDENCE_DIR:-}" ]]; then
        local tc_log_file="${SESSION_LOG_DIR}/${tc_id,,}.log"
        local lower_tc="${tc_id,,}"
        # Strip dashes if there are no dashes in the evidence prefix, usually it's tc01, tc02
        local prefix="${lower_tc//-/}"
        
        # Check if there are any .txt evidence files matching
        if ls "${SESSION_EVIDENCE_DIR}/${prefix}"*.txt 1> /dev/null 2>&1; then
            echo "" >> "$tc_log_file"
            echo "===============================================================================" >> "$tc_log_file"
            echo "  RAW EVIDENCE OUTPUT" >> "$tc_log_file"
            echo "===============================================================================" >> "$tc_log_file"
            
            for ev_file in "${SESSION_EVIDENCE_DIR}/${prefix}"*.txt; do
                echo "" >> "$tc_log_file"
                echo "--- EVIDENCE: $(basename "$ev_file") ---" >> "$tc_log_file"
                # Strip ANSI colors when appending raw evidence logs just in case
                sed -E 's/\x1B\[[0-9;]*[a-zA-Z]//g' "$ev_file" 2>/dev/null >> "$tc_log_file" || cat "$ev_file" >> "$tc_log_file"
            done
        fi
    fi
}

#--- Helper: Extract field from TC_REGISTRY ---
# Fields: name(1), phase(2), deps(3), critical(4), description(5)
get_tc_field() {
    local tc_id="$1"
    local field="$2"
    local entry="${TC_REGISTRY[$tc_id]:-}"
    
    if [[ -z "$entry" ]]; then
        echo "UNKNOWN"
        return 1
    fi
    
    case "$field" in
        "name")        echo "$entry" | cut -d'|' -f1 ;;
        "phase"|"category") echo "$entry" | cut -d'|' -f2 ;;
        "deps")        echo "$entry" | cut -d'|' -f3 ;;
        "critical")    echo "$entry" | cut -d'|' -f4 ;;
        "description") echo "$entry" | cut -d'|' -f5 ;;
        *)             echo "UNKNOWN_FIELD"; return 1 ;;
    esac
}

#--- Validate PCAP file after capture ---
# Usage: validate_pcap "/path/to/file.pcap" "Description of capture"
# Returns: 0 if pcap has packets, 1 if empty/missing
# Side effects: logs result, writes .info companion file
validate_pcap() {
    local pcap_file="$1"
    local description="${2:-Packet capture}"
    local info_file="${pcap_file%.pcap}.pcap.info"

    if [[ ! -f "$pcap_file" ]]; then
        log_warn "PCAP not created: ${description}"
        log_warn "  Reason: Capture file was not written — ${TOOL_PATHS[tcpdump]} may have failed to start"
        log_warn "  File: $(basename "$pcap_file")"
        {
            echo "PCAP STATUS: NOT CREATED"
            echo "Description: ${description}"
            echo "File: $(basename "$pcap_file")"
            echo "Reason: Capture file was not written. Possible causes:"
            echo "  - ${TOOL_PATHS[tcpdump]} failed to start (permission denied, interface busy)"
            echo "  - Capture process was killed before writing"
            echo "  - Interface was not in the correct mode"
            echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
        } > "$info_file"
        return 1
    fi

    local file_size
    file_size=$(stat -c%s "$pcap_file" 2>/dev/null || echo 0)

    if [[ $file_size -le 24 ]]; then
        # 24 bytes = just the pcap header, no actual packets
        log_warn "PCAP empty (no packets): ${description}"
        log_warn "  Reason: No matching traffic was observed during the capture window"
        log_warn "  File: $(basename "$pcap_file") (${file_size} bytes — header only)"
        {
            echo "PCAP STATUS: EMPTY (no packets captured)"
            echo "Description: ${description}"
            echo "File: $(basename "$pcap_file")"
            echo "Size: ${file_size} bytes (pcap header only)"
            echo "Reason: No matching network traffic was observed. Possible causes:"
            echo "  - No relevant traffic on the network during capture"
            echo "  - BPF filter was too restrictive"
            echo "  - Interface was not receiving traffic (wrong VLAN, disconnected, etc.)"
            echo "  - Multicast/broadcast filtering by the AP blocked the traffic"
            echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
        } > "$info_file"
        return 1
    fi

    # Count actual packets
    local pkt_count=0
    pkt_count=$(${TOOL_PATHS[tcpdump]} -r "$pcap_file" -c 1 2>/dev/null | wc -l)
    pkt_count=${pkt_count:-0}

    if [[ $pkt_count -eq 0 ]]; then
        log_warn "PCAP unreadable or corrupt: ${description}"
        log_warn "  File: $(basename "$pcap_file") (${file_size} bytes)"
        {
            echo "PCAP STATUS: UNREADABLE/CORRUPT"
            echo "Description: ${description}"
            echo "File: $(basename "$pcap_file")"
            echo "Size: ${file_size} bytes"
            echo "Reason: File exists but ${TOOL_PATHS[tcpdump]} could not read any packets."
            echo "  Possible file corruption or format mismatch."
            echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
        } > "$info_file"
        return 1
    fi

    log_success "PCAP captured: ${description} ($(basename "$pcap_file"), ${file_size} bytes)"
    {
        echo "PCAP STATUS: OK"
        echo "Description: ${description}"
        echo "File: $(basename "$pcap_file")"
        echo "Size: ${file_size} bytes"
        echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
    } > "$info_file"
    return 0
}