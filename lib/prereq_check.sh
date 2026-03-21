#!/usr/bin/env bash
#===============================================================================
#  lib/prereq_check.sh — Tool Installation Verification
#  
#  Checks all required tools and reports what's missing.
#  Categorizes by test case so users know which TCs will work.
#
#  NOTE: We only run "apt update" and "apt install" — never "apt upgrade",
#  to avoid a full system upgrade.
#===============================================================================

#--- Tool-to-Module mapping ---
declare -gA TOOL_TC_MAP
TOOL_TC_MAP=(
    ["airmon-ng"]="A1,A2,A3"
    ["airodump-ng"]="A1,A2,A3,D2"
    ["aireplay-ng"]="A3,D1,D2,E3"
    ["nmap"]="B1,B2,B5,B9,C2,C3,C4,C5"
    ["masscan"]="C2"
    ["tcpdump"]="B3,B4,B7,B8,A4"
    ["tshark"]="B3,B4,B7,B8,D4,E1,E2,A4"
    ["nbtscan"]="C2"
    ["onesixtyone"]="B5"
    ["snmpwalk"]="B5,B9"
    ["yersinia"]="G1"
    ["fping"]="B1,C2"
    ["arping"]="B1"
    ["avahi-browse"]="B4"
    ["dig"]="C1,F3"
    ["nslookup"]="C1"
    ["ip"]="B1,B7,C3,G1"
    ["jq"]="ALL"
    ["curl"]="B2,F3,F4"
    ["wget"]="B2"
    ["mdk4"]="E3,E4,F2,H1"
    ["wash"]="D3"
    ["reaver"]="D3"
    ["bully"]="D3"
    ["hostapd"]="F1"
    ["dnsmasq"]="F1"
    ["macchanger"]="F4"
    ["aircrack-ng"]="D1,D2"
    ["hcxdumptool"]="D1"
    ["hcxpcapngtool"]="D1"
    ["eaphammer"]="D5"
    ["hostapd-mana"]="D5,F2"
    ["airsnitch"]="B10"
    ["searchsploit"]="B9"
    ["python3"]="F1"
    ["iptables"]="F1"
    ["iw"]="ALL"
    ["bettercap"]="G2"
    ["arpspoof"]="G2"
    ["responder"]="G3"
    ["krack-test"]="E1"
    ["fragattack"]="E2"
    ["dragonslayer"]="D4"
    ["dragondrain"]="D4"
    ["packetforge-ng"]="D2"
)

#--- Quick check at startup (non-blocking) ---
quick_prereq_check() {
    local missing_critical=0
    local critical_tools=("nmap" "jq" "ip" "tcpdump" "dig" "iw")
    
    # Disable strict mode temporarily to handle associative array lookups safely
    set +u
    
    # Check every tool in the registry and store its path
    local tool
    for tool in "${!TOOL_TC_MAP[@]}"; do
        if command -v "$tool" &>/dev/null; then
            TOOL_PATHS["$tool"]=$(command -v "$tool")
        else
            # Default to name if not found
            TOOL_PATHS["$tool"]="$tool"
        fi
    done
    
    # Validate critical ones for reporting
    for tool in "${critical_tools[@]}"; do
        local path="${TOOL_PATHS[$tool]}"
        
        # If path is empty or not an executable, check if it's in PATH
        if [[ ! -x "$path" ]] && ! command -v "$tool" &>/dev/null; then
            ((missing_critical++))
        fi
    done
    
    set -u
    
    if [[ $missing_critical -gt 0 ]]; then
        log_warn "${missing_critical} critical tool(s) missing. Run [P] from menu for full check."
    else
        log_success "Core environment verified."
    fi
}

#--- Full prerequisite check ---
full_prereq_check() {
    echo ""
    echo -e "${C_CYAN}╔══════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_CYAN}║  PREREQUISITE CHECK — Verifying All Required Tools              ║${C_RESET}"
    echo -e "${C_CYAN}╚══════════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
    
    local total=0
    local found=0
    local missing_tools=()
    local affected_tcs=()
    
    # Table header
    printf "  ${C_BOLD}%-20s %-10s %-40s${C_RESET}\n" "TOOL" "STATUS" "REQUIRED FOR"
    echo -e "  ${C_GRAY}$(printf '─%.0s' {1..70})${C_RESET}"
    
    # Check each tool
    for tool in $(echo "${!TOOL_TC_MAP[@]}" | tr ' ' '\n' | sort); do
        ((total++))
        local tcs="${TOOL_TC_MAP[$tool]}"
        
        if command -v "$tool" &>/dev/null; then
            TOOL_PATHS["$tool"]=$(command -v "$tool")
            local version
            version=$(_get_tool_version "$tool")
            printf "  ${C_GREEN}%-20s %-10s${C_RESET} %-40s\n" "$tool" "✓ Found" "$tcs"
            ((found++))
        else
            TOOL_PATHS["$tool"]=""
            printf "  ${C_RED}%-20s %-10s${C_RESET} %-40s\n" "$tool" "✗ MISSING" "$tcs"
            missing_tools+=("$tool")
            
            # Track affected TCs
            IFS=',' read -ra tc_list <<< "$tcs"
            for tc in "${tc_list[@]}"; do
                tc=$(echo "$tc" | xargs)
                if [[ ! " ${affected_tcs[*]} " =~ " ${tc} " ]]; then
                    affected_tcs+=("$tc")
                fi
            done
        fi
    done
    
    echo -e "  ${C_GRAY}$(printf '─%.0s' {1..70})${C_RESET}"
    echo ""
    echo -e "  ${C_BOLD}Total: ${found}/${total} tools found${C_RESET}"
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo ""
        echo -e "  ${C_RED}${C_BOLD}Missing tools (${#missing_tools[@]}):${C_RESET}"
        for tool in "${missing_tools[@]}"; do
            local install_cmd
            install_cmd=$(_get_install_command "$tool")
            echo -e "    ${C_RED}• ${tool}${C_RESET} — Install: ${C_DIM}${install_cmd}${C_RESET}"
        done
        
        echo ""
        echo -e "  ${C_YELLOW}${C_BOLD}Affected test cases:${C_RESET}"
        for tc in "${affected_tcs[@]}"; do
            if [[ "$tc" != "ALL" ]]; then
                local tc_name
                tc_name=$(get_tc_field "$tc" "name" 2>/dev/null || echo "Unknown")
                echo -e "    ${C_YELLOW}• ${tc} — ${tc_name}${C_RESET}"
            fi
        done
        
        echo ""
        echo -e "  ${C_BOLD}Install all missing tools at once (batch apt + custom installs)?${C_RESET}"
        read -rep "  [Y/n]: " prompt
        if [[ "$prompt" =~ ^[Yy]$ ]] || [[ -z "$prompt" ]]; then
            local os
            os=$(_detect_os)
            case "$os" in
                kali|parrot|ubuntu|debian)
                    # Collect unique apt packages for missing tools
                    local -A apt_packages=()
                    local -a custom_tools=()
                    for tool in "${missing_tools[@]}"; do
                        local pkg
                        pkg=$(_get_apt_package "$tool")
                        if [[ -n "$pkg" ]]; then
                            apt_packages["$pkg"]=1
                        else
                            custom_tools+=("$tool")
                        fi
                    done
                    # One apt update and one apt install — no apt upgrade (no full system upgrade)
                    if [[ ${#apt_packages[@]} -gt 0 ]]; then
                        echo -e "  ${C_CYAN}Updating package lists (apt update only, no upgrade)...${C_RESET}"
                        apt update -qq
                        local pkgs_to_install=()
                        for pkg in "${!apt_packages[@]}"; do
                            pkgs_to_install+=("$pkg")
                        done
                        echo -e "  ${C_CYAN}Installing ${#pkgs_to_install[@]} package(s) at once: ${pkgs_to_install[*]}${C_RESET}"
                        apt install -y "${pkgs_to_install[@]}" || echo -e "  ${C_RED}Some apt packages failed. Check output above.${C_RESET}"
                    fi
                    # Custom installs (e.g. ${TOOL_PATHS[eaphammer]}, ${TOOL_PATHS[airsnitch]}) one by one
                    for tool in "${custom_tools[@]}"; do
                        local install_cmd
                        install_cmd=$(_get_install_command "$tool")
                        echo -e "  ${C_CYAN}Installing ${tool} (custom): ${install_cmd}${C_RESET}"
                        eval "$install_cmd" || echo -e "  ${C_RED}Failed to install ${tool}${C_RESET}"
                    done
                    echo -e "  ${C_GREEN}Install-all finished. Re-run [P] to verify.${C_RESET}"
                    ;;
                *)
                    echo -e "  ${C_YELLOW}Auto-install is only supported on Debian-based systems (kali/parrot/ubuntu/debian).${C_RESET}"
                    echo -e "  ${C_YELLOW}Please install the above tools manually using your system package manager.${C_RESET}"
                    ;;
            esac
        fi
    else
        echo ""
        echo -e "  ${C_GREEN}${C_BOLD}${ICON_DONE} All tools installed! All test cases are ready to run.${C_RESET}"
    fi
    
    echo ""
    read -rep "  Press Enter to return to menu..." _
}

#--- Get tool version (best effort) ---
_get_tool_version() {
    local tool="$1"
    set +u
    local path="${TOOL_PATHS[$tool]}"
    set -u
    [[ -z "$path" ]] && path="$tool"
    
    case "$tool" in
        nmap)         "$path" --version 2>/dev/null | head -1 | awk '{print $3}' ;;
        masscan)      "$path" --version 2>/dev/null | head -1 ;;
        *)            echo "installed" ;;
    esac
}

#--- Get install command for a tool ---
_get_install_command() {
    local tool="$1"
    case "$tool" in
        airmon-ng|airodump-ng|aireplay-ng|aircrack-ng|packetforge-ng) echo "apt install -y aircrack-ng" ;;
        nmap)           echo "apt install -y nmap" ;;
        masscan)        echo "apt install -y masscan" ;;
        tcpdump)        echo "apt install -y tcpdump" ;;
        tshark)         echo "apt install -y tshark" ;;
        nbtscan)        echo "apt install -y nbtscan" ;;
        onesixtyone)    echo "apt install -y onesixtyone" ;;
        snmpwalk)       echo "apt install -y snmp" ;;
        yersinia)       echo "apt install -y yersinia" ;;
        fping)          echo "apt install -y fping" ;;
        arping)         echo "apt install -y arping" ;;
        avahi-browse)   echo "apt install -y avahi-utils" ;;
        dig|nslookup)   echo "apt install -y dnsutils" ;;
        jq)             echo "apt install -y jq" ;;
        curl)           echo "apt install -y curl" ;;
        wget)           echo "apt install -y wget" ;;
        ip)             echo "apt install -y iproute2" ;;
        mdk4)           echo "apt install -y mdk4" ;;
        wash|reaver)    echo "apt install -y reaver" ;;
        bully)          echo "apt install -y bully" ;;
        hostapd)        echo "apt install -y hostapd" ;;
        dnsmasq)        echo "apt install -y dnsmasq" ;;
        macchanger)     echo "apt install -y macchanger" ;;
        hcxdumptool)    echo "apt install -y hcxdumptool" ;;
        hcxpcapngtool)  echo "apt install -y hcxtools" ;;
        eaphammer)      echo "git clone https://github.com/s0lst1c3/eaphammer.git && cd eaphammer && ./kali-setup" ;;
        hostapd-mana)   echo "apt install -y hostapd-mana" ;;
        airsnitch)      echo "git clone https://github.com/vanhoefm/airsnitch.git && cd airsnitch && make" ;;
        *)              echo "apt install -y ${tool}" ;;
    esac
}

#--- Check if a specific tool is available ---
require_tool() {
    local tool="$1"
    if ! command -v "$tool" &>/dev/null; then
        local install_cmd
        install_cmd=$(_get_install_command "$tool")
        log_warn "Required tool '${tool}' is not installed."
        read -rep "  Install now? (${install_cmd}) [Y/n]: " prompt
        if [[ "$prompt" =~ ^[Yy]$ ]] || [[ -z "$prompt" ]]; then
            local os
            os=$(_detect_os)
            case "$os" in
                kali|parrot|ubuntu|debian)
                    eval "$install_cmd"
                    if command -v "$tool" &>/dev/null; then
                        log_success "${tool} installed successfully."
                        return 0
                    else
                        log_error "Failed to install ${tool}."
                        return 1
                    fi
                    ;;
                *)
                    log_warn "Auto-install is only supported on Debian-based systems (kali/parrot/ubuntu/debian)."
                    log_warn "Please install '${tool}' manually using your system package manager."
                    return 1
                    ;;
            esac
        else
            return 1
        fi
    fi
    return 0
}

#--- Check multiple tools at once ---
require_tools() {
    local -a tools=("$@")
    local missing_tools=()
    local install_cmds=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
            install_cmds+=("$(_get_install_command "$tool")")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_warn "Missing tools: ${missing_tools[*]}"
        read -rep "  Attempt to install missing tools now? [Y/n]: " prompt
        if [[ "$prompt" =~ ^[Yy]$ ]] || [[ -z "$prompt" ]]; then
            local os
            os=$(_detect_os)
            case "$os" in
                kali|parrot|ubuntu|debian)
                    # apt update only — no apt upgrade
                    apt update -qq
                    for cmd in "${install_cmds[@]}"; do
                        eval "$cmd"
                    done
                    # Re-check
                    local still_missing=0
                    for tool in "${missing_tools[@]}"; do
                        if ! command -v "$tool" &>/dev/null; then
                            log_error "Failed to install ${tool}."
                            ((still_missing++))
                        else
                            log_success "${tool} installed successfully."
                        fi
                    done
                    if [[ $still_missing -gt 0 ]]; then
                        return 1
                    fi
                    return 0
                    ;;
                *)
                    log_warn "Auto-install is only supported on Debian-based systems (kali/parrot/ubuntu/debian)."
                    log_warn "Please install the missing tools manually using your system package manager."
                    return 1
                    ;;
            esac
        else
            return 1
        fi
    fi
    return 0
}

#--- Detect OS (simple helper for package manager decisions) ---
_detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
            kali|parrot|ubuntu|debian) echo "$ID" ;;
            *) echo "other" ;;
        esac
    else
        echo "other"
    fi
}

#--- Get list of tools required for a given test case ---
# Uses TOOL_TC_MAP: tools whose value contains tc_id or "ALL" are required.
get_tools_for_tc() {
    local tc_id="$1"
    local -a tools=()
    local tool tcs
    for tool in $(echo "${!TOOL_TC_MAP[@]}" | tr ' ' '\n' | sort -u); do
        tcs="${TOOL_TC_MAP[$tool]}"
        if [[ "$tcs" == "ALL" ]] || [[ ",${tcs}," == *",${tc_id},"* ]]; then
            tools+=("$tool")
        fi
    done
    echo "${tools[*]}"
}

#--- Ensure all tools for a test case are installed; install if missing ---
# Called at the start of each module run. Prompts to install any missing tools, then proceeds.
# Returns 0 if all tools present (or installed), 1 if user skipped or install failed.
ensure_tools_for_tc() {
    local tc_id="$1"
    local tools
    tools=$(get_tools_for_tc "$tc_id")
    [[ -z "$tools" ]] && return 0
    require_tools $tools
}

#--- Record tool versions into a file (best effort) ---
# Usage: record_tool_versions_to_file "/path/to/file" tool1 tool2 ...
record_tool_versions_to_file() {
    local out_file="$1"
    shift || true
    [[ -n "$out_file" ]] || return 0

    : >"$out_file" 2>/dev/null || true
    echo "# Tool versions (best effort) — $(date -Iseconds)" >>"$out_file" 2>/dev/null || true

    local tool
    for tool in "$@"; do
        command -v "$tool" &>/dev/null || continue
        {
            printf "%s: " "$tool"
            case "$tool" in
                airmon-ng|airodump-ng|aireplay-ng|aircrack-ng|packetforge-ng)
                    ${TOOL_PATHS[aircrack-ng]} --help 2>/dev/null | head -1 || echo "installed"
                    ;;
                tcpdump)
                    ${TOOL_PATHS[tcpdump]} --version 2>/dev/null | head -1 || echo "installed"
                    ;;
                tshark)
                    ${TOOL_PATHS[tshark]} --version 2>/dev/null | head -1 || echo "installed"
                    ;;
                nmap)
                    ${TOOL_PATHS[nmap]} --version 2>/dev/null | head -1 || echo "installed"
                    ;;
                masscan)
                    ${TOOL_PATHS[masscan]} --version 2>/dev/null | head -1 || echo "installed"
                    ;;
                *)
                    set +u
                    local path="${TOOL_PATHS[$tool]}"
                    set -u
                    [[ -z "$path" ]] && path="$tool"
                    "$path" --version 2>/dev/null | head -1 || echo "installed"
                    ;;
            esac
        } >>"$out_file" 2>/dev/null || true
    done
}

#--- Return apt package name for a tool (empty if custom install, e.g. git clone) ---
_get_apt_package() {
    local tool="$1"
    case "$tool" in
        airmon-ng|airodump-ng|aireplay-ng|packetforge-ng|aircrack-ng) echo "aircrack-ng" ;;
        nmap)           echo "nmap" ;;
        masscan)        echo "masscan" ;;
        tcpdump)        echo "tcpdump" ;;
        tshark)         echo "tshark" ;;
        nbtscan)        echo "nbtscan" ;;
        onesixtyone)    echo "onesixtyone" ;;
        snmpwalk)       echo "snmp" ;;
        yersinia)       echo "yersinia" ;;
        fping)          echo "fping" ;;
        arping)         echo "arping" ;;
        avahi-browse)   echo "avahi-utils" ;;
        dig|nslookup)   echo "dnsutils" ;;
        jq)             echo "jq" ;;
        curl)           echo "curl" ;;
        wget)           echo "wget" ;;
        ip)             echo "iproute2" ;;
        mdk4)           echo "mdk4" ;;
        wash|reaver)    echo "reaver" ;;
        bully)          echo "bully" ;;
        hostapd)        echo "hostapd" ;;
        dnsmasq)        echo "dnsmasq" ;;
        macchanger)     echo "macchanger" ;;
        hcxdumptool)    echo "hcxdumptool" ;;
        hcxpcapngtool)  echo "hcxtools" ;;
        searchsploit)   echo "exploitdb" ;;
        python3)        echo "python3" ;;
        iptables)       echo "iptables" ;;
        bettercap)      echo "bettercap" ;;
        arpspoof)       echo "dsniff" ;;
        responder)      echo "responder" ;;
        eaphammer|airsnitch|hostapd-mana) echo "" ;;  # custom install
        *)              echo "$tool" ;;
    esac
}