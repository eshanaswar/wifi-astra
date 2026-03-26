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

# NOTE: TOOL_TC_MAP is now dynamically populated by lib/discovery.sh at startup.

#--- Check availability of all modules based on tools ---
declare -gA TC_AVAILABLE

#--- Resolve tool path (System PATH + Custom locations) ---
_resolve_tool_path() {
    local tool="$1"
    local path=""
    
    # 1. Check system PATH
    path=$(command -v "$tool" 2>/dev/null)
    if [[ -n "$path" ]]; then
        echo "$path"
        return 0
    fi
    
    # 2. Check for common research tool names in subdirectories
    # Some tools have different binary names than their folder/repo name
    local binary="$tool"
    case "$tool" in
        airsnitch)      binary="research/airsnitch.py" ;;
        eaphammer)      binary="eaphammer" ;;
        krack-test)     binary="krackattacks-scripts/krackattack/krackattack.py" ;;
        fragattack)     binary="fragattacks/fragattack.py" ;;
        dragonslayer)   binary="dragonblood/dragonslayer.py" ;;
        dragondrain)    binary="dragonblood/dragondrain.py" ;;
    esac

    # Check relative to script dir
    if [[ -x "${SCRIPT_DIR}/${binary}" ]]; then
        echo "${SCRIPT_DIR}/${binary}"
        return 0
    elif [[ -x "${SCRIPT_DIR}/${tool}/${binary}" ]]; then
        echo "${SCRIPT_DIR}/${tool}/${binary}"
        return 0
    fi
    
    # 3. Check environment variables
    local env_var=$(echo "${tool^^}_PATH" | tr '-' '_')
    if [[ -n "${!env_var:-}" && -x "${!env_var}" ]]; then
        echo "${!env_var}"
        return 0
    fi

    return 1
}

check_all_module_availabilities() {
    for _tc in "${TC_ORDER[@]}"; do
        local tools
        tools=$(get_tools_for_tc "$_tc")
        if [[ -z "$tools" ]]; then
            TC_AVAILABLE["$_tc"]=1
            continue
        fi
        
        local all_present=1
        for tool in $tools; do
            local path="${TOOL_PATHS[$tool]:-}"
            if [[ -z "$path" ]] || [[ ! -x "$path" ]]; then
                # Re-check path
                path=$(_resolve_tool_path "$tool")
                if [[ -n "$path" ]]; then
                    TOOL_PATHS["$tool"]="$path"
                else
                    all_present=0
                    break
                fi
            fi
        done
        TC_AVAILABLE["$_tc"]=$all_present
    done
}

#--- Quick check at startup (blocking for critical tools) ---
quick_prereq_check() {
    local missing_critical=()
    local critical_tools=("bash" "jq" "ip" "tcpdump" "dig" "iw")
    
    # Check every tool in the registry and store its path
    local tool
    for tool in "${!TOOL_TC_MAP[@]}"; do
        local path
        path=$(_resolve_tool_path "$tool")
        if [[ -n "$path" ]]; then
            TOOL_PATHS["$tool"]="$path"
        else
            TOOL_PATHS["$tool"]=""
        fi
    done
    
    # Validate critical ones
    for tool in "${critical_tools[@]}"; do
        if [[ -z "${TOOL_PATHS[$tool]:-}" ]]; then
            # Re-check
            local path
            path=$(_resolve_tool_path "$tool")
            if [[ -n "$path" ]]; then
                TOOL_PATHS["$tool"]="$path"
            else
                missing_critical+=("$tool")
            fi
        fi
    done
    
    if [[ ${#missing_critical[@]} -gt 0 ]]; then
        log_warn "CRITICAL TOOLS MISSING: ${missing_critical[*]}"
        log_info "These tools are required for core framework functionality."
        
        local choice=""
        # Use safe_read if available, otherwise fallback to basic read
        if declare -f safe_read &>/dev/null; then
            safe_read "Attempt to install missing critical tools now? [Y/n]" choice "y"
        else
            printf "  Attempt to install missing critical tools now? [Y/n]: "
            read choice
            choice="${choice:-y}"
        fi

        if [[ "${choice,,}" == "y" ]]; then
            log_info "Updating package lists..."
            apt update -qq || true
            log_info "Installing: ${missing_critical[*]}..."
            # Translate tool names to packages if needed (e.g. jq is jq)
            local pkgs=()
            for t in "${missing_critical[@]}"; do
                local p
                p=$(_get_apt_package "$t")
                [[ -n "$p" ]] && pkgs+=("$p")
            done
            
            if [[ ${#pkgs[@]} -gt 0 ]]; then
                apt install -y "${pkgs[@]}"
            fi

            # Re-verify
            local still_missing=()
            for tool in "${missing_critical[@]}"; do
                if command -v "$tool" &>/dev/null; then
                    TOOL_PATHS["$tool"]=$(command -v "$tool")
                else
                    still_missing+=("$tool")
                fi
            done
            
            if [[ ${#still_missing[@]} -eq 0 ]]; then
                log_success "Critical tools installed and verified."
                missing_critical=()
            else
                missing_critical=("${still_missing[@]}")
            fi
        fi
    fi

    if [[ ${#missing_critical[@]} -gt 0 ]]; then
        log_error "FAILED to resolve critical dependencies: ${missing_critical[*]}"
        log_error "Please install them manually (e.g., sudo apt install ${missing_critical[*]}) and restart."
        exit 1
    fi
    
    log_success "Core environment verified."
    check_all_module_availabilities
    return 0
}

#--- Hardware Injection Validation ---
check_hardware_injection() {
    local iface="${MONITOR_INTERFACE:-}"
    if [[ -z "$iface" ]]; then
        log_debug "MONITOR_INTERFACE not set, skipping injection check."
        return 0
    fi
    
    if ! validate_injection "$iface"; then
        echo ""
        echo -e "${C_BG_RED}${C_WHITE}  [!] HARDWARE INJECTION FAILURE  ${C_RESET}"
        echo -e "${C_RED}  The interface ${C_BOLD}${iface}${C_RESET}${C_RED} failed the injection test.${C_RESET}"
        echo -e "${C_RED}  Active attacks (deauth, replay, etc.) will likely fail.${C_RESET}"
        echo ""
        return 1
    fi
    return 0
}

#--- Check module-specific dependencies before execution ---
check_module_dependencies() {
    local tc_id="$1"
    local tools
    tools=$(get_tools_for_tc "$tc_id")
    [[ -z "$tools" ]] && return 0
    
    local missing_tools=()
    for tool in $tools; do
        local path="${TOOL_PATHS[$tool]:-}"
        if [[ -z "$path" ]] || [[ ! -x "$path" ]]; then
            # Re-check path
            if command -v "$tool" &>/dev/null; then
                TOOL_PATHS["$tool"]=$(command -v "$tool")
            else
                missing_tools+=("$tool")
            fi
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_warn "Missing dependencies for module ${tc_id}: ${missing_tools[*]}"
        if require_tools "${missing_tools[@]}"; then
            return 0
        else
            return 1
        fi
    fi
    return 0
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
            local old_ifs="${IFS:-}"
            IFS=',' read -ra tc_list <<< "$tcs"
            for tc in "${tc_list[@]}"; do
                tc=$(echo "$tc" | xargs)
                if [[ ! " ${affected_tcs[*]} " =~ " ${tc} " ]]; then
                    affected_tcs+=("$tc")
                fi
            done
            IFS="${old_ifs}"
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
        
        safe_read "Install all missing tools at once (batch apt + custom installs)? [Y/n]: " prompt
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
    
    check_all_module_availabilities
    
    echo ""
    safe_read "Press Enter to return to menu..." _
}

#--- Get tool version (best effort) ---
_get_tool_version() {
    local tool="$1"
    local path="${TOOL_PATHS[$tool]:-}"
    [[ -z "$path" ]] && return 1
    
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
        eaphammer)      echo "[[ -d eaphammer ]] || git clone https://github.com/s0lst1c3/eaphammer.git; cd eaphammer && ./kali-setup" ;;
        hostapd-mana)   echo "apt install -y hostapd-mana" ;;
        airsnitch)      echo "apt install -y libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev libdbus-1-dev pkg-config build-essential net-tools python3-venv; [[ -d airsnitch ]] || git clone https://github.com/vanhoefm/airsnitch.git; cd airsnitch && ./setup.sh && cd airsnitch/research && ./build.sh && ./pysetup.sh" ;;
        wkhtmltopdf)    echo "apt install -y wkhtmltopdf 2>/dev/null || { 
            echo '  [*] wkhtmltopdf not in apt, trying GitHub releases (Bookworm/Kali)...';
            local deb_url='https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-3/wkhtmltox_0.12.6.1-3.bookworm_amd64.deb';
            wget -q \"\$deb_url\" -O $TMP_DIR/wkhtml.deb && apt install -y $TMP_DIR/wkhtml.deb && rm $TMP_DIR/wkhtml.deb;
        } || {
            echo '  [*] Bookworm build failed, trying Bullseye fallback...';
            local deb_url_fallback='https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.bullseye_amd64.deb';
            wget -q \"\$deb_url_fallback\" -O $TMP_DIR/wkhtml.deb && apt install -y $TMP_DIR/wkhtml.deb && rm $TMP_DIR/wkhtml.deb;
        } || echo 'Warning: Could not install wkhtmltopdf. PDF reports will be disabled (HTML still available).'" ;;
        krack-test)     echo "[[ -d krackattacks-scripts ]] || git clone https://github.com/vanhoefm/krackattacks-scripts.git" ;;
        fragattack)     echo "[[ -d fragattacks ]] || git clone https://github.com/vanhoefm/fragattacks.git" ;;
        dragonslayer|dragondrain) echo "[[ -d dragonblood ]] || git clone https://github.com/vanhoefm/dragonblood.git" ;;
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
        safe_read "Install now? (${install_cmd}) [Y/n]: " prompt
        if [[ "$prompt" =~ ^[Yy]$ ]] || [[ -z "$prompt" ]]; then
            local os
            os=$(_detect_os)
            case "$os" in
                kali|parrot|ubuntu|debian)
                    eval "$install_cmd"
                    if command -v "$tool" &>/dev/null; then
                        TOOL_PATHS["$tool"]=$(command -v "$tool")
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
        safe_read "Attempt to install missing tools now? [Y/n]: " prompt
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
                            TOOL_PATHS["$tool"]=$(command -v "$tool")
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
        local path="${TOOL_PATHS[$tool]:-}"
        [[ -n "$path" ]] || continue
        {
            printf "%s: " "$tool"
            case "$tool" in
                airmon-ng|airodump-ng|aireplay-ng|aircrack-ng|packetforge-ng)
                    local ac_path="${TOOL_PATHS[aircrack-ng]:-}"
                    if [[ -n "$ac_path" ]]; then
                        "$ac_path" --help 2>/dev/null | head -1 || echo "installed"
                    else
                        echo "missing"
                    fi
                    ;;
                *)
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
        eaphammer|airsnitch|hostapd-mana|krack-test|fragattack|dragonslayer|dragondrain|wkhtmltopdf) echo "" ;;  # custom install
        *)              echo "$tool" ;;
    esac
}

#--- Export helper functions for module subshells ---
export -f check_module_dependencies
export -f get_tools_for_tc
export -f require_tools
