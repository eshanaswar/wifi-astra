# WiFi-Astra Developer Guide

How to build, extend, and contribute to WiFi-Astra.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.24+ |
| CLI framework | Cobra |
| Configuration | Viper |
| Database | SQLite 3 (WAL mode, `mattn/go-sqlite3`) |
| TUI | `chzyer/readline` (singleton manager) |
| Module scripts | Bash (`#!/usr/bin/env bash`, `set -euo pipefail`) |

---

## Build

```bash
# Full build
go build -o bin/wifi-astra ./cmd/astra/

# Build check (no output written)
go build -o /dev/null ./cmd/astra/

# Tests
go test ./...

# Lint modules
shellcheck -S warning modules/*.sh
```

All three must pass before committing. No exceptions.

---

## Adding a New Module

### 1. Create the file

```bash
touch modules/<category><number>_<name>.sh
chmod +x modules/<category><number>_<name>.sh
```

Convention: `a1_identify_networks.sh`, `d4_wpa3_dragonblood.sh`. Lowercase, underscores.

### 2. Write the MODULE_META header

This is parsed at runtime by `internal/module.DiscoverModules()`. Every field is required.

```bash
#!/usr/bin/env bash
# MODULE_META
# NAME="My Attack Module"
# CATEGORY="X"
# DEPS="A1"                        # Comma-separated module IDs this depends on
# CRITICAL="no"                    # "yes" = session fails if this module fails
# TOOLS="mytool,grep,awk"          # Comma-separated; checked at session start
# DESC="Brief one-line description"
# REQS="monitor_iface,target_bssid"  # Required env vars
# PCAP="yes"                       # "yes" if module produces a PCAP
# TIMED="yes"                      # "yes" if module uses SCAN_TIME
# DECODE="wifi_mgmt"               # Decode context hint for report
```

### 3. Implement the module body

Follow the Golden Wrapper pattern:

```bash
set -euo pipefail

# Read env vars from controller (always provide defaults)
INTERFACE="${MONITOR_INTERFACE:-}"
BSSID="${GUEST_BSSID:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
SCAN_TIME="${SCAN_TIME:-60}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="X1"

# Validate required inputs
if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_results.log"

# Telemetry heartbeat (background) — reports progress to TUI
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( ELAPSED * 100 / SCAN_TIME ))
        [[ $PCT -gt 95 ]] && PCT=95
        "$ASTRA_BIN" record-progress \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --percent "$PCT" \
            --status "Running attack..."
        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# Run primary tool — foreground in window, background with wait otherwise
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout --foreground "$SCAN_TIME" mytool -i "$INTERFACE" -t "$BSSID" 2>&1 | tee "$LOG_FILE" || true
else
    timeout "$SCAN_TIME" mytool -i "$INTERFACE" -t "$BSSID" > "$LOG_FILE" 2>&1 &
    TOOL_PID=$!
    wait "$TOOL_PID" || true
fi

kill "$TEL_PID" 2>/dev/null || true

# Final progress update
"$ASTRA_BIN" record-progress \
    --session-dir "$SESSION_DIR" \
    --tc "$TC_ID" \
    --percent 100 \
    --status "Mission Complete"

# Analyze results and record findings
if grep -q "VULN_INDICATOR" "$LOG_FILE" 2>/dev/null; then
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "Vulnerability Found" \
        --severity HIGH \
        --desc "Description of what was observed." \
        --target "$BSSID" \
        --evidence "$LOG_FILE" \
        --rationale "Why this matters and what an attacker can do with it."
else
    # Always record something — controller needs to know the module ran
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[X1] Audit Complete" \
        --severity INFO \
        --desc "Module completed. No vulnerability detected in this window." \
        --evidence "$LOG_FILE" \
        --rationale "Negative result — target appears not vulnerable under tested conditions."
fi

# Hold window in tactical mode so user can see output
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n[*] Mission Complete. Window will close in 5s..."
    sleep 5
fi

exit 0
```

### 4. Register the module's tool dependencies

Add the module ID and its required tools to `pkg/prereq/prereq.go`:

```go
var ModuleToolMap = map[string][]string{
    // ...existing entries...
    "X1": {"mytool", "grep"},
}
```

### 5. Register post-run cracking (D-category only)

If your module captures credentials or cryptographic material that the controller should crack inline, wire it into `internal/controller/assessment.go`. The pattern used by D1, D2, D3, and D5 is:

- `HandlePostRun` dispatches `HandleD1PostRun` (or equivalent) after the module exits with code 0.
- The cracking helper calls `RunHashcat` (or `aircrack-ng` / `asleap`) and records recovered credentials via `c.Session.DB.Exec(INSERT INTO credential ...)`.
- For staged cracking (like D1), `cracking_intel.go` provides `GenerateSSIDWordlist`, `CommonWordlistPaths`, and `BestRulePath` to locate wordlists and generate SSID-derived mutations.

If your module doesn't produce crackable material, skip this step.

### 6. Run the pre-commit checks

```bash
shellcheck -S warning modules/x1_my_attack.sh
go build -o /dev/null ./cmd/astra/
go test ./...
```

---

## Module Writing Rules

These rules are not suggestions — they are enforced by shellcheck and code review.

### Security

- **Double-quote every variable expansion touching external data**: `"$SSID"`, `"$BSSID"`, `"$GUEST_CHANNEL"`. Unquoted variables containing spaces or shell metacharacters from an SSID can break script execution or cause injection.
- **Never use `eval`**. Use explicit variable expansion.
- **`SanitizeEnv` is mandatory** on the Go side — the controller applies it before every module launch. Never bypass it.
- **Heredocs**: use `cat <<'EOF'` (single-quoted, no interpolation) when embedding SSIDs/passwords in config files. Double-quoted heredocs interpolate `$SSID` which breaks on SSIDs containing special characters.

### Process Management

- **Use `timeout N tool`** to bound long-running processes. Never use `(sleep N; kill $PID) &` — the sleep subshell leaks and the kill may race.
- **Use `timeout --foreground N tool`** only in `ASTRA_IN_WINDOW=true` paths where the tool needs a TTY and signal propagation. Never use it on background (`&`) launches.
- **Quote `"$ASTRA_BIN"`** on every invocation.
- **`wait "$PID" || true`** — always use `|| true` on wait to prevent the script from exiting if the child was already killed.

### Window vs Background Mode

Modules execute in two contexts:

```bash
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Interactive terminal window — run in foreground, tee to log
    timeout --foreground "$SCAN_TIME" tool 2>&1 | tee "$LOG_FILE" || true
else
    # Main feed — redirect all output, background + wait
    timeout "$SCAN_TIME" tool > "$LOG_FILE" 2>&1 &
    TOOL_PID=$!
    wait "$TOOL_PID" || true
fi
```

**Critical**: if your module analyzes `$LOG_FILE` for results, the window-mode path **must** tee to that file. A common bug is having window mode write only to stdout while detection reads an empty `$LOG_FILE` — detection always returns negative.

### Always Record a Finding

Every module must call `record-finding` at least once, even on negative results. The controller marks a module as "completed" only when a finding is recorded. A module that exits 0 without recording a finding appears as "no result" in the session and report.

### hostapd Config Files

```bash
# CORRECT — ssid= takes a raw string, no quotes
cat <<'EOF' > "$HOSTAPD_CONF"
ssid=$SSID
EOF

# WRONG — puts literal double-quotes in the SSID name
cat <<EOF > "$HOSTAPD_CONF"
ssid="$SSID"
EOF
```

---

## Go Packages

When modifying the Go core:

### Adding a new subcommand

1. Create `cmd/<command>.go`
2. Register with `rootCmd.AddCommand()` in `cmd/root.go`
3. Follow the cobra pattern from existing commands

### Adding an ingest parser

If your module produces structured output (XML, custom JSON), add a parser to `internal/ingest/`:

```go
// internal/ingest/x1_parser.go
func ParseX1Results(evidenceDir string, tc string) error {
    // Parse tool output, write to session DB
    return nil
}
```

Register it in the controller's post-run dispatch in `internal/controller/assessment.go`.

### Hardware operations

All hardware interactions go through `pkg/hw`. Never call `exec.Command("airmon-ng", ...)` directly from the controller — use the hw package functions which handle error capture via `CombinedOutput()` and interface state tracking.

---

## Testing

```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./...

# Run specific package
go test -v wifi-astra/internal/module
```

Some tests require root (privilege-dropping logic). Run the full suite with `sudo` if you see permission errors.

---

## Shellcheck Compliance

All modules must pass `shellcheck -S warning`. Common issues to avoid:

| Code | Issue | Fix |
|------|-------|-----|
| SC2034 | Unused variable | Remove or use the variable |
| SC2086 | Unquoted variable | Add double quotes: `"$VAR"` |
| SC2064 | Trap with double quotes | Use single quotes for deferred expansion: `trap 'cmd "$VAR"' EXIT` |
| SC2046 | Unquoted command substitution | Quote it: `"$(cmd)"` |
| SC2155 | Declare and assign separately | `local v; v=$(cmd)` not `local v=$(cmd)` |

Run shellcheck before every commit:

```bash
shellcheck -S warning modules/*.sh
```
