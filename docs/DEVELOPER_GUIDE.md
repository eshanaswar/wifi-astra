# WiFi-Astra Developer Guide

WiFi-Astra is designed to be highly extensible. This guide explains the core framework logic and how to contribute new assessment modules.

---

## 🏗️ Core Technologies

*   **Language:** Go (1.24+)
*   **Database:** SQLite 3 (WAL mode enabled)
*   **CLI Framework:** Cobra
*   **Config Management:** Viper
*   **TUI:** Readline (Singleton Manager)

---

## 🛠️ Adding a New Module

Assessment modules are Bash scripts located in the `modules/` directory.

### 1. Module Header (Metadata)
Every module must start with a `MODULE_META` block. The Go orchestrator parses this to discover and categorize the module.

```bash
#!/usr/bin/env bash
# MODULE_META
# NAME="My New Attack"
# CATEGORY="X"
# DEPS="A1"
# TOOLS="mytool,grep"
# DESC="Briefly explain what this does"
# REQS="monitor_iface"
```

### 2. Implementation Pattern (Golden Wrapper)
Follow the "Identify → Target → Verify" methodology. Use the standardized environment variables provided by the core.

```bash
set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-.}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"

# ... attack logic ...

# Report success or info status
$ASTRA_BIN record-finding \
    --session-dir "$SESSION_DIR" \
    --tc "$TC_ID" \
    --type vulnerability \
    --name "Finding Name" \
    --severity "MEDIUM" \
    --desc "Observation detail" \
    --rationale "Why this matters" \
    --evidence "$LOG_FILE"
```

---

## 🔍 Adding a New Parser

If your module produces complex structured data (like XML or custom JSON), you should add a specialized parser to the Go core.

1.  Create a new file in `internal/ingest/`.
2.  Register your parser in the `init()` function:
    ```go
    func init() {
        RegisterParser("X1", func(db *sql.DB, tcID string, evidenceDir string) error {
            // Your parsing logic here
            return nil
        })
    }
    ```

---

## 🧪 Running Tests

Always run the full test suite before submitting a Pull Request:
```bash
go test -v ./...
```
*Note: Some tests require root privileges to verify the privilege dropping logic.*
