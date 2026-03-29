# WiFi-Astra System Architecture

WiFi-Astra follows a modern, decoupled architecture that separates high-level orchestration and state management from low-level hardware interaction and attack tools.

---

## 1. High-Level Design

The system is built on a **Controller-Registry-Wrapper** pattern:

1.  **The Orchestrator (Go Core):** Managed state, TUI, and session persistence using SQLite.
2.  **The Registry (Ingestion):** A decoupled dispatcher that identifies and parses tool outputs (Nmap XML, Airodump CSV, Bettercap JSON) into structured database records.
3.  **The Golden Wrappers (Bash Modules):** Isolated shell scripts that execute specialized auditing tools. They communicate back to the core via a standardized environment variable and callback contract.

---

## 2. Directory Structure

```text
/
├── bin/                # Compiled Go binary (wifi-astra)
├── cmd/                # CLI entry points and command definitions
├── internal/
│   ├── config/         # Global YAML configuration management (Viper)
│   ├── controller/     # Mission orchestration and UI flow logic
│   ├── db/             # SQLite schema and repository layer
│   ├── headless/       # Autonomous audit engine
│   ├── ingest/         # Universal result parsing and data ingestion
│   ├── module/         # Dynamic module discovery and metadata parsing
│   ├── report/         # HTML assessment report generator
│   ├── session/        # Session lifecycle and directory management
│   └── ui/             # Singleton TUI and Readline management
├── modules/            # 40+ Assessment scripts (Golden Wrappers)
├── pkg/
│   ├── constants/      # Project-wide constants (DB keys, statuses)
│   ├── executor/       # Process group management and privilege escalation
│   ├── hw/             # Hardware discovery and self-healing recovery
│   └── prereq/         # Environment validation and privilege management
└── sessions/           # Data isolation directory (0700 permissions)
```

---

## 3. Communication Contract

Modules are invoked with a specific environment:
*   `ASTRA_BIN`: Path to the core binary for findings callbacks.
*   `SESSION_DIR`: Root path of the current session.
*   `ASTRA_TARGET_PMF`: Target PMF status (`Required`, `Capable`, `None`).
*   `ASTRA_TARGET_AUTH`: Detected authentication type (e.g., `WPA3-SAE`).
*   `ASTRA_TARGET_RSSI`: Real-time signal strength of the target.
*   `OUTPUT_CSV / OUTPUT_PCAP`: Target paths for standardized tool outputs.

Modules report findings using the hidden callback:
```bash
$ASTRA_BIN record-finding --tc "D1" --type vulnerability --name "Name" --desc "Obs" --severity "HIGH" --rationale "Impact" --evidence "$FILE"
```

---

## 4. Security & Privilege Model (Guardian)

WiFi-Astra implements a "Guardian" privilege lifecycle:
1.  **Boot (Root):** Tool starts as root to perform hardware discovery and recovery.
2.  **Drop (User):** Immediately switches to the regular invoking user for the TUI, DB, and Parsing logic.
3.  **Contextual Escalate:** The `executor` temporarily restores root access strictly for the duration of a tool's execution (e.g., `airodump-ng`), then drops it immediately after.

---

## 5. Performance & Reliability Patterns

### Smart Exit (Real-time Polling)
Professional attack modules (e.g., `D1`, `D2`, `D3`) do not rely on static `sleep` timers. Instead, they implement a polling loop that interrogates evidence files (e.g., via `aircrack-ng`) every few seconds. The moment a valid cryptographic artifact (handshake, WEP key, WPS PIN) is detected, the module terminates all background processes and exits with success, saving significant time during large-scale engagements.

### Smart Tactical Scout Engine
Before any disruptive module runs, the Go core executes `hw.ScoutTarget()`. This performs a surgical 5-second capture to extract:
*   **PMF Status:** Identifies if 802.11w is Required or Capable.
*   **Encryption:** Detects WPA3-SAE or OWE transition modes.
*   **SNR:** Extracts RSSI to warn the operator if the signal is too weak for reliable injection.

### Process Group Reaper
To prevent orphaned hardware locks (e.g., `hostapd` running after `astra` exits), the `executor` places every module in a unique **Process Group (PGID)**. Upon module termination or framework exit, the core sends a `SIGKILL` to the entire group, ensuring a 100% clean hardware state.

### Hardware Interface Locking
To prevent concurrent modules from clashing over the same wireless adapter (which causes channel-hopping corruption and driver crashes), the Go core implements a global `sync.Mutex` registry. Before an attack starts, the `AssessmentController` must acquire an exclusive lock on the physical interface name. If the interface is busy, the request is queued or rejected.
