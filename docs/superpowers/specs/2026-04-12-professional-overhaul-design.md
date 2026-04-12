# WiFi-Astra: Professional Tool Overhaul Design Spec

**Date:** 2026-04-12
**Author:** eshanaswar
**Status:** Approved
**Scope:** Solo operator, all engagement types (SMB, Enterprise, Hospitality, High-security/Modern)
**Hardware:** Dual adapter — one MONITOR (injection/capture), one MANAGEMENT (stays connected)

---

## 0. Goals

Make WiFi-Astra a professional-grade WiFi penetration testing tool for authorized live engagements. The tool must:

1. **Never corrupt or silently fail** — every test run produces reviewable artifacts
2. **Cover the full modern 802.11 stack** — 2.4GHz, 5GHz, 6GHz, WPA2/WPA3/OWE/WPA3-Enterprise
3. **Be safe to use on live engagements** — scope enforcement prevents accidental testing of unauthorized targets
4. **Leave a complete audit trail** — logs, PCAPs, and structured evidence indexed and hashed for post-engagement review

---

## 1. Architecture: Core Reliability & Security Hardening

### 1.1 Bash Security Hardening (all 46 modules)

**Problem:** Variables from external data (`$SSID`, `$BSSID`, `$TARGET_CLIENT`, `$GUEST_SSID`, etc.) are used unquoted in many modules. SSIDs like `O'Brien's WiFi` or `Corp;Net` silently break module execution on live networks.

**Fix:** Systematic double-quote pass across all 46 `modules/*.sh` files. Every variable expansion touching external data uses `"$VAR"`. `shellcheck` is run against every module as the validation gate — no module passes without a clean shellcheck result.

Special attention areas:
- `cat <<EOF` heredocs in `f1_rogue_ap.sh`, `f2_pineap_karma.sh` — switch to individual `echo` calls with strict quoting or use `cat <<'EOF'` (no interpolation) where possible
- `eval` usage — banned entirely; replace with explicit variable expansion

### 1.2 Go-Side Environment Sanitizer

**Problem:** No sanitization of values before `os.Setenv` in the executor. A malicious or malformed SSID could carry shell metacharacters into Bash module execution.

**Fix:** Add `SanitizeEnv(key, value string) string` in `pkg/executor`. Strips: newlines (`\n`, `\r`), null bytes, and shell metacharacters (`;`, `&`, `|`, `` ` ``, `$(...)`). Applied to all env vars set before module launch. Returns the sanitized value and logs a warning if any characters were stripped.

### 1.3 Hardware Recovery on Crash / SIGTERM

**Problem:** `hw.Recover()` is not guaranteed to run on `SIGTERM` or panic. On dual-adapter setups, a crash leaves the injection adapter locked in monitor mode, requiring manual recovery before the next test.

**Fix:**
- Register `defer hw.Recover(false)` at the top of the main execution path in `cmd/root.go`
- Signal handler explicitly calls `hw.Recover(false)` before `os.Exit`
- `ExecMgr.KillAll()` called before `hw.Recover()` to ensure all process groups are dead before interface recovery

### 1.4 Silent Hardware Failure Capture (`pkg/hw`)

**Problem:** `exec.Command(...).Run()` errors are silently ignored in `pkg/hw`. Failures in `airmon-ng`, `iw`, `ip link` surface as vague downstream errors with no context.

**Fix:** Replace `.Run()` with `CombinedOutput()` throughout `pkg/hw`. Return descriptive errors: `"airmon-ng failed on wlan0: <stderr output>"`. All hardware operation errors are logged at `ERROR` level with full stderr before returning.

### 1.5 Dual Adapter Role Registry

**Problem:** The tool discovers adapters but doesn't formally enforce interface roles. An attack module could accidentally use the management interface, dropping the operator's connectivity.

**Fix:** Add an `InterfaceRoleRegistry` to `pkg/hw`:
- Two roles: `RoleMonitor` (injection/capture), `RoleManagement` (never touched by attacks)
- Registry is set once during the Adapter Assignment Wizard at session start
- `AssessmentController` checks role before assigning any interface to a module
- Any attempt to use the management interface for monitor ops is rejected with an explicit error and logged

---

## 2. Evidence System

The session evidence directory becomes the primary deliverable of every engagement — a self-contained, reviewable artifact store.

### 2.1 Per-Module Structured JSON Log

Every module produces a structured log alongside existing stdout output:

```
sessions/<id>/evidence/logs/<TC_ID>_run_<timestamp>.json
```

Fields:
```json
{
  "module_id": "D1",
  "module_name": "WPA Handshake & PMKID Capture",
  "started_at": "2026-04-12T14:30:22Z",
  "ended_at": "2026-04-12T14:31:45Z",
  "duration_seconds": 83,
  "exit_code": 0,
  "success": true,
  "target": { "ssid": "CorpNet", "bssid": "AA:BB:CC:DD:EE:FF", "channel": 6 },
  "tools_invoked": ["hcxdumptool", "aireplay-ng", "aircrack-ng"],
  "files_written": ["D1_capture.pcapng", "D1_capture.hc22000"],
  "findings_recorded": 1,
  "interface_monitor": "wlan1mon",
  "interface_management": "wlan0"
}
```

### 2.2 SHA256 Evidence Manifest

Every file written to `sessions/<id>/evidence/` is SHA256-hashed at the moment of creation. The session root maintains `manifest.json`:

```json
{
  "D1_capture.pcapng": {
    "sha256": "a3f9b2c1...",
    "captured_at": "2026-04-12T14:31:45Z",
    "module": "D1",
    "size_bytes": 48291
  }
}
```

The manifest is append-only during the session. This provides chain of custody — evidence files can be verified as unmodified since capture.

### 2.3 Pre-Module / Post-Module Context Snapshot

Before each module runs, the controller writes `<TC_ID>_run_context.json`:
- Target SSID, BSSID, channel, PMF status, auth type
- Adapter assignments
- Operator-entered parameters (e.g., `TARGET_CLIENT`)
- Engagement name and session ID

After completion, exit status, duration, and captured files are appended to the same file.

### 2.4 Failure Capture

If a module exits non-zero, the tool captures:
- Full stderr output
- Last 50 lines of stdout
- Exit code and signal (if killed)
- Written to `sessions/<id>/evidence/logs/<TC_ID>_failure.log`

Currently failed modules leave no trace. On engagements this is critical — you must know whether D1 failed because no handshake was captured or because `hcxdumptool` wasn't installed.

### 2.5 Session Replay Log

Written throughout the session to `sessions/<id>/session_replay.log`. Plain text, one line per event, chronological:

```
2026-04-12T14:28:00Z [SESSION_START] engagement=AcmeCorp session=abc123
2026-04-12T14:28:05Z [SCOPE_SET] networks=3 ssids=["CorpNet","Corp-Guest","IoT"]
2026-04-12T14:30:00Z [MODULE_START] tc=D1 target=CorpNet bssid=AA:BB:CC:DD:EE:FF
2026-04-12T14:31:45Z [MODULE_END] tc=D1 exit=0 files=2 findings=1
2026-04-12T14:32:00Z [MODULE_START] tc=D3 target=CorpNet
2026-04-12T14:34:10Z [MODULE_END] tc=D3 exit=1 reason=WPS_LOCKED
2026-04-12T15:00:00Z [SESSION_END] total_modules=12 total_findings=4 total_files=18
```

### 2.6 Session Evidence Index

On session close or via `wifi-astra session summary`, generates `EVIDENCE_INDEX.txt` — a flat human-readable listing of every artifact, its hash, module, and size. Used when writing the manual report.

---

## 3. Modern Attack Coverage

### 3.1 6 GHz / Wi-Fi 6E Discovery (Update A1)

`airodump-ng` is blind to 6GHz. Update `a1_identify_networks.sh`:
1. Check adapter 6GHz support via `iw phy` before starting
2. Run parallel `hcxdumptool` sweep on 6GHz channels alongside airodump 2.4/5GHz scan
3. Merge results into unified network table in SQLite
4. Tag each discovered network with its band (2.4, 5, 6)

Without this, entire APs are invisible on modern Wi-Fi 6E deployments.

### 3.2 PMKID Clientless Path Verification (Update D1)

D1 invokes `hcxdumptool` but the PMKID extraction chain needs hardening:
1. Verify `hcxpcapngtool` extracts to hashcat 22000 format (not legacy 16800)
2. Add fallback path if `hcxtools` version doesn't support 22000
3. Run `hashcat --identify` on the output to confirm format before reporting success
4. PMKID capture is now the primary path — deauth/4-way handshake is the fallback, not the default

### 3.3 WPA3-SAE Dragonblood — Current State (Update D4)

Original CVE-2019-9494 / CVE-2019-9496 are largely patched. Update D4 to:
1. Detect SAE-PK (WPA3 R3) — immune to Dragonblood, skip and report `NOT_VULNERABLE`
2. Test for incomplete patch implementations (timing side-channels on Broadcom/Qualcomm chipsets)
3. Use `dragonslayer` (updated fork) rather than the original PoC tools
4. Report specific CVE tested and result clearly in the finding

### 3.4 PEAP/MSCHAPv2 Credential Capture (Update D5)

Most common enterprise WiFi attack. Update D5:
1. Integrate `hostapd-wpe` as the primary engine for rogue RADIUS
2. Capture MSCHAPv2 challenge/response pairs to `<TC_ID>_mschapv2.txt`
3. Automatically run `asleap` against captured pairs for offline crack attempt
4. If `eaphammer` is available, use it as alternative (supports more EAP types)
5. Log RADIUS server certificate used (self-signed vs custom) in run context

### 3.5 MAC Randomization Correlation (Update A4)

iOS 14+, Android 10+, Windows 10+ rotate MACs while disconnected. Update A4:
1. Track 802.11 sequence number continuity across MAC changes to correlate devices
2. Build IE (Information Element) fingerprints: supported rates, HT/VHT/HE capabilities, vendor IEs, power constraints — unique per device model
3. Maintain a `device_correlation.json` mapping randomized MACs to probable physical devices
4. Flag clients using randomization so targeted attacks (Evil Twin, Karma) know to use SSID-based rather than MAC-based targeting

### 3.6 OWE Transition Mode Testing (Update D6)

OWE Transition Mode APs advertise two BSSIDs — one open, one OWE-protected, with a hidden IE linking them. Update D6:
1. Detect Transition Mode pairs from A1 scan data (look for matching SSID with different AKMs)
2. Test forced association to the open BSSID to confirm whether OWE protection is actually enforced
3. Test whether clients that support OWE can be forced to the open BSSID via deauth + timed Probe Response spoofing
4. Common in hospitality and retail — document the bypass result clearly

### 3.7 Captive Portal Vendor Fingerprinting (Update F3)

Update F3 to detect the captive portal vendor from HTTP headers, redirect URL patterns, and login page HTML structure:
- Cisco ISE, Aruba ClearPass, FortiGate, UniFi, pfSense, Meraki
- Adapt bypass strategy based on detected vendor (each has known weaknesses)
- Log detected vendor in run context so manual testing can continue with vendor-specific techniques

### 3.8 NAC Bypass via Authorized MAC Clone (Update G4)

Update G4:
1. From A4 data, identify clients that have successfully authenticated to the target network
2. Use `macchanger` to clone the authorized client MAC on the management interface
3. Attempt network association and test if NAC grants segment access
4. Covers Cisco ISE and Aruba ClearPass MAC-based admission control

### 3.9 New Module: EAP Certificate Validation Testing (D8)

**The most common enterprise WiFi misconfiguration.**

Tests whether clients validate the RADIUS server certificate during EAP authentication. If they don't, an attacker can capture credentials with any self-signed cert.

1. Stand up rogue AP with `hostapd-wpe` using a self-signed certificate
2. Monitor for client EAP authentication attempts
3. If a client completes Phase 1 (TLS handshake) with the self-signed cert → `VULNERABLE`
4. If client rejects or shows a warning → `SECURE` (log the EAP rejection frame as evidence)
5. Write captured EAP exchanges to PCAP regardless of outcome

### 3.10 New Module: Wi-Fi 6 Environment Detection (A5)

Passive reconnaissance module — not an attack. Detects 802.11ax (Wi-Fi 6/6E) specific capabilities:
1. BSS Coloring values in use (spatial reuse)
2. OFDMA support (uplink/downlink)
3. Target Wake Time (TWT) agreements
4. MU-MIMO configuration
5. Output: a `wifi6_environment.json` report indicating what generation of hardware is present and which attack modules are viable vs likely to fail

---

## 4. Engagement Workflow

### 4.1 Pre-Engagement Gate

When starting a new session, prompt for engagement name only:
```
Engagement name: AcmeCorp_HQ_Apr2026
```
Written to `session_metadata.json`. All subsequent log entries are stamped with this name.

No time-boxing, no tester name field.

### 4.2 Live Scope Selection (Post-A1)

After A1 (network discovery) completes, the operator selects authorized networks from the discovered list:
```
Discovered Networks — Select in-scope targets:
  [x] 1. CorpNet          AA:BB:CC:DD:EE:FF  ch6   WPA2-Enterprise
  [x] 2. Corp-Guest       AA:BB:CC:DD:EE:F0  ch11  WPA2-PSK
  [ ] 3. Neighbor_WiFi    11:22:33:44:55:66  ch1   WPA2-PSK
  [x] 4. IoT-Devices      AA:BB:CC:DD:EE:F1  ch6   WPA2-PSK
```

Selected networks become the authorized scope for the session. No manual BSSID/SSID entry — scope is built entirely from live scan results.

### 4.3 Scope Enforcement

Before any module that targets a specific BSSID/SSID runs:
1. Controller checks target against the authorized scope list
2. If not in scope: module is blocked, attempt is logged to `session_replay.log` with reason `SCOPE_VIOLATION`
3. Operator sees a clear error: `"[!] CorpNet2 (BB:CC:DD:EE:FF:00) is not in the authorized scope for this session"`

This prevents accidental testing of neighboring networks in dense RF environments.

### 4.4 Dependency Preflight Check

At session start, `pkg/prereq` runs a hard dependency check against all tools used across all modules:
- `aircrack-ng`, `airodump-ng`, `aireplay-ng`, `airmon-ng`
- `hcxdumptool`, `hcxpcapngtool`
- `hostapd`, `hostapd-wpe`, `dnsmasq`
- `mdk4`, `nmap`, `responder`, `eaphammer`
- `asleap`, `hashcat`, `john`

Missing tools are reported upfront with install instructions. The session can still start with missing tools, but affected modules are marked `UNAVAILABLE` in the module list with the reason shown.

### 4.5 Adapter Assignment Wizard

At session start, detected adapters are listed with capabilities:
```
Detected Adapters:
  wlan0  [Realtek RTL8812AU]  Monitor: YES  Injection: YES  5GHz: YES  6GHz: NO
  wlan1  [Intel AX210]        Monitor: YES  Injection: YES  5GHz: YES  6GHz: YES

Assign roles:
  MONITOR (injection/capture): wlan0
  MANAGEMENT (internet/C2):    wlan1
```

Role assignment is locked for the session. `InterfaceRoleRegistry` in `pkg/hw` enforces it.

### 4.6 Post-Engagement Cleanup Checklist

When a session is closed, the controller runs and displays a checklist:
```
[✓] wlan0 restored to managed mode
[✓] wlan1 unchanged (management interface)
[✓] NetworkManager re-enabled
[✓] hostapd: no active processes
[✓] dnsmasq: no active processes
[✓] responder: no active processes
[✓] Evidence index generated: 18 files, 142MB
[✓] manifest.json written with 18 SHA256 hashes
[✓] session_replay.log closed
```

Operator sees a clear all-clear before disconnecting.

---

## 3.11 Inline Offline Cracking Integration

WiFi-Astra is a one-stop tool — the pentester should never need to export files to a separate terminal to crack captured material. After any module that produces crackable output, the controller offers an inline cracking step:

**After D1 (WPA Handshake / PMKID):**
- Prompt: `"Handshake captured. Run offline crack now? [wordlist path or skip]"`
- If wordlist provided: run `hashcat -m 22000` (PMKID) or `hashcat -m 2500` (EAPOL) against it
- Stream hashcat progress into the TUI mission feed in real time
- If cracked: record the PSK as a credential finding with severity `CRITICAL`
- If not cracked: log the attempt, wordlist used, and time spent — still useful evidence

**After D5 (PEAP/MSCHAPv2):**
- Auto-run `asleap` against captured challenge/response pairs immediately after capture
- If `asleap` fails: offer `hashcat -m 5500` (NetNTLMv1) or `-m 5600` (NetNTLMv2) with wordlist
- Cracked NTLM hash recorded as credential finding

**After D3 (WPS):**
- Pixie Dust attack runs inline as the primary path (via `oneshot` or `bully --pixie`)
- PIN brute-force offered as fallback if Pixie Dust fails
- Recovered WPS PIN and derived PSK recorded as credential finding

**After D2 (WEP):**
- `aircrack-ng` key recovery runs inline immediately after sufficient IVs captured
- Recovered WEP key recorded as credential finding

This keeps the full attack lifecycle — capture → crack → finding — inside one tool, matching the usability of airgeddon while producing structured, persisted results that airgeddon cannot.

---

## 5. Implementation Phases

| Phase | Focus | Modules / Files | Priority |
|-------|-------|-----------------|----------|
| 1 | Security hardening | All 46 `modules/*.sh`, `pkg/executor` | P0 |
| 2 | Hardware reliability | `pkg/hw`, `cmd/root.go` | P0 |
| 3 | Dual adapter registry | `pkg/hw`, `internal/controller` | P1 |
| 4 | Evidence system | `internal/controller`, new `internal/evidence` package | P1 |
| 5 | Engagement workflow | `cmd/start.go`, `pkg/prereq`, `internal/module` | P1 |
| 6 | Inline cracking integration | `modules/d1_*.sh`, `modules/d2_*.sh`, `modules/d3_*.sh`, `modules/d5_*.sh` | P1 |
| 7 | Coverage: 6GHz + D1 PMKID | `modules/a1_*.sh`, `modules/d1_*.sh` | P1 |
| 8 | Coverage: D4 WPA3, D5 PEAP, D8 new | `modules/d4_*.sh`, `modules/d5_*.sh`, new `modules/d8_*.sh` | P2 |
| 9 | Coverage: A4 MAC corr, D6 OWE, F3 portal, G4 NAC | Respective modules | P2 |
| 10 | Coverage: A5 Wi-Fi 6 detection | New `modules/a5_*.sh` | P3 |

---

## 6. Success Criteria

The tool is professional when:

1. Running any module against an SSID with special characters (`'`, `;`, `"`, `&`) produces correct output without errors
2. A crash or SIGTERM at any point leaves all interfaces in managed mode on next boot
3. Every completed session contains: structured JSON logs, SHA256 manifest, session replay log, and failure logs for any non-zero exits
4. Attempting to run a module against a network not selected in the scope list is blocked and logged
5. A1 scan discovers networks on all three bands (2.4, 5, 6GHz) when the adapter supports it
6. D5 (PEAP) produces a crackable MSCHAPv2 hash when tested against a vulnerable enterprise network
7. D8 (EAP cert validation) correctly identifies whether a client validates the RADIUS certificate
8. All tools required for the session are surfaced as missing before any test begins
9. After D1 captures a handshake/PMKID, the operator can crack it inline without leaving the tool
10. After D3 WPS capture, Pixie Dust runs inline and the recovered PSK is stored as a finding
