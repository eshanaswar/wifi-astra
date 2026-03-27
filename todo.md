# WiFi-Astra Project Roadmap & Status

## ✅ Completed Tasks
- [x] **Phase 1: Engine Daemonization**: Go engine now runs as a persistent daemon via UNIX socket.
- [x] **Phase 2: Database Reliability**: Enabled SQLite WAL mode and structured summary API.
- [x] **Phase 3: Module Decoupling**: All 40+ modules refactored to use explicit argument parsing.
- [x] **Phase 4: E2E Validation**: Headless simulation framework with mock tools is fully operational.
- [x] **UI Hardening**: Framework-wide terminal echo control and buffer purging (no more ^[[C noise).
- [x] **API Security**: Forced 0600 socket permissions and mandatory Astra Token authentication.

## 🚧 Active / High Priority
- [ ] **Hardware Mapping Fix**: Investigate why `wlan0mon` fails PHY mapping despite fallbacks.
- [ ] **Stale Variable Bleed**: Ensure `MONITOR_INTERFACE` is purged more aggressively when switching adapters in Preflight.
- [ ] **Process Heartbeats**: Implement a watchdog in Go to reap orphans if the Bash orchestrator dies unexpectedly.

## 📅 Next Milestones
- [ ] **Reporting V2**: Migrate `lib/report.sh` (Bash strings) to Go `html/template` for cleaner maintainability.
- [ ] **Extended E2E Failures**: Add test cases for tool exit codes > 0 and database lock scenarios.
- [ ] **Advanced Ingestion**: Correlate captured credentials with physical AP infrastructure in the SQLite database automatically.
