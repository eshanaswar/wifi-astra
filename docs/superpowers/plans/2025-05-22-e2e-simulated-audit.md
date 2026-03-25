# E2E Simulated Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish a reliable end-to-end (E2E) testing framework that allows verifying the entire audit lifecycle (Discovery -> Attack -> Reporting) without requiring physical wireless hardware.

**Architecture:** Use a mock tool suite that overrides the `PATH` to intercept calls to wireless tools (airmon-ng, airodump-ng, etc.) and return static, valid data. The orchestrator will run `wifi-astra.sh` in headless mode and verify the resulting session state and reports.

**Tech Stack:** Bash, Mocking, E2E Testing

---

### Task 1: Create Mock Data and Tools

**Files:**
- Create: `tests/mocks/data/airodump_mock.csv`
- Create: `tests/mocks/data/dummy_handshake.cap`
- Create: `tests/mocks/mock_tools.sh`

- [ ] **Step 1: Create mock data directory and files**
- [ ] **Step 2: Implement mock_tools.sh to handle core binaries**
- [ ] **Step 3: Verify mock_tools.sh returns expected output for a few tools**

### Task 2: Implement E2E Orchestrator

**Files:**
- Create: `tests/e2e_simulated_audit.sh`

- [ ] **Step 1: Create e2e_simulated_audit.sh with PATH override and headless config**
- [ ] **Step 2: Implement validation logic (exit codes, session state, report existence)**
- [ ] **Step 3: Ensure the script handles cleanup of temporary mock binaries**

### Task 3: Execution and Verification

- [ ] **Step 1: Run the E2E test and verify it passes**
- [ ] **Step 2: Check evidence_manifest.json and reports**
- [ ] **Step 3: Verify no system state was affected (e.g., monitor mode interfaces left behind)**

---
