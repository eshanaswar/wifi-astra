# Fix Critical Audit Issues Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix fatal and critical issues identified during the real-world security audit to make WiFi-Astra field-ready.

**Architecture:** 
- Patch the Go Core `executor` to support interactive standard input.
- Replace the primitive Python one-liner in the Captive Portal module with a robust POST-handling script.
- Add safety timeouts and dynamic configuration to Bash modules to prevent hangs and improve reliability.

**Tech Stack:** Go, Bash, Python, Linux Networking (`iptables`, `ip`, `dhclient`, `hostapd`).

---

### Task 1: Fix Interactive Stdin Hang in Go Executor

**Files:**
- Modify: `pkg/executor/executor.go`

- [x] **Step 1: Implement minimal code to enable Stdin**
- [x] **Step 2: Verify the change compiles**
- [x] **Step 3: Commit**

---

### Task 2: Robust POST Handling in Captive Portal Phishing

**Files:**
- Modify: `modules/f3_captive_portal.sh`

- [x] **Step 1: Replace Python one-liner with robust handler**
- [x] **Step 2: Commit**

---

### Task 3: Add Safety Timeout to MAC Spoofing DHCP

**Files:**
- Modify: `modules/f4_portal_bypass.sh`

- [x] **Step 1: Add timeout to dhclient**
- [x] **Step 2: Commit**

---

### Task 4: Dynamic Channel Synchronization in WPA3 Downgrade

**Files:**
- Modify: `modules/d7_wpa3_downgrade_active.sh`

- [x] **Step 1: Pass GUEST_CHANNEL to hostapd config**
- [x] **Step 2: Commit**
