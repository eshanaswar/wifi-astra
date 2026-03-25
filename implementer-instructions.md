# Task 01-01-02: Harden Session Persistence (Atomic + Backups)

**Goal:** Refactor session management to include rolling backups (.bak) and interactive corruption recovery.

**Files:**
- Modify: `lib/session.sh`
- Test: `tests/test_session.py`

**Implementation Steps:**
1. **Update `save_session_state` in `lib/session.sh`:**
   - Before moving `.tmp` to `session.state`, copy the current `session.state` to `session.state.bak`.
   - Validate the `state_json` (or the `.tmp` file) with `${TOOL_PATHS[jq]} -e .` before any movement.
2. **Enhance `load_session` in `lib/session.sh`:**
   - If `session.state` is missing or corrupt (invalid JSON):
     - Check for `session.state.bak`.
     - If `.bak` exists and is valid, prompt the user: "Session state is corrupt. Recover from backup? (y/N)".
     - If the user says "y", restore the backup.
     - Otherwise, initialize a fresh state (preserving the SESSION_ID and directory structure).
3. **Address Reviewer Suggestions:**
   - Call `finalize_evidence_permissions` at the end of `init_new_session` to ensure the new session directory is owned by the correct user.
   - Ensure `validate_json` correctly handles cases where `jq` might be missing (use `run_tool jq` or similar guard).
4. **Update `tests/test_session.py`:**
   - Add a test for `.bak` creation.
   - Add a test for corruption recovery (mocking the user prompt).

**Constraints:**
- Use `set -uo pipefail`.
- Use `run_tool jq` or ensure `TOOL_PATHS[jq]` is checked.
- Use the existing TUI conventions for prompts (e.g., `read -rep`).

**Verification:**
- Run `bash -n lib/session.sh`.
- Run the updated pytest suite.
- Manually test the corruption recovery prompt by purposefully mangling `session.state`.

**Context:**
- `finalize_evidence_permissions` is defined in `lib/evidence.sh`.
- `get_or_request_param` is in `lib/ui_helpers.sh`.
- `TOOL_PATHS[jq]` is expected to be set (usually to `jq`).
