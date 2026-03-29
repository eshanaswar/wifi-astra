#!/usr/bin/env bash
# MODULE_META
# NAME="Reaper Test Module"
# CATEGORY="Z"
# DEPS="none"
# CRITICAL="no"
# TOOLS="none"
# DESC="Test the process reaper"
# REQS="none"

set -euo pipefail

echo "Starting child process..."
# Spawn a child that sleeps. We use sleep 3600 to ensure it's still alive when we check.
sleep 3600 &
CHILD_PID=$!
echo "REAPER_TEST_CHILD_PID=$CHILD_PID"
echo "REAPER_TEST_PARENT_PID=$$"

# Log to a file we can check later
echo "$CHILD_PID" > /tmp/reaper_test_child.pid

# Keep running until killed
while true; do
    sleep 1
done
