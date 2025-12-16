#!/bin/bash
#
# shadow_watcher.sh - Automatically crack new shadow files as they arrive
#
# This script runs in a loop, monitoring /attacker/credentials/new/ for new
# shadow files and automatically runs hashcracker.sh on them.
#

SHADOW_DIR="/attacker/credentials/new"
HASHRACKER_SCRIPT="/attacker/credentials/hashcracker.sh"
PROCESSED_FILE="/attacker/credentials/.processed_shadows"
WATCHER_LOG="/tmp/watcher.log"

# Ensure log file exists and is writable
touch "$WATCHER_LOG" 2>/dev/null || {
    echo "ERROR: Cannot create watcher log file: $WATCHER_LOG" >&2
    WATCHER_LOG="/dev/stdout"  # Fallback to stdout if /tmp is not writable
}

# Wait a bit for volume mounts to be ready
sleep 2

# Function to log to both stdout and log file
log_with_file() {
    local message="$1"
    echo "$message"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$WATCHER_LOG"
}

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    local msg="${BLUE}[*]${NC} $1"
    echo -e "$msg"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1" >> "$WATCHER_LOG"
}

log_success() {
    local msg="${GREEN}[+]${NC} $1"
    echo -e "$msg"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $1" >> "$WATCHER_LOG"
}

log_warn() {
    local msg="${YELLOW}[!]${NC} $1"
    echo -e "$msg"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] $1" >> "$WATCHER_LOG"
}

# Create processed file if it doesn't exist
touch "$PROCESSED_FILE"

# Initialize processed list from file
declare -A processed
while IFS= read -r line; do
    [ -n "$line" ] && processed["$line"]=1
done < "$PROCESSED_FILE"

log_info "Shadow file watcher started"
log_info "Monitoring directory: $SHADOW_DIR"
log_info "Hashcracker script: $HASHRACKER_SCRIPT"
log_info "Processed file: $PROCESSED_FILE"
log_info "Already processed: ${#processed[@]} file(s)"
echo ""

# Main loop
while true; do
    # Check if shadow directory exists
    if [ ! -d "$SHADOW_DIR" ]; then
        log_warn "Shadow directory does not exist: $SHADOW_DIR"
        sleep 5
        continue
    fi
    
    # Find all shadow files (exclude .crack.log files and .log files)
    for shadow_file in "$SHADOW_DIR"/shadow_*; do
        # Skip if no files match the pattern
        [ ! -f "$shadow_file" ] && continue
        
        # Skip log files and processed files
        if [[ "$shadow_file" == *.log ]] || [[ "$shadow_file" == *.crack.log ]]; then
            continue
        fi
        
        # Get just the filename
        filename=$(basename "$shadow_file")
        
        # Check if we've already processed this file
        if [ -z "${processed[$filename]}" ]; then
            log_info "Found new shadow file: $filename"
            
            # Check if hashcracker script exists
            if [ ! -f "$HASHRACKER_SCRIPT" ]; then
                log_warn "Hashcracker script not found: $HASHRACKER_SCRIPT"
                continue
            fi
            
            # Make sure script is executable
            chmod +x "$HASHRACKER_SCRIPT" 2>/dev/null
            
            # Run hashcracker on the new shadow file
            log_info "Starting hash cracking for: $filename"
            echo "---------------------------------------------------"
            
            # Run hashcracker in background so we can continue monitoring
            # Store output in a log file
            log_file="${shadow_file}.crack.log"
            # Ensure log file exists and is empty initially
            > "$log_file"
            
            log_success "Hash cracking started for: $filename (will log to: $log_file)"
            
            # Run hashcracker script and redirect all output to log file
            # Use stdbuf if available for unbuffered output
            if command -v stdbuf >/dev/null 2>&1; then
                stdbuf -oL -eL bash "$HASHRACKER_SCRIPT" "$shadow_file" >> "$log_file" 2>&1 &
            else
                # Fallback: just run directly with output redirection
                bash "$HASHRACKER_SCRIPT" "$shadow_file" >> "$log_file" 2>&1 &
            fi
            CRACKER_PID=$!
            
            # Verify the process started
            sleep 1
            if ! kill -0 $CRACKER_PID 2>/dev/null; then
                log_warn "Hash cracker process died immediately (PID: $CRACKER_PID)"
                log_warn "Check log file for errors: $log_file"
            fi
            
            log_info "Hash cracker PID: $CRACKER_PID, log file: $log_file"
            
            # Start a background process to monitor the crack log and forward updates to watcher log
            (
                sleep 2  # Give cracker a moment to start writing
                LAST_SIZE=0
                while kill -0 $CRACKER_PID 2>/dev/null; do
                    if [ -f "$log_file" ]; then
                        CURRENT_SIZE=$(stat -c %s "$log_file" 2>/dev/null || stat -f %z "$log_file" 2>/dev/null || echo 0)
                        if [ "$CURRENT_SIZE" -gt "$LAST_SIZE" ]; then
                            # New content added - show it in watcher log
                            NEW_LINES=$(tail -c +$((LAST_SIZE + 1)) "$log_file" 2>/dev/null)
                            if [ -n "$NEW_LINES" ]; then
                                echo "$NEW_LINES" | while IFS= read -r line; do
                                    echo "$(date '+%Y-%m-%d %H:%M:%S') [CRACK:$filename] $line" >> "$WATCHER_LOG"
                                done
                            fi
                            LAST_SIZE=$CURRENT_SIZE
                        fi
                    fi
                    sleep 3  # Check every 3 seconds
                done
                # Final update when cracker finishes
                if [ -f "$log_file" ]; then
                    echo "$(date '+%Y-%m-%d %H:%M:%S') [CRACK:$filename] Process finished, final output:" >> "$WATCHER_LOG"
                    tail -20 "$log_file" 2>/dev/null | while IFS= read -r line; do
                        echo "$(date '+%Y-%m-%d %H:%M:%S') [CRACK:$filename] $line" >> "$WATCHER_LOG"
                    done
                fi
                echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Hash cracking completed for: $filename" >> "$WATCHER_LOG"
            ) &
            
            log_info "Monitor progress: tail -f $log_file (updates also shown in watcher log)"
            
            # Mark as processed
            processed["$filename"]=1
            echo "$filename" >> "$PROCESSED_FILE"
            
            echo ""
        fi
    done
    
    # Sleep before next check
    sleep 5
done

