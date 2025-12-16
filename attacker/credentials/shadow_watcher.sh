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

# Wait a bit for volume mounts to be ready
sleep 2

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
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
            # Use nohup to ensure process continues even if terminal disconnects
            nohup "$HASHRACKER_SCRIPT" "$shadow_file" > "$log_file" 2>&1 &
            CRACKER_PID=$!
            
            log_success "Hash cracking started (PID: $CRACKER_PID, log: $log_file)"
            log_info "Monitor progress with: tail -f $log_file"
            
            # Mark as processed
            processed["$filename"]=1
            echo "$filename" >> "$PROCESSED_FILE"
            
            echo ""
        fi
    done
    
    # Sleep before next check
    sleep 5
done

