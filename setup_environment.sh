#!/bin/bash
#
# setup_environment.sh - Environment preparation script for worm propagation scenario
#
# This script sets up the environment by:
# 1. Generating SSH keys
# 2. Building Docker images
# 3. Starting containers
# 4. Compiling the worm binary
# 5. Building the fileless dropper
#
# Usage: ./setup_environment.sh [options]
#
# Options:
#   --skip-build    Skip Docker build (use existing images)
#   --skip-compile  Skip worm compilation (use existing binary)
#   --interactive   Open interactive log terminals for all containers
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Flags
SKIP_BUILD=0
SKIP_COMPILE=0
INTERACTIVE=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build)
            SKIP_BUILD=1
            shift
            ;;
        --skip-compile)
            SKIP_COMPILE=1
            shift
            ;;
        --interactive)
            INTERACTIVE=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--skip-build] [--skip-compile] [--interactive]"
            exit 1
            ;;
    esac
done

# Helper functions
log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

log_step() {
    echo ""
    echo -e "${BOLD}${CYAN}=== $1 ===${NC}"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking Prerequisites"
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    # Note: gcc is not required on host - compilation happens in Docker container
    
    if ! command -v python3 &> /dev/null; then
        log_error "python3 is not installed (needed for dropper builder)"
        exit 1
    fi
    
    # Check if Docker is available (required for cross-compilation)
    if ! docker info &> /dev/null; then
        log_error "Docker is not running or not accessible"
        log_info "Docker is required for cross-compiling the worm to x86_64 Linux"
        exit 1
    fi
    
    log_success "All prerequisites met"
}

# Step 1: Generate SSH keys
step1_generate_keys() {
    log_step "Step 1: Generating SSH Keys"
    
    if [ -f "./keys/id_rsa" ] && [ -f "./keys/id_rsa.pub" ]; then
        log_warn "SSH keys already exist, skipping generation"
        log_info "To regenerate, delete ./keys/ directory first"
    else
        log_info "Generating SSH keypair..."
        chmod +x setup.sh
        ./setup.sh
        log_success "SSH keys generated in ./keys/"
    fi
}

# Step 2: Build Docker images
step2_build_docker() {
    log_step "Step 2: Building Docker Images"
    
    if [ $SKIP_BUILD -eq 1 ]; then
        log_warn "Skipping Docker build (--skip-build flag)"
        return
    fi
    
    log_info "Building Docker images (this may take a few minutes)..."
    docker-compose build 2>&1 | grep -E "(Step|Successfully|ERROR)" || true
    
    log_success "Docker images built successfully"
}

# Step 3: Start containers
step3_start_containers() {
    log_step "Step 3: Starting Containers"
    
    log_info "Starting Docker containers..."
    docker-compose up -d
    
    log_info "Waiting for services to be ready..."
    sleep 5
    
    # Check if containers are running
    if docker-compose ps | grep -q "Up"; then
        log_success "Containers started successfully"
    else
        log_error "Some containers failed to start"
        docker-compose ps
        exit 1
    fi
    
    log_info "Waiting for Next.js app to initialize (this may take 30-60 seconds)..."
    log_info "Checking if pms_server is ready..."
    
    MAX_WAIT=120
    WAITED=0
    while [ $WAITED -lt $MAX_WAIT ]; do
        if curl -s http://localhost:3000 > /dev/null 2>&1; then
            log_success "pms_server is ready!"
            break
        fi
        echo -n "."
        sleep 2
        WAITED=$((WAITED + 2))
    done
    
    if [ $WAITED -ge $MAX_WAIT ]; then
        log_warn "pms_server did not become ready in time, but continuing..."
    fi
}

# Step 4: Compile worm
step4_compile_worm() {
    log_step "Step 4: Compiling Worm (x86_64 Linux)"
    
    if [ $SKIP_COMPILE -eq 1 ]; then
        log_warn "Skipping worm compilation (--skip-compile flag)"
        if [ ! -f "./attacker/worm/worm" ]; then
            log_error "Worm binary not found! Cannot continue without compilation."
            exit 1
        fi
        # Verify it's x86_64 Linux binary
        if command -v file &> /dev/null; then
            FILE_OUTPUT=$(file ./attacker/worm/worm 2>/dev/null || echo "")
            if echo "$FILE_OUTPUT" | grep -q "x86-64\|x86_64"; then
                log_success "Existing binary is x86_64 Linux"
            else
                log_warn "Existing binary may not be x86_64 Linux: $FILE_OUTPUT"
            fi
        fi
        return
    fi
    
    cd attacker/worm
    
    log_info "Compiling worm binary in x86_64 Linux container..."
    log_info "Using Docker to cross-compile for Linux x86_64 architecture"
    log_info "This ensures compatibility even on ARM Macs (M1/M2/M3/M4)"
    
    # Use gcc:13 image with --platform linux/amd64 for x86_64 compilation
    # Using Debian-based image for better glibc compatibility
    docker run --rm --platform linux/amd64 \
        -v "$PWD":/src -w /src \
        gcc:13 \
        gcc -static -s -Wall -Wextra -std=c11 -O2 -pipe -o worm worm.c
    
    if [ ! -f "worm" ]; then
        log_error "Compilation failed!"
        cd ../..
        exit 1
    fi
    
    # Verify it's x86_64 Linux binary
    log_info "Verifying binary architecture..."
    if command -v file &> /dev/null; then
        FILE_OUTPUT=$(file worm 2>/dev/null || echo "")
        if echo "$FILE_OUTPUT" | grep -q "x86-64\|x86_64"; then
            log_success "Binary verified: x86_64 Linux ELF"
            log_info "Architecture: $FILE_OUTPUT"
        else
            log_warn "Binary architecture check: $FILE_OUTPUT"
            log_warn "Expected x86_64 Linux, but continuing anyway..."
        fi
    else
        log_warn "Cannot verify binary architecture (file command not available)"
    fi
    
    WORM_SIZE=$(stat -f%z worm 2>/dev/null || stat -c%s worm 2>/dev/null)
    log_success "Worm compiled successfully (${WORM_SIZE} bytes, x86_64 Linux)"
    
    cd ../..
}

# Step 5: Build dropper
step5_build_dropper() {
    log_step "Step 5: Building Fileless Dropper"
    
    cd attacker/worm
    
    if [ ! -f "worm" ]; then
        log_error "Worm binary not found! Run compilation first."
        cd ../..
        exit 1
    fi
    
    log_info "Building dropper (CRL file)..."
    python3 build-dropper.py
    
    if [ ! -f "revoke.crl" ]; then
        log_error "Dropper build failed!"
        cd ../..
        exit 1
    fi
    
    CRL_SIZE=$(stat -f%z revoke.crl 2>/dev/null || stat -c%s revoke.crl 2>/dev/null)
    log_success "Dropper built successfully (${CRL_SIZE} bytes)"
    
    log_info "Copying revoke.crl to C2 server..."
    mkdir -p ../c2/public
    cp -f revoke.crl ../c2/public/revoke.crl
    
    log_success "Dropper deployed to C2 server"
    
    cd ../..
}

# Get display name for a container (bash 3.2 compatible)
get_display_name() {
    local container=$1
    case "$container" in
        "attacker")     echo "ATTACKER (Red Team)" ;;
        "c2")           echo "C2 SERVER (Command & Control)" ;;
        "pms_server")   echo "PMS SERVER (Target Application)" ;;
        "local_site_1") echo "LOCAL SITE 1 (Victim)" ;;
        "local_site_2") echo "LOCAL SITE 2 (Victim)" ;;
        "local_site_3") echo "LOCAL SITE 3 (Victim)" ;;
        *)              echo "$container" ;;
    esac
}

# Open interactive log terminals for each container
open_interactive_logs() {
    log_info "Opening interactive log terminals for all containers..."
    
    # Container names (bash 3.2 compatible - using array instead of associative array)
    containers=("attacker" "c2" "pms_server" "local_site_1" "local_site_2" "local_site_3")
    
    # Clean up any old temp scripts from previous runs (before we start creating new ones)
    if [[ "$(uname)" == "Darwin" ]]; then
        rm -f /tmp/docker-logs-*.sh 2>/dev/null || true
    fi
    
    # Check if we're on macOS
    if [[ "$(uname)" == "Darwin" ]]; then
        # Use osascript to open new Terminal windows on macOS
        for container in "${containers[@]}"; do
            display_name=$(get_display_name "$container")
            
            # Create a temporary script file for this container
            # Clean up any old temp files for this container first (handle glob expansion safely)
            rm -f /tmp/docker-logs-${container}-*.sh 2>/dev/null || true
            # Use mktemp with a unique pattern for each container
            temp_script=$(mktemp "/tmp/docker-logs-${container}-XXXXXX.sh" 2>/dev/null)
            if [ -z "$temp_script" ] || [ ! -f "$temp_script" ]; then
                # Fallback: use timestamp-based naming if mktemp fails
                temp_script="/tmp/docker-logs-${container}-$$.sh"
            fi
            # Get absolute path to docker (in case PATH isn't set in new terminal)
            docker_path=$(which docker || echo "docker")
            # Get current directory for context
            current_dir=$(pwd)
            cat > "$temp_script" <<SCRIPTEOF
#!/bin/bash
# Ensure we're in a proper shell environment with docker in PATH
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:\$PATH"
cd "${current_dir}"

clear
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  ${display_name}"
echo "║  Container: ${container}"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Check if container is running
if ! ${docker_path} ps --format "{{.Names}}" | grep -q "^${container}\$"; then
    echo "ERROR: Container '${container}' is not running!"
    echo ""
    echo "Running containers:"
    ${docker_path} ps --format "{{.Names}}"
    echo ""
    echo "Press Enter to close this window..."
    read
    exit 1
fi

# Determine what logs to show based on container type
if echo "${container}" | grep -q "local_site\|pms_server"; then
    # For local_site and pms_server containers: show worm log file
    if [ "${container}" = "pms_server" ]; then
        echo "Container type: PMS Server (showing worm activity log)"
    else
        echo "Container type: Victim (showing worm activity log)"
    fi
    echo ""
    echo "Showing worm log file (/tmp/worm.log) if it exists:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if ${docker_path} exec ${container} test -f /tmp/worm.log 2>/dev/null; then
        ${docker_path} exec ${container} tail -50 /tmp/worm.log 2>&1 || echo "(log file exists but couldn't read)"
    else
        echo "(No worm log file yet - worm hasn't run on this container)"
    fi
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Following worm log file (Press Ctrl+C to stop):"
    echo ""
    # Poll and tail the log file
    while true; do
        if ${docker_path} exec ${container} test -f /tmp/worm.log 2>/dev/null; then
            ${docker_path} exec ${container} tail -f /tmp/worm.log 2>&1
            break
        else
            echo "Waiting for worm log file to appear..."
            sleep 2
        fi
    done
elif [ "${container}" = "attacker" ]; then
    # For attacker container: show watcher log and hashcracker logs
    echo "Container type: Attacker (showing hash cracking activity)"
    echo ""
    echo "Hash cracking watcher log (/tmp/watcher.log):"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if ${docker_path} exec ${container} test -f /tmp/watcher.log 2>/dev/null; then
        ${docker_path} exec ${container} tail -50 /tmp/watcher.log 2>&1
    else
        echo "(Watcher log not found - watcher may not be running)"
        echo "(Start it with: docker exec -d attacker bash /attacker/credentials/shadow_watcher.sh)"
    fi
    echo ""
    echo "Recent hash crack logs:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    CRACK_LOGS=$(${docker_path} exec ${container} find /attacker/credentials/new -name "*.crack.log" -type f 2>/dev/null)
    if [ -n "$CRACK_LOGS" ]; then
        echo "$CRACK_LOGS" | while read logfile; do
            echo ""
            echo "=== $(basename "$logfile") ==="
            ${docker_path} exec ${container} tail -20 "$logfile" 2>&1
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        done
    else
        echo "(No crack logs found yet - waiting for shadow files to be cracked)"
    fi
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Following logs (watcher + crack logs) - Press Ctrl+C to stop:"
    echo ""
    # Use multitail or combine logs: show both watcher log and all crack logs
    ${docker_path} exec ${container} sh -c '
        # Start background process to tail all crack logs and show updates
        (
            while true; do
                sleep 5
                for log in /attacker/credentials/new/*.crack.log; do
                    if [ -f "$log" ]; then
                        # Check if file was modified in last 15 seconds
                        mtime=$(stat -c %Y "$log" 2>/dev/null || stat -f %m "$log" 2>/dev/null || echo 0)
                        now=$(date +%s)
                        if [ $((now - mtime)) -lt 15 ]; then
                            echo ""
                            echo "[CRACK LOG UPDATE: $(basename $log)]"
                            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                            tail -10 "$log" 2>/dev/null | tail -5
                            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                        fi
                    fi
                done
            done
        ) &
        CRACK_TAIL_PID=$!
        
        # Follow watcher log (primary output)
        if [ -f /tmp/watcher.log ]; then
            tail -f /tmp/watcher.log 2>&1
        else
            echo "Waiting for watcher log to appear..."
            while [ ! -f /tmp/watcher.log ]; do
                sleep 1
            done
            tail -f /tmp/watcher.log 2>&1
        fi
        
        # Cleanup
        kill $CRACK_TAIL_PID 2>/dev/null || true
    ' 2>&1
else
    # For c2 and pms_server: show docker logs (these produce good stdout logs)
    echo "Showing last 50 lines of existing logs:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    ${docker_path} logs --tail 50 ${container} 2>&1
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Following new logs (Press Ctrl+C to stop following, then close window):"
    echo ""
    ${docker_path} logs -f --since 0s ${container} 2>&1
fi
SCRIPTEOF
            chmod +x "$temp_script"
            
            # Open new Terminal window with the script (using full path)
            osascript -e "tell application \"Terminal\" to do script \"$temp_script\"" > /dev/null 2>&1
            
            # Small delay to avoid overwhelming the system
            sleep 0.3
        done
    else
        # Fallback for Linux: use tmux if available, otherwise just print commands
        if command -v tmux &> /dev/null; then
            log_info "Using tmux to show logs (attach with: tmux attach -t docker-logs)"
            
            # Create a new tmux session
            tmux new-session -d -s docker-logs -n "docker-logs"
            
            # Create panes for each container
            pane_index=0
            for container in "${containers[@]}"; do
                display_name=$(get_display_name "$container")
                
                # Determine command based on container type
                if echo "${container}" | grep -q "local_site\|pms_server"; then
                    # For local_site and pms_server containers, tail the worm log file
                    cmd="clear; echo '╔═══════════════════════════════════════════════════════════╗'; echo '║  ${display_name}'; echo '║  Container: ${container}'; echo '╚═══════════════════════════════════════════════════════════╝'; echo ''; echo 'Showing worm log (/tmp/worm.log):'; echo ''; if docker exec ${container} test -f /tmp/worm.log 2>/dev/null; then docker exec ${container} tail -50 /tmp/worm.log; else echo '(No worm log file yet)'; fi; echo ''; echo '--- Following worm log ---'; while ! docker exec ${container} test -f /tmp/worm.log 2>/dev/null; do sleep 1; done; docker exec ${container} tail -f /tmp/worm.log"
                elif [ "${container}" = "attacker" ]; then
                    # For attacker, show watcher and crack logs
                    cmd="clear; echo '╔═══════════════════════════════════════════════════════════╗'; echo '║  ${display_name}'; echo '║  Container: ${container}'; echo '╚═══════════════════════════════════════════════════════════╝'; echo ''; echo 'Hash cracking watcher log (/tmp/watcher.log):'; if docker exec ${container} test -f /tmp/watcher.log 2>/dev/null; then docker exec ${container} tail -50 /tmp/watcher.log; else echo '(No watcher log yet - start watcher with: docker exec -d attacker bash /attacker/credentials/shadow_watcher.sh)'; fi; echo ''; echo 'Recent crack logs:'; docker exec ${container} find /attacker/credentials/new -name '*.crack.log' -exec sh -c 'echo \"\" && echo \"=== {} ===\" && tail -10 \"\$1\"' _ {} \; 2>/dev/null | head -100; echo ''; echo '--- Following watcher log (Ctrl+C to stop) ---'; if docker exec ${container} test -f /tmp/watcher.log 2>/dev/null; then docker exec ${container} tail -f /tmp/watcher.log; else echo 'Waiting for watcher log...'; while ! docker exec ${container} test -f /tmp/watcher.log 2>/dev/null; do sleep 1; done; docker exec ${container} tail -f /tmp/watcher.log; fi"
                else
                    # For c2 and pms_server, use docker logs
                    cmd="clear; echo '╔═══════════════════════════════════════════════════════════╗'; echo '║  ${display_name}'; echo '║  Container: ${container}'; echo '╚═══════════════════════════════════════════════════════════╝'; echo ''; echo 'Showing last 50 lines, then following live logs...'; echo ''; docker logs --tail 50 ${container}; echo ''; echo '--- Following new logs ---'; docker logs -f ${container}"
                fi
                
                if [ $pane_index -eq 0 ]; then
                    # First pane - send command directly
                    tmux send-keys -t docker-logs:0 "$cmd" C-m
                else
                    # Split pane horizontally and send command to new pane
                    tmux split-window -t docker-logs:0 -h
                    tmux send-keys -t docker-logs:0 "$cmd" C-m
                    tmux select-layout -t docker-logs:0 tiled
                fi
                ((pane_index++))
            done
            
            # Attach to the session
            tmux attach -t docker-logs
        else
            # No tmux - just print the commands
            log_warn "tmux not found. Run these commands manually to view logs:"
            echo ""
            for container in "${containers[@]}"; do
                display_name=$(get_display_name "$container")
                echo "  # ${display_name}:"
                echo "  docker logs -f ${container}"
                echo ""
            done
        fi
    fi
    
    log_success "Interactive log terminals opened!"
}

# Main execution
main() {
    echo ""
    echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║${NC}  ${BOLD}Environment Setup - Worm Propagation Scenario${NC}          ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    check_prerequisites
    step1_generate_keys
    step2_build_docker
    step3_start_containers
    step4_compile_worm
    step5_build_dropper
    
    echo ""
    log_step "Environment Setup Complete!"
    echo ""
    log_success "All environment preparation steps completed"
    echo ""
    log_info "Next steps:"
    echo "  ./run_exploit.sh              - Run the exploit and verify infection"
    echo "  ./run_exploit.sh --interactive - Run exploit with confirmation prompt"
    echo ""
    log_info "Useful commands:"
    echo "  docker-compose ps          - Check container status"
    echo "  docker-compose logs        - View logs"
    echo "  docker-compose down        - Stop all containers"
    echo ""
    
    # Open interactive logs if flag is set
    if [ "$INTERACTIVE" -eq 1 ]; then
        open_interactive_logs
    fi
}

# Run main
main

