#!/bin/bash

# ------------------------------------------------------------
# initial-set-up.sh - Automated script for the following tasks:
#
#  1. Docker containers clean-up
#  2. SSH key generation
#  3. Docker containers build   
#  4. Docker containers launch
#  5. Infra verification
# ------------------------------------------------------------

# ------------------------------------------------------------
# Exit the script when something goes bad
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
# Defautl flags
# ------------------------------------------------------------
SKIP_BUILD=0
SKIP_COMPILE=0
SKIP_EXPLOIT=0
INTERACTIVE=0

# ------------------------------------------------------------
# Ensure script runs from its own directory
# ------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ------------------------------------------------------------
# Auxiliar script for the infra checkup
# ------------------------------------------------------------
INFRA_CHECK="$SCRIPT_DIR/infra-check.sh"

# ------------------------------------------------------------
# Centralized and configurable paths
# ------------------------------------------------------------
BASE_DIR="$SCRIPT_DIR/.."
ATTACKER_DIR="$BASE_DIR/attacker"
WORM_DIR="$ATTACKER_DIR/worm"
IAC_DIR="$ATTACKER_DIR/iac"
C2_DIR="$ATTACKER_DIR/c2"
KEYS_DIR="$BASE_DIR/../keys"

# ------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build) SKIP_BUILD=1 ; shift ;;
        --skip-compile) SKIP_COMPILE=1 ; shift ;;
        --skip-exploit) SKIP_EXPLOIT=1 ; shift ;;
        --interactive) INTERACTIVE=1 ; shift ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ------------------------------------------------------------
# Logging helpers
# ------------------------------------------------------------
log_info()    { echo -e "${BLUE}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[-]${NC} $1"; }
log_step()    { echo -e "\n${BOLD}${CYAN}=== $1 ===${NC}\n"; }

# ------------------------------------------------------------
# Step 0: Clean previous Docker containers and volumes
# ------------------------------------------------------------
cleanup_docker() {
    log_step "Step 0: Cleaning up previous Docker containers"

    # Detener todos los contenedores definidos en docker-compose
    if docker-compose ps -q | grep -q .; then
        log_info "Stopping existing containers..."
        docker-compose down
        log_success "Existing containers stopped and removed"
    else
        log_info "No existing containers to stop"
    fi
}

# ------------------------------------------------------------
# Step 1: SSH keys set up
# ------------------------------------------------------------
step1_generate_keys() {
    log_step "Step 1: Generating SSH Keys"

    if [ -f "$KEYS_DIR/id_rsa" ] && [ -f "$KEYS_DIR/id_rsa.pub" ]; then
        log_warn "SSH keys already exist, skipping"
        return
    fi

    log_info "Generating SSH keys"
    mkdir -p "$KEYS_DIR"
    ssh-keygen -f "$KEYS_DIR/id_rsa" -N "" -q
    log_success "SSH keys generated in $KEYS_DIR"
}

# ------------------------------------------------------------
# Step 2: Docker build
# ------------------------------------------------------------
step2_build_docker() {
    log_step "Step 2: Building Docker Images"

    if [ "$SKIP_BUILD" -eq 1 ]; then
        log_warn "Skipping Docker build"
        return
    fi

    docker-compose build
    log_success "Docker images built"
}

# ------------------------------------------------------------
# Step 3: Start containers (unchanged logic)
# ------------------------------------------------------------
step3_start_containers() {
    log_step "Step 3: Starting Containers"
    docker-compose up -d
    sleep 5 # Time for set up
}

# ------------------------------------------------------------
# Step 5: Verification (unchanged logic)
# ------------------------------------------------------------
step4_verify() {
    log_step "Step 4: Verification"

    sleep 15

    if [ -f "$INFRA_CHECK" ]; then
        source "$INFRA_CHECK"
        infra_check
    else
        log_warn "Infra check module not found: $INFRA_CHECK"
        exit 1
    fi
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
main() {
    log_step "Setting up the scenario"
    cleanup_docker
    step1_generate_keys
    step2_build_docker
    step3_start_containers
    step4_verify
    log_success "Scenario complete"
}

main
