#!/bin/bash

# ------------------------------------------------------------
# infra_check.sh - Initial infrastructure verification for:
#
#  1. Docker containers existence and state
#  2. Docker network configuration
#  3. SSH keys presence and mounting
#  4. Basic inter-container connectivity
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
# Expected containers
# ------------------------------------------------------------
ATTACKER_CONTAINER="attacker"
C2_CONTAINER="c2"
PMS_SERVER="pms_server"
LOCAL_SITE_1="local_site_1"
LOCAL_SITE_2="local_site_2"
LOCAL_SITE_3="local_site_3"

SPOKE_CONTAINERS=(
    "$LOCAL_SITE_1"
    "$LOCAL_SITE_2"
    "$LOCAL_SITE_3"
)

CONTAINERS=(
    "$ATTACKER_CONTAINER"
    "$C2_CONTAINER"
    "$PMS_SERVER"
    "$LOCAL_SITE_1"
    "$LOCAL_SITE_2"
    "$LOCAL_SITE_3"
)

# ------------------------------------------------------------
# Expected networks
# ------------------------------------------------------------
PUBLIC_NET="worm-mlw-project_public_internet"
PRIVATE_NET="worm-mlw-project_private_vpn"

# ------------------------------------------------------------
# Expected keys
# ------------------------------------------------------------
HOST_KEYS_DIR="../keys"
PMS_SSH_KEY="/home/node/.ssh/id_rsa"

# ------------------------------------------------------------
# Logging helpers (self-contained, safe if main didn't load)
# ------------------------------------------------------------
log_info()    { echo -e "${BLUE}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[-]${NC} $1"; }
log_step()    { echo -e "\n${BOLD}${CYAN}=== $1 ===${NC}\n"; }

# ------------------------------------------------------------
# Internal helper functions
# ------------------------------------------------------------
check_container_exists() {
    docker inspect "$1" >/dev/null 2>&1
}

check_container_running() {
    docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null | grep -q true
}

check_container_network() {
    local container="$1"
    local network="$2"

    docker inspect "$container" \
        | grep -q "\"$network\""
}

# ------------------------------------------------------------
# Step 4.1: Containers verification
# ------------------------------------------------------------
step1_verify_containers() {
    log_step "Step 4.1: Container Presence & State"

    for c in "${CONTAINERS[@]}"; do
        if check_container_exists "$c"; then
            if check_container_running "$c"; then
                log_success "Container running: $c"
            else
                log_error "Container exists but NOT running: $c"
                exit 1
            fi
        else
            log_error "Container not found: $c"
            exit 1
        fi
    done
}

# ------------------------------------------------------------
# Step 4.2: Network verification
# ------------------------------------------------------------
step2_verify_networks() {
    log_step "Step 4.2: Docker Network Configuration"

    for net in "$PUBLIC_NET" "$PRIVATE_NET"; do
        if docker network inspect "$net" >/dev/null 2>&1; then
            log_success "Network exists: $net"
        else
            log_error "Missing Docker network: $net"
            exit 1
        fi
    done

    log_info "Checking container network attachments..."

    check_container_network "$ATTACKER_CONTAINER" "$PUBLIC_NET" && log_success "$ATTACKER_CONTAINER -> public"
    check_container_network "$C2_CONTAINER" "$PUBLIC_NET"       && log_success "$C2_CONTAINER -> public"
    check_container_network "$PMS_SERVER" "$PUBLIC_NET"         && log_success "$PMS_SERVER -> public"
    check_container_network "$PMS_SERVER" "$PRIVATE_NET"        && log_success "$PMS_SERVER -> private"

    for c in "${SPOKE_CONTAINERS[@]}"; do
        check_container_network "$c" "$PRIVATE_NET" \
            && log_success "$c -> private"
    done
}

# ------------------------------------------------------------
# Step 4.3: Keys verification
# ------------------------------------------------------------
step3_verify_ssh_keys() {
    log_step "Step 4.3: SSH Key Verification"

    if [ -f "$HOST_KEYS_DIR/id_rsa" ] && [ -f "$HOST_KEYS_DIR/id_rsa.pub" ]; then
        log_success "SSH keypair exists on host"
    else
        log_error "SSH keypair missing in $HOST_KEYS_DIR"
        exit 1
    fi

    log_info "Checking SSH key mounted in $PMS_SERVER..."

    if docker exec "$PMS_SERVER" test -f "$PMS_SSH_KEY"; then
        log_success "Private SSH key present in $PMS_SERVER"
    else
        log_error "Private SSH key NOT found in $PMS_SERVER"
        exit 1
    fi
}

# ------------------------------------------------------------
# Step 4.4: Connectivity verification
# ------------------------------------------------------------
step4_verify_connectivity() {
    log_step "Step 4.4: Inter-Container Connectivity"

    log_info "Checking C2 reachability from PMS..."

    if docker exec "$PMS_SERVER" ping -c 1 -W 2 "$C2_CONTAINER" >/dev/null 2>&1; then
        log_success "$PMS_SERVER can reach $C2_CONTAINER"
    else
        log_warn "Ping failed (HTTP may still work)"
    fi

    for c in "${SPOKE_CONTAINERS[@]}"; do
        docker exec "$PMS_SERVER" ping -c 1 -W 2 "$c" >/dev/null 2>&1 \
            && log_success "$PMS_SERVER can reach $c"
    done
}

# ------------------------------------------------------------
# Step 4.5: Node.js service exposure (internal perspective)
# ------------------------------------------------------------
step5_verify_node_service_internal() {
    log_step "Step 4.5: Node.js Service Exposure (Internal View)"

    local src_container="attacker"
    local target_host="pms_server"
    local target_port=3000

    log_info "Checking service from inside: $src_container"

    # TCP connectivity check
    if docker exec "$src_container" \
        bash -c "echo > /dev/tcp/$target_host/$target_port" \
        >/dev/null 2>&1; then
        log_success "TCP $target_host:$target_port is reachable"
    else
        log_error "Cannot reach $target_host:$target_port from $src_container"
        exit 1
    fi

    # HTTP responsiveness check
    if docker exec "$src_container" \
        curl -s --max-time 3 "http://$target_host:$target_port" \
        >/dev/null; then
        log_success "HTTP service responding at http://$target_host:$target_port"
    else
        log_warn "TCP open but HTTP not responding"
    fi
}

# ------------------------------------------------------------
# Public entry point
# ------------------------------------------------------------
infra_check() {

    step1_verify_containers
    step2_verify_networks
    step3_verify_ssh_keys
    step4_verify_connectivity
    step5_verify_node_service_internal

    log_step "Infrastructure Check Complete"
    log_success "All infrastructure checks passed"
}
