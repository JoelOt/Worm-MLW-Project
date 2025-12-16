#!/bin/bash
#
# cleanup.sh - Cleanup script for worm propagation scenario
#
# This script cleans up all resources created during the scenario:
# - Stops and removes Docker containers
# - Removes Docker volumes (optional)
# - Cleans up generated files (optional)
#
# IMPORTANT: Everything removed by this script is recreated by:
#   - setup_environment.sh (SSH keys, Docker images/containers, worm binary, dropper)
#   - run_exploit.sh (shadow files are created by the worm during execution)
#
# Usage: ./cleanup.sh [options]
#
# Options:
#   --keep-volumes    Keep Docker volumes (don't remove them)
#   --keep-files      Keep generated files (worm binary, dropper, etc.)
#   --keep-keys       Keep SSH keys
#   --all             Remove everything (containers, volumes, files, keys)
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
KEEP_VOLUMES=0
KEEP_FILES=0
KEEP_KEYS=0
REMOVE_ALL=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --keep-volumes)
            KEEP_VOLUMES=1
            shift
            ;;
        --keep-files)
            KEEP_FILES=1
            shift
            ;;
        --keep-keys)
            KEEP_KEYS=1
            shift
            ;;
        --all)
            REMOVE_ALL=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--keep-volumes] [--keep-files] [--keep-keys] [--all]"
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

# Step 1: Stop and remove Docker containers
step1_cleanup_containers() {
    log_step "Step 1: Stopping and Removing Containers"
    
    if docker-compose ps -q 2>/dev/null | grep -q .; then
        log_info "Stopping Docker containers..."
        docker-compose down 2>/dev/null || true
        
        if [ $REMOVE_ALL -eq 1 ] || [ $KEEP_VOLUMES -eq 0 ]; then
            log_info "Removing containers with volumes..."
            docker-compose down -v 2>/dev/null || true
        else
            log_info "Removing containers (keeping volumes)..."
            docker-compose down 2>/dev/null || true
        fi
        
        log_success "Containers stopped and removed"
    else
        log_warn "No running containers found"
    fi
}

# Step 2: Clean up generated files
step2_cleanup_files() {
    log_step "Step 2: Cleaning Up Generated Files"
    
    if [ $REMOVE_ALL -eq 1 ] || [ $KEEP_FILES -eq 0 ]; then
        # Remove compiled worm binary
        if [ -f "./attacker/worm/worm" ]; then
            log_info "Removing compiled worm binary..."
            rm -f ./attacker/worm/worm
            log_success "Worm binary removed"
        fi
        
        # Remove dropper file
        if [ -f "./attacker/worm/revoke.crl" ]; then
            log_info "Removing dropper file..."
            rm -f ./attacker/worm/revoke.crl
            log_success "Dropper file removed"
        fi
        
        # Remove dropper from C2 public directory
        if [ -f "./attacker/c2/public/revoke.crl" ]; then
            log_info "Removing dropper from C2 server..."
            rm -f ./attacker/c2/public/revoke.crl
            log_success "C2 dropper removed"
        fi
        
        # Clean up exfiltrated shadow files (optional - you might want to keep these)
        if [ -d "./attacker/credentials/new" ]; then
            SHADOW_COUNT=$(find ./attacker/credentials/new -name "shadow_*" -type f 2>/dev/null | wc -l | tr -d ' ')
            if [ "$SHADOW_COUNT" -gt 0 ]; then
                log_info "Found $SHADOW_COUNT exfiltrated shadow file(s)"
                read -p "Remove exfiltrated shadow files? (y/N): " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    rm -f ./attacker/credentials/new/shadow_*
                    rm -f ./attacker/credentials/new/*.crack.log
                    log_success "Shadow files removed"
                else
                    log_info "Keeping shadow files"
                fi
            fi
        fi
        
        # Clean up watcher processed file and crack logs
        if [ -f "./attacker/credentials/.processed_shadows" ]; then
            log_info "Removing watcher processed file..."
            rm -f ./attacker/credentials/.processed_shadows
            log_success "Watcher processed file removed"
        fi
    else
        log_info "Keeping generated files (--keep-files flag)"
    fi
}

# Step 3: Clean up SSH keys
step3_cleanup_keys() {
    log_step "Step 3: Cleaning Up SSH Keys"
    
    if [ $REMOVE_ALL -eq 1 ] || [ $KEEP_KEYS -eq 0 ]; then
        if [ -d "./keys" ]; then
            log_info "Removing SSH keys..."
            rm -rf ./keys
            log_success "SSH keys removed"
        else
            log_warn "No SSH keys directory found"
        fi
    else
        log_info "Keeping SSH keys (--keep-keys flag)"
    fi
}

# Step 4: Clean up Docker images (optional)
step4_cleanup_images() {
    log_step "Step 4: Docker Images Cleanup"
    
    log_info "Docker images are kept by default"
    log_info "To remove images, run manually:"
    echo "  docker-compose down --rmi all"
    echo "  docker rmi \$(docker images -q 'worm-mlw-project*' 2>/dev/null) 2>/dev/null || true"
}

# Main execution
main() {
    echo ""
    echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║${NC}  ${BOLD}Cleanup - Worm Propagation Scenario${NC}                    ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [ $REMOVE_ALL -eq 0 ]; then
        log_info "Cleanup options:"
        [ $KEEP_VOLUMES -eq 1 ] && log_info "  - Keeping Docker volumes"
        [ $KEEP_FILES -eq 1 ] && log_info "  - Keeping generated files"
        [ $KEEP_KEYS -eq 1 ] && log_info "  - Keeping SSH keys"
        echo ""
    fi
    
    step1_cleanup_containers
    step2_cleanup_files
    step3_cleanup_keys
    step4_cleanup_images
    
    echo ""
    log_step "Cleanup Complete!"
    echo ""
    log_success "Cleanup completed successfully"
    echo ""
    log_info "Remaining resources:"
    echo "  - Docker images (if you want to remove them, see Step 4 output above)"
    echo "  - Local files (if --keep-files was used)"
    echo "  - SSH keys (if --keep-keys was used)"
    echo ""
}

# Run main
main

