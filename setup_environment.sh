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
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--skip-build] [--skip-compile]"
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
}

# Run main
main

