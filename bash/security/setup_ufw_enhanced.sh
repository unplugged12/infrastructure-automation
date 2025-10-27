#!/usr/bin/env bash
###############################################################################
# Script Name: setup_ufw.sh
# Description: Enterprise firewall configuration for Ubuntu servers running
#              Docker, Kubernetes, MRCP services, and Nginx. Implements
#              defense-in-depth with separate rules for admin, internal, and
#              public access tiers.
#
# ENHANCED VERSION with:
#   - IP address validation
#   - Backup of existing firewall rules
#   - Rollback capability
#   - Pre-flight checks
#   - Dry-run mode
#   - Comprehensive logging
#
# Usage: sudo ./setup_ufw.sh [OPTIONS]
#
# Options:
#   -h, --help       Display help message
#   --dry-run        Validate configuration without making changes
#   --backup-only    Backup current rules and exit
#   --restore FILE   Restore rules from backup file
#
# Configuration Variables (REQUIRED - Edit before running):
#   ADMIN_V4        Admin IPv4 address/subnet for SSH and management access
#   ADMIN_V6        Admin IPv6 address/subnet (optional, leave empty if unused)
#   INTERNAL_V4     Internal network IPv4 subnet for cluster communication
#   INTERNAL_V6     Internal network IPv6 subnet (optional)
#   SIP_TRUST_V4    Trusted IPv4 subnet for SIP/MRCP traffic
#   SIP_TRUST_V6    Trusted IPv6 subnet for SIP/MRCP (optional)
#
# Examples:
#   # 1. Validate configuration (dry-run)
#   sudo ./setup_ufw.sh --dry-run
#
#   # 2. Backup current rules
#   sudo ./setup_ufw.sh --backup-only
#
#   # 3. Apply new rules
#   sudo ./setup_ufw.sh
#
#   # 4. Restore from backup
#   sudo ./setup_ufw.sh --restore /var/backups/ufw_backup_20250109.tar.gz
#
# Prerequisites:
#   - Root/sudo access required
#   - UFW installed (apt install ufw)
#   - Ubuntu 20.04+ or Debian 11+
#   - Network configuration must be correct before running
#   - Backup access method (console/IPMI) in case of lockout
#
# Exit Codes:
#   0   Success - All firewall rules configured
#   1   General error - UFW command failed
#   2   Validation error - Invalid IP addresses in variables
#   3   Permission denied - Not running as root
#   4   Pre-flight checks failed
#   5   Rollback failed
#
# Risk Level: CRITICAL
#   - Resets entire UFW configuration (existing rules deleted)
#   - Can lock you out if admin IP is incorrect
#   - Affects production network traffic immediately
#   - Modifies access to critical services (SSH, Kubernetes, databases)
#
# WARNING - FIREWALL RESET:
#   - This script runs 'ufw --force reset' which DELETES ALL existing rules
#   - You will lose SSH access if ADMIN_V4 is incorrect
#   - Have console/IPMI access ready before running
#   - Test on non-production system first
#
# Security Considerations:
#   - SSH restricted to admin subnet only (prevents brute force attacks)
#   - Database ports (PostgreSQL, Redis, MongoDB) restricted to internal network
#   - Kubernetes API (6443) restricted to admin access
#   - RabbitMQ management (15672) restricted to admin access
#   - SIP/MRCP ports can be public or restricted based on configuration
#   - All incoming traffic denied by default (whitelist approach)
#
# Ports Opened:
#   Public (0.0.0.0/0):
#     80/tcp      - HTTP (Nginx)
#     443/tcp     - HTTPS (Nginx)
#     554/tcp     - RTSP
#     5060/udp    - SIP
#     5061/tcp    - SIP TLS
#     8085/tcp    - MRCP
#
#   Admin Subnet Only:
#     22/tcp      - SSH
#     6443/tcp    - Kubernetes API
#     15672/tcp   - RabbitMQ Management
#
#   Internal Network Only:
#     5432/tcp    - PostgreSQL
#     6379/tcp    - Redis
#     27016-27017 - MongoDB
#     5672/tcp    - RabbitMQ AMQP
#     25672/tcp   - RabbitMQ Clustering
#     4369/tcp    - RabbitMQ EPMD
#     8181/tcp    - Custom service
#     8443/tcp    - Custom HTTPS
#     10245-10259 - Kubernetes components
#
# Author: System Administrator
# Created: 2024-10-05
# Modified: 2025-01-09
# Version: 2.0.0 (Enhanced)
#
# Notes:
#   - Review public port configuration before running
#   - IPv6 support enabled but optional (leave variables empty to skip)
#   - Script uses --force flags to avoid interactive prompts
#   - Loopback interface (lo) explicitly allowed for local services
#   - Backup files saved to /var/backups/ufw_backup_<timestamp>.tar.gz
#
# Post-Execution Steps:
#   - Verify you can still SSH: ssh user@server-ip
#   - Check rule order: sudo ufw status numbered
#   - Test application connectivity from expected sources
#   - Document firewall configuration in your runbook
###############################################################################

# Strict error handling
set -euo pipefail

###############################################################################
# Configuration - CUSTOMIZE THESE BEFORE RUNNING
###############################################################################

ADMIN_V4="172.16.2.60/32"
ADMIN_V6=""  # leave empty if unused
INTERNAL_V4="172.16.1.0/24"
INTERNAL_V6=""
SIP_TRUST_V4="172.16.1.0/24"
SIP_TRUST_V6=""

###############################################################################
# Script Configuration (Do not modify)
###############################################################################

readonly SCRIPT_NAME="$(basename "$0")"
readonly BACKUP_DIR="/var/backups"
readonly LOG_DIR="/var/log/firewall"
readonly LOG_FILE="${LOG_DIR}/ufw_config_$(date +%Y%m%d_%H%M%S).log"
readonly ROLLBACK_FILE="${BACKUP_DIR}/ufw_backup_$(date +%Y%m%d_%H%M%S).tar.gz"

# Command-line options
DRY_RUN=false
BACKUP_ONLY=false
RESTORE_FILE=""

# Exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_GENERAL_ERROR=1
readonly EXIT_VALIDATION_ERROR=2
readonly EXIT_PERMISSION_ERROR=3
readonly EXIT_PREFLIGHT_FAILED=4
readonly EXIT_ROLLBACK_FAILED=5

###############################################################################
# Helper Functions
###############################################################################

# Display usage
usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Enterprise firewall configuration for Ubuntu servers.

OPTIONS:
    -h, --help           Display this help message
    --dry-run            Validate configuration without making changes
    --backup-only        Backup current rules and exit
    --restore FILE       Restore rules from backup file

EXAMPLES:
    sudo ./$SCRIPT_NAME --dry-run
    sudo ./$SCRIPT_NAME --backup-only
    sudo ./$SCRIPT_NAME
    sudo ./$SCRIPT_NAME --restore /var/backups/ufw_backup_20250109.tar.gz

For more information, see script header comments.
EOF
    exit 0
}

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    # Color codes
    local RED='\033[0;31m'
    local YELLOW='\033[1;33m'
    local GREEN='\033[0;32m'
    local BLUE='\033[0;34m'
    local NC='\033[0m' # No Color

    # Format log message
    local log_msg="[${timestamp}] [${level}] ${message}"

    # Write to log file
    echo "${log_msg}" >> "${LOG_FILE}"

    # Display on console with colors
    case "${level}" in
        INFO)
            echo -e "${BLUE}[INFO]${NC} ${message}"
            ;;
        SUCCESS)
            echo -e "${GREEN}[SUCCESS]${NC} ${message}"
            ;;
        WARNING)
            echo -e "${YELLOW}[WARNING]${NC} ${message}"
            ;;
        ERROR)
            echo -e "${RED}[ERROR]${NC} ${message}" >&2
            ;;
        CRITICAL)
            echo -e "${RED}[CRITICAL]${NC} ${message}" >&2
            ;;
        *)
            echo "${message}"
            ;;
    esac
}

# Error handler
error_exit() {
    local message="$1"
    local exit_code="${2:-$EXIT_GENERAL_ERROR}"

    log "ERROR" "${message}"
    log "ERROR" "Script failed at line ${BASH_LINENO[0]}"
    log "ERROR" "Exiting with code ${exit_code}"

    if [[ -f "${ROLLBACK_FILE}" ]]; then
        log "WARNING" "Rollback available: ${ROLLBACK_FILE}"
        log "WARNING" "Restore with: sudo $SCRIPT_NAME --restore ${ROLLBACK_FILE}"
    fi

    exit "${exit_code}"
}

# Trap errors
trap 'error_exit "Unexpected error occurred" $EXIT_GENERAL_ERROR' ERR

# Validate IPv4 address or CIDR
validate_ipv4() {
    local ip="$1"
    local label="$2"

    # Allow empty values for optional fields
    if [[ -z "$ip" ]]; then
        return 0
    fi

    # IPv4 address validation regex
    local ipv4_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'

    if [[ ! $ip =~ $ipv4_regex ]]; then
        log "ERROR" "Invalid IPv4 address/CIDR for $label: $ip"
        return 1
    fi

    # Validate each octet is 0-255
    local ip_only="${ip%/*}"  # Remove CIDR if present
    IFS='.' read -ra OCTETS <<< "$ip_only"

    for octet in "${OCTETS[@]}"; do
        if [[ $octet -gt 255 ]]; then
            log "ERROR" "Invalid IPv4 octet (>255) in $label: $ip"
            return 1
        fi
    done

    # Validate CIDR range if present
    if [[ $ip =~ / ]]; then
        local cidr="${ip##*/}"
        if [[ $cidr -gt 32 ]] || [[ $cidr -lt 0 ]]; then
            log "ERROR" "Invalid CIDR range in $label: $ip (must be 0-32)"
            return 1
        fi
    fi

    log "SUCCESS" "Valid IPv4 for $label: $ip"
    return 0
}

# Validate IPv6 address or CIDR
validate_ipv6() {
    local ip="$1"
    local label="$2"

    # Allow empty values for optional fields
    if [[ -z "$ip" ]]; then
        return 0
    fi

    # Basic IPv6 validation
    if [[ ! $ip =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})?$ ]]; then
        log "ERROR" "Invalid IPv6 address/CIDR for $label: $ip"
        return 1
    fi

    # Validate CIDR range if present
    if [[ $ip =~ / ]]; then
        local cidr="${ip##*/}"
        if [[ $cidr -gt 128 ]] || [[ $cidr -lt 0 ]]; then
            log "ERROR" "Invalid IPv6 CIDR range in $label: $ip (must be 0-128)"
            return 1
        fi
    fi

    log "SUCCESS" "Valid IPv6 for $label: $ip"
    return 0
}

###############################################################################
# Pre-flight Checks
###############################################################################

preflight_checks() {
    log "INFO" "Starting pre-flight checks..."

    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root" $EXIT_PERMISSION_ERROR
    fi
    log "SUCCESS" "Root privileges confirmed"

    # Check if UFW is installed
    if ! command -v ufw >/dev/null 2>&1; then
        error_exit "UFW is not installed. Install with: apt install ufw" $EXIT_PREFLIGHT_FAILED
    fi
    log "SUCCESS" "UFW is installed"

    # Validate IP addresses
    log "INFO" "Validating IP address configuration..."

    validate_ipv4 "$ADMIN_V4" "ADMIN_V4" || error_exit "Invalid ADMIN_V4 address" $EXIT_VALIDATION_ERROR
    validate_ipv6 "$ADMIN_V6" "ADMIN_V6" || error_exit "Invalid ADMIN_V6 address" $EXIT_VALIDATION_ERROR
    validate_ipv4 "$INTERNAL_V4" "INTERNAL_V4" || error_exit "Invalid INTERNAL_V4 address" $EXIT_VALIDATION_ERROR
    validate_ipv6 "$INTERNAL_V6" "INTERNAL_V6" || error_exit "Invalid INTERNAL_V6 address" $EXIT_VALIDATION_ERROR
    validate_ipv4 "$SIP_TRUST_V4" "SIP_TRUST_V4" || error_exit "Invalid SIP_TRUST_V4 address" $EXIT_VALIDATION_ERROR
    validate_ipv6 "$SIP_TRUST_V6" "SIP_TRUST_V6" || error_exit "Invalid SIP_TRUST_V6 address" $EXIT_VALIDATION_ERROR

    log "SUCCESS" "All IP addresses validated"

    # Check if admin IP is not empty
    if [[ -z "$ADMIN_V4" ]] && [[ -z "$ADMIN_V6" ]]; then
        error_exit "ADMIN_V4 or ADMIN_V6 must be set (SSH will be locked!)" $EXIT_VALIDATION_ERROR
    fi

    # Warn about SSH lockout risk
    log "WARNING" "========================================="
    log "WARNING" "CRITICAL: This will reset all firewall rules"
    log "WARNING" "SSH will be restricted to: $ADMIN_V4 ${ADMIN_V6:+(and $ADMIN_V6)}"
    log "WARNING" "Current SSH connections may be terminated"
    log "WARNING" "========================================="

    # Check current IP
    local current_ip
    current_ip=$(who am i | awk '{print $5}' | tr -d '()')
    if [[ -n "$current_ip" ]]; then
        log "INFO" "Your current IP appears to be: $current_ip"
        log "WARNING" "Ensure this IP is within your ADMIN subnet!"
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "Dry-run mode - exiting without making changes"
        log "SUCCESS" "All validations passed"
        exit 0
    fi

    # Final confirmation
    read -p "Continue with firewall reset? (type 'YES' to confirm): " confirm
    if [[ "$confirm" != "YES" ]]; then
        log "INFO" "Operation cancelled by user"
        exit 0
    fi

    log "SUCCESS" "All pre-flight checks passed"
}

###############################################################################
# Backup and Restore Functions
###############################################################################

backup_ufw() {
    log "INFO" "Backing up current UFW configuration..."

    # Create backup directory
    mkdir -p "${BACKUP_DIR}"
    mkdir -p "${LOG_DIR}"

    # Check if UFW is configured
    if [[ ! -d /etc/ufw ]]; then
        log "WARNING" "No UFW configuration found to backup"
        return 0
    fi

    # Create backup archive
    tar -czf "${ROLLBACK_FILE}" \
        -C / \
        etc/ufw \
        etc/default/ufw \
        2>/dev/null || log "WARNING" "Some files could not be backed up"

    if [[ -f "${ROLLBACK_FILE}" ]]; then
        local backup_size
        backup_size=$(du -h "${ROLLBACK_FILE}" | cut -f1)
        log "SUCCESS" "UFW configuration backed up to: ${ROLLBACK_FILE} (${backup_size})"
    else
        error_exit "Failed to create backup file" $EXIT_GENERAL_ERROR
    fi
}

restore_ufw() {
    local restore_file="$1"

    log "INFO" "Restoring UFW configuration from: $restore_file"

    if [[ ! -f "$restore_file" ]]; then
        error_exit "Backup file not found: $restore_file" $EXIT_GENERAL_ERROR
    fi

    # Disable UFW before restoring
    ufw --force disable || log "WARNING" "Could not disable UFW"

    # Extract backup
    tar -xzf "$restore_file" -C / || error_exit "Failed to extract backup" $EXIT_GENERAL_ERROR

    # Reload UFW
    ufw --force enable || error_exit "Failed to enable UFW after restore" $EXIT_GENERAL_ERROR

    log "SUCCESS" "UFW configuration restored successfully"
    log "INFO" "Current firewall status:"
    ufw status verbose
}

###############################################################################
# Main Firewall Configuration
###############################################################################

configure_firewall() {
    log "INFO" "Starting firewall configuration..."

    # Reset UFW
    log "WARNING" "Resetting UFW (all existing rules will be deleted)..."
    ufw --force reset || error_exit "Failed to reset UFW" $EXIT_GENERAL_ERROR
    log "SUCCESS" "UFW reset complete"

    # Set default policies
    log "INFO" "Setting default policies..."
    ufw default deny incoming || error_exit "Failed to set default deny incoming" $EXIT_GENERAL_ERROR
    ufw default allow outgoing || error_exit "Failed to set default allow outgoing" $EXIT_GENERAL_ERROR
    log "SUCCESS" "Default policies configured"

    # Allow loopback
    log "INFO" "Allowing loopback interface..."
    ufw allow in on lo || error_exit "Failed to allow loopback" $EXIT_GENERAL_ERROR
    log "SUCCESS" "Loopback interface allowed"

    # Public-facing services
    log "INFO" "Configuring public-facing services..."
    ufw allow 80/tcp comment 'HTTP' || log "WARNING" "Failed to allow port 80"
    ufw allow 443/tcp comment 'HTTPS' || log "WARNING" "Failed to allow port 443"
    ufw allow 554/tcp comment 'RTSP' || log "WARNING" "Failed to allow port 554"
    ufw allow 5060/udp comment 'SIP' || log "WARNING" "Failed to allow port 5060"
    ufw allow 5061/tcp comment 'SIP TLS' || log "WARNING" "Failed to allow port 5061"
    ufw allow 8085/tcp comment 'MRCP' || log "WARNING" "Failed to allow port 8085"
    log "SUCCESS" "Public services configured"

    # Admin-only services
    log "INFO" "Configuring admin-only services..."
    ufw allow from "$ADMIN_V4" to any port 22 proto tcp comment 'SSH - Admin IPv4' || \
        error_exit "CRITICAL: Failed to allow SSH from admin IP" $EXIT_GENERAL_ERROR

    if [[ -n "$ADMIN_V6" ]]; then
        ufw allow from "$ADMIN_V6" to any port 22 proto tcp comment 'SSH - Admin IPv6' || \
            log "WARNING" "Failed to allow SSH from admin IPv6"
    fi

    ufw allow from "$ADMIN_V4" to any port 15672 proto tcp comment 'RabbitMQ Mgmt' || \
        log "WARNING" "Failed to allow RabbitMQ management"

    if [[ -n "$ADMIN_V6" ]]; then
        ufw allow from "$ADMIN_V6" to any port 15672 proto tcp comment 'RabbitMQ Mgmt IPv6' || \
            log "WARNING" "Failed to allow RabbitMQ management IPv6"
    fi

    ufw allow from "$ADMIN_V4" to any port 6443 proto tcp comment 'Kubernetes API' || \
        log "WARNING" "Failed to allow Kubernetes API"

    if [[ -n "$ADMIN_V6" ]]; then
        ufw allow from "$ADMIN_V6" to any port 6443 proto tcp comment 'Kubernetes API IPv6' || \
            log "WARNING" "Failed to allow Kubernetes API IPv6"
    fi

    log "SUCCESS" "Admin services configured"

    # Internal-only services
    log "INFO" "Configuring internal-only services..."
    local internal_ports=(5432 6379 27016 27017 5672 25672 4369 8181 8443 \
                          10245 10246 10247 10248 10249 10250 10254 10256 10257 10259)

    for port in "${internal_ports[@]}"; do
        ufw allow from "$INTERNAL_V4" to any port "$port" comment "Internal - Port $port" || \
            log "WARNING" "Failed to allow port $port from internal network"

        if [[ -n "$INTERNAL_V6" ]]; then
            ufw allow from "$INTERNAL_V6" to any port "$port" comment "Internal IPv6 - Port $port" || \
                log "WARNING" "Failed to allow port $port from internal IPv6 network"
        fi
    done

    log "SUCCESS" "Internal services configured"

    # SIP/MRCP trusted peers
    log "INFO" "Configuring SIP/MRCP trusted peer access..."
    local sip_ports=("554/tcp" "5060/udp" "5061/tcp" "8085/tcp")

    for port_proto in "${sip_ports[@]}"; do
        local port="${port_proto%/*}"
        local proto="${port_proto#*/}"

        ufw allow from "$SIP_TRUST_V4" to any port "$port" proto "$proto" comment "SIP Trusted - $port_proto" || \
            log "WARNING" "Failed to allow $port_proto from SIP trusted network"

        if [[ -n "$SIP_TRUST_V6" ]]; then
            ufw allow from "$SIP_TRUST_V6" to any port "$port" proto "$proto" comment "SIP Trusted IPv6 - $port_proto" || \
                log "WARNING" "Failed to allow $port_proto from SIP trusted IPv6 network"
        fi
    done

    log "SUCCESS" "SIP/MRCP trusted peer access configured"

    # Enable UFW
    log "INFO" "Enabling UFW firewall..."
    ufw --force enable || error_exit "Failed to enable UFW" $EXIT_GENERAL_ERROR
    log "SUCCESS" "UFW firewall enabled"

    # Display status
    log "INFO" "Current firewall status:"
    ufw status numbered | tee -a "${LOG_FILE}"

    log "SUCCESS" "Firewall configuration complete"
}

###############################################################################
# Main Script Execution
###############################################################################

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --backup-only)
                BACKUP_ONLY=true
                shift
                ;;
            --restore)
                RESTORE_FILE="$2"
                shift 2
                ;;
            *)
                echo "Unknown option: $1"
                usage
                ;;
        esac
    done

    # Create log directory
    mkdir -p "${LOG_DIR}"

    log "INFO" "========================================="
    log "INFO" "UFW Enterprise Firewall Configuration"
    log "INFO" "Version 2.0.0 (Enhanced)"
    log "INFO" "========================================="

    # Handle restore mode
    if [[ -n "$RESTORE_FILE" ]]; then
        restore_ufw "$RESTORE_FILE"
        exit $EXIT_SUCCESS
    fi

    # Run pre-flight checks
    preflight_checks

    # Backup current configuration
    backup_ufw

    # Handle backup-only mode
    if [[ "$BACKUP_ONLY" == true ]]; then
        log "INFO" "Backup complete, exiting (--backup-only mode)"
        exit $EXIT_SUCCESS
    fi

    # Configure firewall
    configure_firewall

    # Completion message
    log "SUCCESS" "========================================="
    log "SUCCESS" "Firewall configuration complete!"
    log "SUCCESS" "========================================="
    log "INFO" "Log file: ${LOG_FILE}"
    log "INFO" "Backup file: ${ROLLBACK_FILE}"
    log "WARNING" "IMPORTANT: Test SSH access immediately!"
    log "WARNING" "If locked out, restore with:"
    log "WARNING" "  sudo $SCRIPT_NAME --restore ${ROLLBACK_FILE}"
    log "INFO" "========================================="

    exit $EXIT_SUCCESS
}

# Run main function
main "$@"
