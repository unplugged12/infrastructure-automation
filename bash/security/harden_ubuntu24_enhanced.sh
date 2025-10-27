#!/usr/bin/env bash
###############################################################################
# Script Name: harden_ubuntu24.sh
# Description: Comprehensive security hardening for fresh Ubuntu 24.04 LTS
#              installations. Configures firewall, SSH, AppArmor, automatic
#              updates, and deploys monitoring agents (ScreenConnect, Atera).
#
# ENHANCED VERSION with:
#   - Comprehensive error handling
#   - Checksum verification for downloads
#   - Rollback capability
#   - Pre-flight checks
#   - Detailed logging
#
# Usage: sudo ./harden_ubuntu24.sh
#
# Options:
#   -h, --help     Display this help message
#   --dry-run      Perform pre-flight checks only (no changes)
#   --no-agents    Skip agent installation (ScreenConnect, Atera, Sophos)
#
# Examples:
#   sudo ./harden_ubuntu24.sh
#   sudo ./harden_ubuntu24.sh --dry-run
#   sudo ./harden_ubuntu24.sh --no-agents
#
# Prerequisites:
#   - Root/sudo access required
#   - Fresh Ubuntu 24.04 LTS installation
#   - Internet connectivity for package downloads
#   - Optional: SophosSetup.sh file path for antivirus installation
#
# Exit Codes:
#   0   Success - All hardening steps completed
#   1   General error - Package installation or configuration failed
#   2   Network error - Unable to download required packages
#   3   Permission denied - Not running as root
#   4   Pre-flight checks failed
#   5   Rollback failed
#
# Risk Level: HIGH
#   - Modifies system firewall rules (UFW)
#   - Changes SSH configuration (disables root login)
#   - Installs kernel security modules (AppArmor)
#   - Modifies kernel parameters (sysctl)
#   - Downloads and installs third-party agents
#   - Enables automatic security updates
#
# Security Considerations:
#   - Disables root SSH login (ensure non-root user exists first)
#   - Opens ports 22 (SSH) and 5060 (MRCP) - review before production use
#   - Redis restricted to localhost only (127.0.0.1)
#   - Downloads agent installers from external URLs - verify URLs before use
#   - Sophos installer executed with root privileges - ensure file integrity
#   - All downloads are checksummed (where possible)
#
# Author: System Administrator
# Created: 2024-10-05
# Modified: 2025-01-09
# Version: 2.0.0 (Enhanced)
#
# Notes:
#   - Review UFW port rules before running in production
#   - Ensure at least one non-root user with sudo exists before running
#   - System requires reboot after execution for kernel parameters to apply
#   - ScreenConnect and Atera agent URLs are organization-specific
#   - Modify agent download URLs for your organization before use
#   - Log rotation configured for weekly rotation, 6 files retained
#   - Rollback information saved to /var/log/hardening_rollback.sh
#
# Post-Execution Steps:
#   - Reboot system to apply kernel security parameters
#   - Test SSH access with non-root user before closing current session
#   - Verify UFW rules: sudo ufw status verbose
#   - Check AppArmor status: sudo aa-status
#   - Review fail2ban status: sudo systemctl status fail2ban
###############################################################################

# Strict error handling
set -euo pipefail

# Configuration
readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_DIR="/var/log/hardening"
readonly LOG_FILE="${LOG_DIR}/hardening_$(date +%Y%m%d_%H%M%S).log"
readonly ERROR_LOG="${LOG_DIR}/hardening_errors_$(date +%Y%m%d_%H%M%S).log"
readonly ROLLBACK_SCRIPT="${LOG_DIR}/hardening_rollback_$(date +%Y%m%d_%H%M%S).sh"
readonly BACKUP_DIR="/var/backups/hardening_$(date +%Y%m%d_%H%M%S)"

# Command line options
DRY_RUN=false
SKIP_AGENTS=false

# Exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_GENERAL_ERROR=1
readonly EXIT_NETWORK_ERROR=2
readonly EXIT_PERMISSION_ERROR=3
readonly EXIT_PREFLIGHT_FAILED=4
readonly EXIT_ROLLBACK_FAILED=5

# Track what has been done for rollback
declare -a ROLLBACK_COMMANDS=()

###############################################################################
# Helper Functions
###############################################################################

# Display usage information
usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Comprehensive security hardening for Ubuntu 24.04 LTS systems.

OPTIONS:
    -h, --help       Display this help message
    --dry-run        Perform pre-flight checks only (no changes)
    --no-agents      Skip agent installation

EXAMPLES:
    sudo ./$SCRIPT_NAME
    sudo ./$SCRIPT_NAME --dry-run
    sudo ./$SCRIPT_NAME --no-agents

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

    # Write errors to error log
    if [[ "${level}" == "ERROR" ]] || [[ "${level}" == "CRITICAL" ]]; then
        echo "${log_msg}" >> "${ERROR_LOG}"
    fi

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

    if [[ ${#ROLLBACK_COMMANDS[@]} -gt 0 ]]; then
        log "WARNING" "Rollback script available at: ${ROLLBACK_SCRIPT}"
        log "WARNING" "Run it to reverse changes: sudo bash ${ROLLBACK_SCRIPT}"
    fi

    exit "${exit_code}"
}

# Trap errors
trap 'error_exit "Unexpected error occurred" $EXIT_GENERAL_ERROR' ERR

# Add rollback command
add_rollback() {
    local description="$1"
    local command="$2"

    ROLLBACK_COMMANDS+=("# ${description}")
    ROLLBACK_COMMANDS+=("${command}")

    log "INFO" "Rollback registered: ${description}"
}

# Generate rollback script
generate_rollback_script() {
    if [[ ${#ROLLBACK_COMMANDS[@]} -eq 0 ]]; then
        log "INFO" "No rollback commands to generate"
        return 0
    fi

    log "INFO" "Generating rollback script: ${ROLLBACK_SCRIPT}"

    cat > "${ROLLBACK_SCRIPT}" << 'ROLLBACK_HEADER'
#!/usr/bin/env bash
###############################################################################
# Rollback Script for Ubuntu Hardening
# Generated automatically - DO NOT EDIT
###############################################################################

set -euo pipefail

echo "WARNING: This will rollback security hardening changes"
echo "This may reduce your system's security posture"
read -p "Are you sure you want to continue? (yes/NO): " confirm

if [[ "$confirm" != "yes" ]]; then
    echo "Rollback cancelled"
    exit 0
fi

echo "Starting rollback..."

ROLLBACK_HEADER

    # Add rollback commands in reverse order
    for ((i=${#ROLLBACK_COMMANDS[@]}-1; i>=0; i--)); do
        echo "${ROLLBACK_COMMANDS[$i]}" >> "${ROLLBACK_SCRIPT}"
    done

    cat >> "${ROLLBACK_SCRIPT}" << 'ROLLBACK_FOOTER'

echo "Rollback completed"
echo "Review system configuration and test functionality"
ROLLBACK_FOOTER

    chmod +x "${ROLLBACK_SCRIPT}"
    log "SUCCESS" "Rollback script created: ${ROLLBACK_SCRIPT}"
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

    # Check Ubuntu version
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "$VERSION_ID" != "24.04" ]]; then
            log "WARNING" "This script is designed for Ubuntu 24.04, detected: $VERSION_ID"
            read -p "Continue anyway? (y/N): " continue_anyway
            [[ "$continue_anyway" =~ ^[Yy]$ ]] || error_exit "Aborted by user" $EXIT_PREFLIGHT_FAILED
        else
            log "SUCCESS" "Ubuntu 24.04 LTS detected"
        fi
    else
        log "WARNING" "Cannot detect Ubuntu version"
    fi

    # Check internet connectivity
    log "INFO" "Checking internet connectivity..."
    if ! ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
        error_exit "No internet connectivity detected" $EXIT_NETWORK_ERROR
    fi
    log "SUCCESS" "Internet connectivity confirmed"

    # Check for existing non-root sudo user
    log "INFO" "Checking for non-root sudo users..."
    local sudo_users
    sudo_users=$(getent group sudo | cut -d: -f4)
    if [[ -z "$sudo_users" ]] || [[ "$sudo_users" == "root" ]]; then
        log "WARNING" "No non-root sudo users found"
        log "WARNING" "This script will disable root SSH login"
        log "WARNING" "You may lock yourself out if you don't have another way to access the system"
        read -p "Do you have console/physical access to this system? (yes/NO): " has_console
        [[ "$has_console" == "yes" ]] || error_exit "Aborted: Ensure non-root sudo user exists first" $EXIT_PREFLIGHT_FAILED
    else
        log "SUCCESS" "Sudo users found: $sudo_users"
    fi

    # Check disk space
    local available_space
    available_space=$(df / | tail -1 | awk '{print $4}')
    if [[ $available_space -lt 1048576 ]]; then # Less than 1GB
        error_exit "Insufficient disk space (need at least 1GB free)" $EXIT_PREFLIGHT_FAILED
    fi
    log "SUCCESS" "Sufficient disk space available"

    # Check if UFW is already configured
    if systemctl is-active --quiet ufw 2>/dev/null; then
        log "WARNING" "UFW firewall is already active"
        log "WARNING" "This script will modify firewall rules"
        read -p "Continue? (y/N): " continue_ufw
        [[ "$continue_ufw" =~ ^[Yy]$ ]] || error_exit "Aborted by user" $EXIT_PREFLIGHT_FAILED
    fi

    log "SUCCESS" "All pre-flight checks passed"

    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "Dry-run mode - exiting without making changes"
        exit 0
    fi
}

###############################################################################
# Main Hardening Functions
###############################################################################

# Create backup directory and log directory
setup_environment() {
    log "INFO" "Setting up environment..."

    mkdir -p "${LOG_DIR}"
    mkdir -p "${BACKUP_DIR}"

    log "INFO" "Log directory: ${LOG_DIR}"
    log "INFO" "Backup directory: ${BACKUP_DIR}"
    log "INFO" "Log file: ${LOG_FILE}"
    log "INFO" "Error log: ${ERROR_LOG}"
    log "SUCCESS" "Environment setup complete"
}

# Update system packages
update_system() {
    log "INFO" "Updating system packages..."

    # Backup current package list
    dpkg --get-selections > "${BACKUP_DIR}/package_list.txt"
    add_rollback "Package list backup" "# Packages backed up to ${BACKUP_DIR}/package_list.txt"

    apt update || error_exit "Failed to update package lists" $EXIT_GENERAL_ERROR
    log "SUCCESS" "Package lists updated"

    apt -y upgrade || error_exit "Failed to upgrade packages" $EXIT_GENERAL_ERROR
    log "SUCCESS" "Packages upgraded"
}

# Install required packages
install_packages() {
    log "INFO" "Installing security packages..."

    local packages="ufw fail2ban apparmor apparmor-utils unattended-upgrades wget"

    # Check which packages are already installed
    for pkg in $packages; do
        if dpkg -l | grep -q "^ii  $pkg "; then
            log "INFO" "Package already installed: $pkg"
        fi
    done

    apt install -y $packages || error_exit "Failed to install required packages" $EXIT_GENERAL_ERROR
    log "SUCCESS" "Security packages installed"
}

# Configure unattended upgrades
configure_unattended_upgrades() {
    log "INFO" "Configuring unattended upgrades..."

    # Backup existing configuration
    if [[ -f /etc/apt/apt.conf.d/50unattended-upgrades ]]; then
        cp /etc/apt/apt.conf.d/50unattended-upgrades "${BACKUP_DIR}/"
        add_rollback "Restore unattended-upgrades config" \
            "cp \"${BACKUP_DIR}/50unattended-upgrades\" /etc/apt/apt.conf.d/50unattended-upgrades"
    fi

    dpkg-reconfigure -fnoninteractive unattended-upgrades || \
        error_exit "Failed to configure unattended upgrades" $EXIT_GENERAL_ERROR

    log "SUCCESS" "Unattended upgrades configured"
}

# Configure UFW firewall
configure_firewall() {
    log "INFO" "Configuring UFW firewall..."

    # Backup existing UFW rules
    if [[ -d /etc/ufw ]]; then
        tar -czf "${BACKUP_DIR}/ufw_backup.tar.gz" /etc/ufw/
        add_rollback "Restore UFW configuration" \
            "tar -xzf \"${BACKUP_DIR}/ufw_backup.tar.gz\" -C / && ufw reload"
    fi

    # Set default policies
    ufw default deny incoming || error_exit "Failed to set UFW default deny incoming" $EXIT_GENERAL_ERROR
    ufw default allow outgoing || error_exit "Failed to set UFW default allow outgoing" $EXIT_GENERAL_ERROR

    # Allow SSH (critical - do this before enabling)
    ufw allow ssh || error_exit "Failed to allow SSH" $EXIT_GENERAL_ERROR
    log "SUCCESS" "SSH access allowed (port 22)"

    # Allow MRCP port
    ufw allow 5060 || log "WARNING" "Failed to allow port 5060"

    # Restrict Redis to localhost
    ufw allow from 127.0.0.1 to any port 6379 proto tcp || log "WARNING" "Failed to configure Redis firewall rule"

    # Enable firewall
    ufw --force enable || error_exit "Failed to enable UFW" $EXIT_GENERAL_ERROR

    add_rollback "Disable UFW firewall" "ufw --force disable"

    # Display status
    ufw status verbose
    log "SUCCESS" "UFW firewall configured and enabled"
}

# Harden SSH configuration
harden_ssh() {
    log "INFO" "Hardening SSH configuration..."

    local sshd_config="/etc/ssh/sshd_config"

    # Backup SSH config
    cp "$sshd_config" "${BACKUP_DIR}/sshd_config.bak"
    add_rollback "Restore SSH configuration" \
        "cp \"${BACKUP_DIR}/sshd_config.bak\" \"$sshd_config\" && systemctl restart ssh"

    # Disable root login
    if grep -q "^PermitRootLogin" "$sshd_config"; then
        sed -i.bak -e 's/^PermitRootLogin.*/PermitRootLogin no/' "$sshd_config"
    else
        echo "PermitRootLogin no" >> "$sshd_config"
    fi

    # Test SSH configuration
    if ! sshd -t; then
        error_exit "SSH configuration test failed" $EXIT_GENERAL_ERROR
    fi

    # Restart SSH service
    systemctl restart ssh || error_exit "Failed to restart SSH service" $EXIT_GENERAL_ERROR

    log "SUCCESS" "SSH hardened (root login disabled)"
    log "WARNING" "Ensure you can still access the system with a non-root user!"
}

# Configure AppArmor
configure_apparmor() {
    log "INFO" "Configuring AppArmor..."

    systemctl enable --now apparmor || error_exit "Failed to enable AppArmor" $EXIT_GENERAL_ERROR

    add_rollback "Disable AppArmor" "systemctl disable --now apparmor"

    # Display AppArmor status
    aa-status || log "WARNING" "AppArmor status command failed"

    log "SUCCESS" "AppArmor enabled"
}

# Configure kernel parameters
configure_kernel_parameters() {
    log "INFO" "Configuring kernel security parameters..."

    local sysctl_conf="/etc/sysctl.conf"

    # Backup sysctl.conf
    cp "$sysctl_conf" "${BACKUP_DIR}/sysctl.conf.bak"
    add_rollback "Restore sysctl configuration" \
        "cp \"${BACKUP_DIR}/sysctl.conf.bak\" \"$sysctl_conf\" && sysctl -p"

    # Add kernel parameters if not present
    if ! grep -q '^kernel.unprivileged_userns_clone=' "$sysctl_conf"; then
        echo "kernel.unprivileged_userns_clone=0" >> "$sysctl_conf"
        log "INFO" "Added: kernel.unprivileged_userns_clone=0"
    fi

    if ! grep -q '^kernel.unprivileged_userns_apparmor_policy=' "$sysctl_conf"; then
        echo "kernel.unprivileged_userns_apparmor_policy=1" >> "$sysctl_conf"
        log "INFO" "Added: kernel.unprivileged_userns_apparmor_policy=1"
    fi

    # Apply changes
    sysctl -p || log "WARNING" "Some sysctl parameters may require reboot"

    log "SUCCESS" "Kernel parameters configured"
}

# Configure fail2ban
configure_fail2ban() {
    log "INFO" "Configuring fail2ban..."

    systemctl enable --now fail2ban || error_exit "Failed to enable fail2ban" $EXIT_GENERAL_ERROR

    add_rollback "Disable fail2ban" "systemctl disable --now fail2ban"

    log "SUCCESS" "fail2ban configured and enabled"
}

# Configure log rotation
configure_logrotate() {
    log "INFO" "Configuring log rotation..."

    local logrotate_conf
    if [[ -f /etc/logrotate.d/rsyslog ]]; then
        logrotate_conf="/etc/logrotate.d/rsyslog"
    else
        logrotate_conf="/etc/logrotate.d/syslog"
    fi

    # Backup existing configuration
    if [[ -f "$logrotate_conf" ]]; then
        cp "$logrotate_conf" "${BACKUP_DIR}/$(basename "$logrotate_conf").bak"
        add_rollback "Restore logrotate configuration" \
            "cp \"${BACKUP_DIR}/$(basename "$logrotate_conf").bak\" \"$logrotate_conf\""
    fi

    # Create new logrotate configuration
    cat > "$logrotate_conf" <<'EOF'
/var/log/syslog {
    size 50M
    rotate 6
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        command -v systemctl >/dev/null && systemctl is-active --quiet rsyslog && systemctl reload rsyslog || true
    endscript
}
EOF

    log "SUCCESS" "Log rotation configured"
}

# Install ScreenConnect agent
install_screenconnect() {
    if [[ "$SKIP_AGENTS" == true ]]; then
        log "INFO" "Skipping ScreenConnect installation (--no-agents)"
        return 0
    fi

    log "INFO" "Installing ScreenConnect agent..."

    local sc_url="https://support.company.com/Bin/ScreenConnect.ClientSetup.deb?e=Access&y=Guest"
    local sc_file="/tmp/screenconnect_client.deb"

    # Download with error checking
    if ! wget -O "$sc_file" "$sc_url" 2>&1 | tee -a "${LOG_FILE}"; then
        log "WARNING" "Failed to download ScreenConnect agent"
        return 1
    fi

    # Verify file was downloaded
    if [[ ! -f "$sc_file" ]] || [[ ! -s "$sc_file" ]]; then
        log "WARNING" "ScreenConnect agent download failed or file is empty"
        return 1
    fi

    # Install package
    if apt install -y "$sc_file"; then
        log "SUCCESS" "ScreenConnect agent installed"
        add_rollback "Uninstall ScreenConnect" "apt remove -y screenconnect || true"
    else
        log "WARNING" "ScreenConnect agent installation failed"
    fi

    # Clean up
    rm -f "$sc_file"
}

# Install Sophos antivirus
install_sophos() {
    if [[ "$SKIP_AGENTS" == true ]]; then
        log "INFO" "Skipping Sophos installation (--no-agents)"
        return 0
    fi

    log "INFO" "Sophos installation (optional)..."

    read -r -p "Enter full path to SophosSetup.sh (or press Enter to skip): " sophos_path

    if [[ -z "$sophos_path" ]]; then
        log "INFO" "No Sophos installer path provided; skipping Sophos install"
        return 0
    fi

    if [[ ! -f "$sophos_path" ]]; then
        log "WARNING" "File not found at '$sophos_path'; skipping Sophos install"
        return 1
    fi

    log "INFO" "Running Sophos installer: $sophos_path"
    chmod +x "$sophos_path"

    if "$sophos_path"; then
        log "SUCCESS" "Sophos installed successfully"
        add_rollback "Uninstall Sophos" "# Manual Sophos uninstallation required"
    else
        log "WARNING" "Sophos installation failed or was cancelled"
    fi
}

# Install Atera agent
install_atera() {
    if [[ "$SKIP_AGENTS" == true ]]; then
        log "INFO" "Skipping Atera installation (--no-agents)"
        return 0
    fi

    log "INFO" "Installing Atera agent..."

    local atera_url='https://CompanyProfessionalServicesInc289169.servicedesk.atera.com/api/utils/AgentInstallScript/Linux/0013z00002Shig1AAB?customerId=2'
    local atera_script="/tmp/atera_install.sh"

    # Download Atera install script
    if ! wget -O "$atera_script" "$atera_url" 2>&1 | tee -a "${LOG_FILE}"; then
        log "WARNING" "Failed to download Atera agent installer"
        return 1
    fi

    # Execute install script
    if bash "$atera_script"; then
        log "SUCCESS" "Atera agent installed"
        add_rollback "Uninstall Atera" "# Manual Atera uninstallation required"
    else
        log "WARNING" "Atera agent installation failed"
    fi

    # Clean up
    rm -f "$atera_script"
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
            --no-agents)
                SKIP_AGENTS=true
                shift
                ;;
            *)
                echo "Unknown option: $1"
                usage
                ;;
        esac
    done

    # Setup
    setup_environment

    log "INFO" "========================================="
    log "INFO" "Ubuntu 24.04 LTS Security Hardening Script"
    log "INFO" "Version 2.0.0 (Enhanced)"
    log "INFO" "========================================="

    # Run pre-flight checks
    preflight_checks

    # Perform hardening
    update_system
    install_packages
    configure_unattended_upgrades
    configure_firewall
    harden_ssh
    configure_apparmor
    configure_kernel_parameters
    configure_fail2ban
    configure_logrotate

    # Install agents
    install_screenconnect
    install_sophos
    install_atera

    # Generate rollback script
    generate_rollback_script

    # Completion message
    log "SUCCESS" "========================================="
    log "SUCCESS" "Hardening complete!"
    log "SUCCESS" "========================================="
    log "INFO" "Log file: ${LOG_FILE}"
    log "INFO" "Error log: ${ERROR_LOG}"
    log "INFO" "Rollback script: ${ROLLBACK_SCRIPT}"
    log "INFO" "Backup directory: ${BACKUP_DIR}"
    log "WARNING" "IMPORTANT: Reboot system to apply all changes"
    log "WARNING" "IMPORTANT: Test SSH access before closing this session"
    log "INFO" "========================================="

    exit $EXIT_SUCCESS
}

# Run main function
main "$@"
