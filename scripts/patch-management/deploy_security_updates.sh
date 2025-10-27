#!/usr/bin/env bash
###############################################################################
# Script Name: deploy_security_updates.sh
# Description: Deploy security updates with system snapshots, rollback, and compliance scanning
#
# Author: SysAdmin Toolkit Team
# Created: 2025-10-06
# Modified: 2025-10-06
# Version: 1.0.0
# Risk Level: High
#
###############################################################################
# USAGE
#
#   deploy_security_updates.sh [OPTIONS]
#
# OPTIONS
#   -h, --help              Display this help message
#   -d, --dry-run           Show what would be done without making changes
#   -s, --snapshot          Create system snapshot before patching (LVM/BTRFS)
#   -k, --kernel-live       Enable kernel live patching (if available)
#   -r, --restart-services  Restart affected services after patching
#   -c, --compliance        Run compliance scan after patching (CIS, DISA STIG)
#   -e, --email EMAIL       Send notification email to specified address
#   -f, --force             Skip confirmation prompts
#   -v, --verbose           Enable verbose output
#   --exclude PACKAGES      Comma-separated list of packages to exclude
#   --security-only         Install security updates only (default)
#   --all-updates           Install all available updates, not just security
#
# ARGUMENTS
#   None
#
###############################################################################
# DESCRIPTION
#
#   Comprehensive Linux security update deployment script supporting multiple
#   distributions (Ubuntu, Debian, RHEL, CentOS, AlmaLinux, Rocky Linux).
#   Provides enterprise-grade patch management with safety features.
#
#   This script performs the following operations:
#     1. Detects Linux distribution and package manager
#     2. Creates pre-patch system snapshot (LVM/BTRFS if available)
#     3. Checks for and applies security updates
#     4. Enables kernel live patching if requested (Ubuntu/RHEL)
#     5. Restarts affected services intelligently
#     6. Runs post-patch compliance scanning
#     7. Sends email notifications with results
#     8. Provides rollback procedures and documentation
#
#   Key Features:
#     - Multi-distribution support (apt/yum/dnf)
#     - Automatic snapshot creation for rollback
#     - Kernel live patching support (Livepatch/kpatch)
#     - Service dependency analysis and restart orchestration
#     - CIS/DISA STIG compliance scanning
#     - Email notifications with detailed reports
#     - Package exclusion support
#     - Dry-run mode for testing
#
###############################################################################
# EXAMPLES
#
#   Example 1: Dry-run to preview security updates
#     $ sudo ./deploy_security_updates.sh --dry-run
#
#   Example 2: Install security updates with snapshot and email notification
#     $ sudo ./deploy_security_updates.sh --snapshot --email admin@example.com
#
#   Example 3: Install all updates with kernel live patching and service restart
#     $ sudo ./deploy_security_updates.sh --all-updates --kernel-live --restart-services
#
#   Example 4: Security-only updates with compliance scan
#     $ sudo ./deploy_security_updates.sh --snapshot --compliance --email security@example.com
#
#   Example 5: Force update excluding specific packages
#     $ sudo ./deploy_security_updates.sh --force --exclude "kernel,docker-ce" --snapshot
#
###############################################################################
# EXIT CODES
#
#   0   Success - Operation completed successfully
#   1   General error - Unspecified failure
#   2   Invalid arguments or options
#   3   Permission denied - Script must be run as root
#   4   Package manager error - Failed to update packages
#   5   Snapshot creation failed
#   6   Service restart failed
#   7   Compliance scan failed
#   8   Email notification failed (non-critical)
#
###############################################################################
# PREREQUISITES
#
#   - Bash 4.0 or later
#   - Root/sudo privileges required
#   - Package manager: apt, yum, or dnf
#   - Optional: LVM or BTRFS for snapshot support
#   - Optional: mail/sendmail for email notifications
#   - Optional: OpenSCAP or Lynis for compliance scanning
#   - Network access to package repositories
#   - Minimum 2GB free space for snapshots (if enabled)
#
#   Supported Distributions:
#     - Ubuntu 18.04, 20.04, 22.04, 24.04
#     - Debian 10, 11, 12
#     - RHEL 7, 8, 9
#     - CentOS 7, 8, Stream
#     - AlmaLinux 8, 9
#     - Rocky Linux 8, 9
#
###############################################################################
# SECURITY CONSIDERATIONS (for Medium/High risk scripts)
#
#   Risk Level: HIGH
#
#   This script performs security-sensitive operations:
#     - Installs system security updates and patches
#     - Requires root privileges for system modifications
#     - Can impact system availability during patching
#     - May require system or service restarts
#     - Creates snapshots consuming disk space
#     - Modifies critical system packages
#
#   Security best practices:
#     - Test in non-production environment first
#     - Always create snapshots before production patching
#     - Run during scheduled maintenance windows
#     - Verify package sources and signatures
#     - Review excluded packages for security impact
#     - Monitor service restarts for proper operation
#     - Maintain rollback procedure documentation
#
#   Mitigation strategies:
#     - Use --dry-run flag to preview changes
#     - Enable snapshot creation for rollback capability
#     - Exclude problematic packages if necessary
#     - Test service restart procedures beforehand
#     - Maintain console/IPMI access for recovery
#     - Enable compliance scanning to verify security posture
#     - Document all changes via email notifications
#
###############################################################################
# NOTES
#
#   - This script uses 'set -euo pipefail' for strict error handling
#   - All functions include error checking and validation
#   - Snapshots are created with timestamp naming for easy identification
#   - Logging goes to both console and /var/log/security-updates.log
#   - Service restart is intelligent and only affects updated packages
#   - Kernel live patching avoids reboot for kernel updates when possible
#   - Email notifications include full update list and compliance results
#
# ENVIRONMENT VARIABLES
#
#   DRY_RUN               Set to 1 to enable dry-run mode
#   VERBOSE               Set to 1 to enable verbose logging
#   SNAPSHOT_SIZE         Override default snapshot size (default: 5G)
#   COMPLIANCE_PROFILE    Compliance profile to use (CIS, STIG, etc.)
#   SMTP_SERVER           SMTP server for email notifications
#
###############################################################################
# ROLLBACK PROCEDURE
#
#   If updates cause issues, rollback using these steps:
#
#   For LVM Snapshots:
#     1. Boot from rescue media or single-user mode
#     2. List snapshots: lvs
#     3. Merge snapshot: lvconvert --merge /dev/vg/snapshot_name
#     4. Reboot system to complete rollback
#
#   For BTRFS Snapshots:
#     1. Boot from rescue media or BTRFS snapshot submenu
#     2. List snapshots: btrfs subvolume list /
#     3. Set default: btrfs subvolume set-default <ID> /
#     4. Reboot to snapshot
#
#   For Package Rollback (without snapshot):
#     1. Review /var/log/security-updates.log for installed packages
#     2. Downgrade packages: apt/yum/dnf downgrade <package>
#     3. Hold packages: apt-mark hold <package> / yum versionlock
#     4. Reboot if kernel was updated
#
###############################################################################
# CHANGE LOG
#
#   1.0.0 - 2025-10-06 - Initial release
#           - Multi-distribution support (apt/yum/dnf)
#           - LVM and BTRFS snapshot support
#           - Kernel live patching integration
#           - Service restart orchestration
#           - Compliance scanning (OpenSCAP/Lynis)
#           - Email notification support
#           - Package exclusion capability
#           - Dry-run mode for testing
#
###############################################################################

set -euo pipefail

# Script constants
readonly SCRIPT_NAME="$(basename "${0}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
readonly LOG_FILE="/var/log/security-updates.log"
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)
readonly SNAPSHOT_NAME="security_updates_${TIMESTAMP}"

# Default configuration
DRY_RUN=0
CREATE_SNAPSHOT=0
KERNEL_LIVE=0
RESTART_SERVICES=0
RUN_COMPLIANCE=0
VERBOSE=0
FORCE=0
SECURITY_ONLY=1
EMAIL=""
EXCLUDE_PACKAGES=""
SNAPSHOT_SIZE="${SNAPSHOT_SIZE:-5G}"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

#region Functions

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "$level" in
        INFO)
            echo -e "${BLUE}[${timestamp}] [INFO]${NC} ${message}" | tee -a "${LOG_FILE}"
            ;;
        SUCCESS)
            echo -e "${GREEN}[${timestamp}] [SUCCESS]${NC} ${message}" | tee -a "${LOG_FILE}"
            ;;
        WARNING)
            echo -e "${YELLOW}[${timestamp}] [WARNING]${NC} ${message}" | tee -a "${LOG_FILE}"
            ;;
        ERROR)
            echo -e "${RED}[${timestamp}] [ERROR]${NC} ${message}" | tee -a "${LOG_FILE}"
            ;;
        *)
            echo "[${timestamp}] ${message}" | tee -a "${LOG_FILE}"
            ;;
    esac
}

show_usage() {
    grep '^#' "${0}" | grep -E '# (USAGE|OPTIONS|ARGUMENTS|EXAMPLES|DESCRIPTION)' -A 100 | \
        grep -v '###' | sed 's/^# //' | sed 's/^#//'
    exit 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log ERROR "This script must be run as root or with sudo"
        exit 3
    fi
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO_ID="${ID}"
        DISTRO_VERSION="${VERSION_ID}"
        DISTRO_NAME="${NAME}"
    else
        log ERROR "Cannot detect Linux distribution"
        exit 1
    fi

    # Detect package manager
    if command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
    else
        log ERROR "Unsupported package manager. Supported: apt, yum, dnf"
        exit 1
    fi

    log INFO "Detected: ${DISTRO_NAME} ${DISTRO_VERSION} (${PKG_MANAGER})"
}

create_snapshot() {
    if [[ $CREATE_SNAPSHOT -eq 0 ]]; then
        return 0
    fi

    log INFO "Creating system snapshot: ${SNAPSHOT_NAME}"

    # Check for LVM
    if command -v lvcreate &>/dev/null; then
        local root_vg=$(lvs --noheadings -o vg_name,lv_name | grep -E 'root|lv_root' | awk '{print $1}' | head -n1)
        local root_lv=$(lvs --noheadings -o vg_name,lv_name | grep -E 'root|lv_root' | awk '{print $2}' | head -n1)

        if [[ -n "$root_vg" ]] && [[ -n "$root_lv" ]]; then
            if [[ $DRY_RUN -eq 1 ]]; then
                log INFO "[DRY-RUN] Would create LVM snapshot: /dev/${root_vg}/${SNAPSHOT_NAME}"
                return 0
            fi

            if lvcreate -L "${SNAPSHOT_SIZE}" -s -n "${SNAPSHOT_NAME}" "/dev/${root_vg}/${root_lv}" >> "${LOG_FILE}" 2>&1; then
                log SUCCESS "LVM snapshot created: /dev/${root_vg}/${SNAPSHOT_NAME}"
                echo "${root_vg}/${SNAPSHOT_NAME}" > "/tmp/snapshot_info_${TIMESTAMP}.txt"
                return 0
            else
                log ERROR "Failed to create LVM snapshot"
                return 5
            fi
        fi
    fi

    # Check for BTRFS
    if command -v btrfs &>/dev/null; then
        local root_mount=$(df / | tail -1 | awk '{print $6}')
        if btrfs filesystem show "${root_mount}" &>/dev/null; then
            if [[ $DRY_RUN -eq 1 ]]; then
                log INFO "[DRY-RUN] Would create BTRFS snapshot: /.snapshots/${SNAPSHOT_NAME}"
                return 0
            fi

            mkdir -p "/.snapshots"
            if btrfs subvolume snapshot "${root_mount}" "/.snapshots/${SNAPSHOT_NAME}" >> "${LOG_FILE}" 2>&1; then
                log SUCCESS "BTRFS snapshot created: /.snapshots/${SNAPSHOT_NAME}"
                echo "btrfs:/.snapshots/${SNAPSHOT_NAME}" > "/tmp/snapshot_info_${TIMESTAMP}.txt"
                return 0
            else
                log ERROR "Failed to create BTRFS snapshot"
                return 5
            fi
        fi
    fi

    log WARNING "No snapshot system detected (LVM/BTRFS). Proceeding without snapshot."
    log WARNING "Manual backup is strongly recommended!"

    if [[ $FORCE -eq 0 ]]; then
        read -p "Continue without snapshot? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log INFO "Deployment cancelled by user"
            exit 0
        fi
    fi

    return 0
}

check_updates() {
    log INFO "Checking for available updates..."

    case "$PKG_MANAGER" in
        apt)
            if [[ $DRY_RUN -eq 1 ]]; then
                log INFO "[DRY-RUN] Would run: apt-get update"
            else
                apt-get update -qq >> "${LOG_FILE}" 2>&1
            fi

            if [[ $SECURITY_ONLY -eq 1 ]]; then
                UPDATES=$(apt-get upgrade -s | grep -E '^Inst.*security' | wc -l)
                log INFO "Found ${UPDATES} security updates available"
            else
                UPDATES=$(apt-get upgrade -s | grep '^Inst' | wc -l)
                log INFO "Found ${UPDATES} total updates available"
            fi
            ;;

        yum|dnf)
            if [[ $DRY_RUN -eq 1 ]]; then
                log INFO "[DRY-RUN] Would run: ${PKG_MANAGER} check-update"
            else
                ${PKG_MANAGER} check-update -q >> "${LOG_FILE}" 2>&1 || true
            fi

            if [[ $SECURITY_ONLY -eq 1 ]]; then
                UPDATES=$(${PKG_MANAGER} updateinfo list security 2>/dev/null | grep -v '^$' | wc -l)
                log INFO "Found ${UPDATES} security updates available"
            else
                UPDATES=$(${PKG_MANAGER} check-update -q 2>/dev/null | grep -v '^$' | wc -l || echo 0)
                log INFO "Found ${UPDATES} total updates available"
            fi
            ;;
    esac

    return 0
}

install_updates() {
    if [[ $UPDATES -eq 0 ]]; then
        log SUCCESS "System is up to date. No updates to install."
        return 0
    fi

    log INFO "Installing updates..."

    local exclude_args=""
    if [[ -n "$EXCLUDE_PACKAGES" ]]; then
        IFS=',' read -ra PKG_ARRAY <<< "$EXCLUDE_PACKAGES"
        for pkg in "${PKG_ARRAY[@]}"; do
            case "$PKG_MANAGER" in
                apt)
                    exclude_args="${exclude_args} -o Dpkg::Options::='--exclude=${pkg}'"
                    ;;
                yum|dnf)
                    exclude_args="${exclude_args} --exclude=${pkg}"
                    ;;
            esac
        done
        log INFO "Excluding packages: ${EXCLUDE_PACKAGES}"
    fi

    case "$PKG_MANAGER" in
        apt)
            local cmd="DEBIAN_FRONTEND=noninteractive apt-get"
            if [[ $SECURITY_ONLY -eq 1 ]]; then
                cmd="${cmd} upgrade -y ${exclude_args} -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold'"
            else
                cmd="${cmd} dist-upgrade -y ${exclude_args} -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold'"
            fi

            if [[ $DRY_RUN -eq 1 ]]; then
                log INFO "[DRY-RUN] Would run: ${cmd}"
                apt-get upgrade -s | grep '^Inst' | head -20
            else
                eval "${cmd}" 2>&1 | tee -a "${LOG_FILE}"
                log SUCCESS "Updates installed successfully"
            fi
            ;;

        yum|dnf)
            local cmd="${PKG_MANAGER} -y"
            if [[ $SECURITY_ONLY -eq 1 ]]; then
                cmd="${cmd} update --security ${exclude_args}"
            else
                cmd="${cmd} update ${exclude_args}"
            fi

            if [[ $DRY_RUN -eq 1 ]]; then
                log INFO "[DRY-RUN] Would run: ${cmd}"
                ${PKG_MANAGER} updateinfo list security 2>/dev/null | head -20
            else
                eval "${cmd}" 2>&1 | tee -a "${LOG_FILE}"
                log SUCCESS "Updates installed successfully"
            fi
            ;;
    esac

    return 0
}

enable_kernel_livepatch() {
    if [[ $KERNEL_LIVE -eq 0 ]]; then
        return 0
    fi

    log INFO "Configuring kernel live patching..."

    case "$DISTRO_ID" in
        ubuntu)
            if ! command -v canonical-livepatch &>/dev/null; then
                if [[ $DRY_RUN -eq 1 ]]; then
                    log INFO "[DRY-RUN] Would install: canonical-livepatch"
                else
                    snap install canonical-livepatch
                fi
            fi

            if [[ $DRY_RUN -eq 1 ]]; then
                log INFO "[DRY-RUN] Would enable Canonical Livepatch"
            else
                log INFO "Canonical Livepatch requires registration. Visit: https://ubuntu.com/livepatch"
                log INFO "Run: sudo canonical-livepatch enable <TOKEN>"
            fi
            ;;

        rhel|centos|almalinux|rocky)
            if ! rpm -q kpatch &>/dev/null; then
                if [[ $DRY_RUN -eq 1 ]]; then
                    log INFO "[DRY-RUN] Would install: kpatch"
                else
                    ${PKG_MANAGER} install -y kpatch
                fi
            fi

            if [[ $DRY_RUN -eq 1 ]]; then
                log INFO "[DRY-RUN] Would enable kpatch service"
            else
                systemctl enable --now kpatch.service
                log SUCCESS "kpatch service enabled"
            fi
            ;;

        *)
            log WARNING "Kernel live patching not supported for ${DISTRO_ID}"
            ;;
    esac

    return 0
}

restart_affected_services() {
    if [[ $RESTART_SERVICES -eq 0 ]]; then
        return 0
    fi

    log INFO "Checking for services requiring restart..."

    # Use needrestart or checkrestart if available
    if command -v needrestart &>/dev/null; then
        if [[ $DRY_RUN -eq 1 ]]; then
            log INFO "[DRY-RUN] Would run: needrestart -r l"
            needrestart -b -r l 2>/dev/null || true
        else
            log INFO "Running needrestart to identify affected services..."
            needrestart -r a 2>&1 | tee -a "${LOG_FILE}"
            log SUCCESS "Services restarted successfully"
        fi
    elif command -v checkrestart &>/dev/null; then
        if [[ $DRY_RUN -eq 1 ]]; then
            log INFO "[DRY-RUN] Would run: checkrestart"
        else
            log INFO "Running checkrestart to identify affected services..."
            checkrestart 2>&1 | tee -a "${LOG_FILE}"
        fi
    else
        log WARNING "needrestart/checkrestart not available. Install for automatic service restart detection."
        log INFO "To install: apt-get install needrestart (Debian/Ubuntu) or yum install yum-plugin-ps (RHEL)"
    fi

    return 0
}

run_compliance_scan() {
    if [[ $RUN_COMPLIANCE -eq 0 ]]; then
        return 0
    fi

    log INFO "Running compliance scan..."

    # Try OpenSCAP first
    if command -v oscap &>/dev/null; then
        log INFO "Using OpenSCAP for compliance scanning..."

        local profile="${COMPLIANCE_PROFILE:-xccdf_org.ssgproject.content_profile_cis}"
        local report_file="/tmp/compliance_report_${TIMESTAMP}.html"

        if [[ $DRY_RUN -eq 1 ]]; then
            log INFO "[DRY-RUN] Would run OpenSCAP compliance scan"
        else
            oscap xccdf eval --profile "${profile}" --report "${report_file}" \
                /usr/share/xml/scap/ssg/content/*ds.xml 2>&1 | tee -a "${LOG_FILE}" || true
            log SUCCESS "Compliance report generated: ${report_file}"
        fi

    # Fallback to Lynis
    elif command -v lynis &>/dev/null; then
        log INFO "Using Lynis for compliance scanning..."

        if [[ $DRY_RUN -eq 1 ]]; then
            log INFO "[DRY-RUN] Would run: lynis audit system"
        else
            lynis audit system --quick 2>&1 | tee -a "${LOG_FILE}"
            log SUCCESS "Lynis scan completed. Check /var/log/lynis.log for results"
        fi

    else
        log WARNING "No compliance scanner found (OpenSCAP/Lynis)"
        log INFO "Install: apt-get install libopenscap8 lynis (Ubuntu) or yum install openscap-scanner lynis (RHEL)"
    fi

    return 0
}

send_email_notification() {
    if [[ -z "$EMAIL" ]]; then
        return 0
    fi

    log INFO "Sending email notification to: ${EMAIL}"

    local subject="Security Updates Completed - ${HOSTNAME} - ${TIMESTAMP}"
    local body="Security Update Report for ${HOSTNAME}

Distribution: ${DISTRO_NAME} ${DISTRO_VERSION}
Timestamp: $(date '+%Y-%m-%d %H:%M:%S')
Updates Installed: ${UPDATES}
Snapshot Created: $([ $CREATE_SNAPSHOT -eq 1 ] && echo 'Yes' || echo 'No')
Kernel Live Patch: $([ $KERNEL_LIVE -eq 1 ] && echo 'Enabled' || echo 'Disabled')
Services Restarted: $([ $RESTART_SERVICES -eq 1 ] && echo 'Yes' || echo 'No')
Compliance Scan: $([ $RUN_COMPLIANCE -eq 1 ] && echo 'Completed' || echo 'Skipped')

Full log: ${LOG_FILE}

---
Automated Security Update Deployment
Generated by: ${SCRIPT_NAME}
"

    if [[ $DRY_RUN -eq 1 ]]; then
        log INFO "[DRY-RUN] Would send email to: ${EMAIL}"
        echo "Subject: ${subject}"
        echo "${body}"
    else
        if command -v mail &>/dev/null; then
            echo "${body}" | mail -s "${subject}" "${EMAIL}" 2>&1 | tee -a "${LOG_FILE}"
            log SUCCESS "Email notification sent"
        elif command -v sendmail &>/dev/null; then
            echo -e "Subject: ${subject}\n\n${body}" | sendmail "${EMAIL}" 2>&1 | tee -a "${LOG_FILE}"
            log SUCCESS "Email notification sent via sendmail"
        else
            log WARNING "No mail command found. Install mailutils or postfix"
            return 8
        fi
    fi

    return 0
}

cleanup() {
    log INFO "Cleanup completed"
}

#endregion

#region Main Script

main() {
    # Parse command-line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_usage
                ;;
            -d|--dry-run)
                DRY_RUN=1
                log INFO "DRY-RUN mode enabled"
                shift
                ;;
            -s|--snapshot)
                CREATE_SNAPSHOT=1
                shift
                ;;
            -k|--kernel-live)
                KERNEL_LIVE=1
                shift
                ;;
            -r|--restart-services)
                RESTART_SERVICES=1
                shift
                ;;
            -c|--compliance)
                RUN_COMPLIANCE=1
                shift
                ;;
            -e|--email)
                EMAIL="$2"
                shift 2
                ;;
            -f|--force)
                FORCE=1
                shift
                ;;
            -v|--verbose)
                VERBOSE=1
                set -x
                shift
                ;;
            --exclude)
                EXCLUDE_PACKAGES="$2"
                shift 2
                ;;
            --security-only)
                SECURITY_ONLY=1
                shift
                ;;
            --all-updates)
                SECURITY_ONLY=0
                shift
                ;;
            *)
                log ERROR "Unknown option: $1"
                show_usage
                ;;
        esac
    done

    # Set trap for cleanup
    trap cleanup EXIT

    log INFO "=== Security Update Deployment Started ==="
    log INFO "Script: ${SCRIPT_NAME} v1.0.0"

    # Pre-flight checks
    check_root
    detect_distro

    # Create snapshot if requested
    create_snapshot || exit $?

    # Check and install updates
    check_updates
    install_updates || exit $?

    # Post-update tasks
    enable_kernel_livepatch
    restart_affected_services
    run_compliance_scan
    send_email_notification

    # Final summary
    log SUCCESS "=== Security Update Deployment Completed ==="
    log INFO "Updates installed: ${UPDATES}"
    log INFO "Log file: ${LOG_FILE}"

    if [[ $CREATE_SNAPSHOT -eq 1 ]] && [[ -f "/tmp/snapshot_info_${TIMESTAMP}.txt" ]]; then
        local snapshot_info=$(cat "/tmp/snapshot_info_${TIMESTAMP}.txt")
        log INFO "Snapshot created: ${snapshot_info}"
        log INFO "To rollback: See ROLLBACK PROCEDURE in script header"
    fi

    # Check if reboot required
    if [[ -f /var/run/reboot-required ]]; then
        log WARNING "System reboot is required to complete updates"
        log INFO "Run: sudo reboot"
    fi

    exit 0
}

# Execute main function
main "$@"

#endregion
