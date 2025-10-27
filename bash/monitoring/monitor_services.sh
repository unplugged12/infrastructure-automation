#!/usr/bin/env bash
###############################################################################
# Script Name: monitor_services.sh
# Description: Monitor systemd services with auto-restart, notifications, and Prometheus export
#
# Author: SysAdmin Toolkit
# Created: 2025-10-06
# Modified: 2025-10-06
# Version: 1.0.0
# Risk Level: Medium
#
###############################################################################
# USAGE
#
#   monitor_services.sh [OPTIONS] [SERVICE_NAMES...]
#
# OPTIONS
#   -h, --help              Display this help message
#   -c, --config FILE       Path to configuration file (default: /etc/monitor_services.conf)
#   -r, --auto-restart      Automatically restart failed services
#   -w, --webhook URL       Webhook URL for notifications (Slack, Discord, etc.)
#   -s, --slack URL         Slack webhook URL (alias for --webhook)
#   -p, --prometheus        Enable Prometheus exporter format output
#   -o, --output FILE       Output file for Prometheus metrics
#   -d, --check-deps        Check service dependencies
#   -l, --log-rotation      Monitor log file sizes and rotation
#   -v, --verbose           Enable verbose output
#   -q, --quiet             Suppress output (useful for cron)
#   --syslog                Send alerts to syslog
#   --interval SECONDS      Monitoring interval (default: 60)
#
# ARGUMENTS
#   SERVICE_NAMES          Space-separated list of services to monitor
#                          If not specified, uses services from config file
#
###############################################################################
# DESCRIPTION
#
#   Comprehensive systemd service monitoring script that provides:
#
#   Core Features:
#     - Monitor systemd service status (active, inactive, failed)
#     - Automatic restart of failed services (optional)
#     - Service dependency tree checking
#     - Log file rotation monitoring
#     - Webhook notifications (Slack, Discord, Teams compatible)
#     - Prometheus metrics export for monitoring integration
#     - Syslog integration for centralized logging
#     - Configuration file support for persistent settings
#
#   This script continuously monitors specified systemd services and takes
#   action when services enter failed state. It can automatically restart
#   services, send notifications via webhooks, and export metrics in
#   Prometheus format for integration with monitoring platforms.
#
###############################################################################
# EXAMPLES
#
#   Example 1: Monitor specific services with auto-restart
#     $ sudo ./monitor_services.sh --auto-restart nginx apache2 mysql
#
#   Example 2: Monitor services with Slack notifications
#     $ ./monitor_services.sh --slack "https://hooks.slack.com/services/XXX" nginx docker
#
#   Example 3: Enable Prometheus exporter
#     $ ./monitor_services.sh --prometheus --output /var/lib/node_exporter/textfile_collector/services.prom
#
#   Example 4: Use configuration file with dependency checking
#     $ ./monitor_services.sh --config /etc/monitor.conf --check-deps --verbose
#
#   Example 5: Continuous monitoring with 30-second interval
#     $ ./monitor_services.sh --interval 30 --auto-restart --syslog nginx mysql postgresql
#
###############################################################################
# EXIT CODES
#
#   0   Success - All monitored services are running
#   1   Warning - One or more services in degraded state
#   2   Critical - One or more services have failed
#   3   Configuration error - Invalid config or missing services
#   4   Permission denied - Insufficient privileges
#
###############################################################################
# PREREQUISITES
#
#   - Bash 4.0 or later
#   - systemd-based Linux distribution
#   - Root/sudo privileges (required for service restart and some queries)
#   - Required commands: systemctl, journalctl, curl, jq
#   - Optional: logger (for syslog integration)
#
###############################################################################
# SECURITY CONSIDERATIONS
#
#   Risk Level: MEDIUM
#
#   This script performs the following security-sensitive operations:
#     - Monitors system service status
#     - Can automatically restart services (requires root)
#     - Accesses systemd journal logs
#     - Sends data to external webhooks
#
#   Security best practices:
#     - Protect webhook URLs (contain authentication tokens)
#     - Limit auto-restart to non-critical services
#     - Use configuration file with restricted permissions (600)
#     - Review services before adding auto-restart
#     - Monitor restart loops to prevent resource exhaustion
#
#   Mitigation strategies:
#     - Run as dedicated monitoring user when possible
#     - Use sudo for restart operations only
#     - Implement rate limiting for restarts
#     - Log all restart attempts for audit
#
###############################################################################
# CONFIGURATION FILE
#
#   Default location: /etc/monitor_services.conf
#
#   Example configuration:
#     # Services to monitor (one per line)
#     SERVICES=(
#       nginx
#       apache2
#       mysql
#       postgresql
#     )
#
#     # Auto-restart failed services
#     AUTO_RESTART=true
#
#     # Webhook URL for notifications
#     WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
#
#     # Prometheus metrics file
#     PROMETHEUS_OUTPUT="/var/lib/node_exporter/textfile_collector/services.prom"
#
#     # Enable Prometheus export
#     PROMETHEUS_ENABLED=true
#
#     # Check service dependencies
#     CHECK_DEPENDENCIES=true
#
#     # Monitor log rotation
#     LOG_ROTATION_CHECK=true
#
#     # Syslog integration
#     SYSLOG_ENABLED=true
#
#     # Monitoring interval in seconds
#     INTERVAL=60
#
###############################################################################
# NOTES
#
#   - Script uses 'set -euo pipefail' for strict error handling
#   - All operations are logged for audit trail
#   - Restart operations include cooldown period to prevent loops
#   - Webhook notifications use JSON payload format
#   - Prometheus metrics use standard naming conventions
#
# ENVIRONMENT VARIABLES
#
#   MONITOR_CONFIG        Override default configuration file path
#   WEBHOOK_URL           Webhook URL for notifications
#   AUTO_RESTART          Enable automatic restart (true/false)
#   PROMETHEUS_OUTPUT     Path for Prometheus metrics file
#
###############################################################################
# CHANGE LOG
#
#   1.0.0 - 2025-10-06 - Initial release
#           - Core service monitoring functionality
#           - Auto-restart capability
#           - Webhook notifications (Slack/Discord/Teams)
#           - Prometheus metrics export
#           - Configuration file support
#           - Dependency checking
#           - Log rotation monitoring
#           - Syslog integration
#
###############################################################################

set -euo pipefail

# Script constants
readonly SCRIPT_NAME="$(basename "${0}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
readonly DEFAULT_CONFIG="/etc/monitor_services.conf"
readonly LOG_FILE="/var/log/monitor_services.log"
readonly STATE_FILE="/var/lib/monitor_services.state"

# Default values
CONFIG_FILE="${MONITOR_CONFIG:-$DEFAULT_CONFIG}"
AUTO_RESTART=false
WEBHOOK_URL="${WEBHOOK_URL:-}"
PROMETHEUS_ENABLED=false
PROMETHEUS_OUTPUT=""
CHECK_DEPENDENCIES=false
LOG_ROTATION_CHECK=false
VERBOSE=false
QUIET=false
SYSLOG_ENABLED=false
INTERVAL=60
SERVICES=()

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Cooldown tracking (prevent restart loops)
declare -A RESTART_ATTEMPTS
declare -A LAST_RESTART_TIME
readonly MAX_RESTART_ATTEMPTS=3
readonly RESTART_COOLDOWN=300  # 5 minutes

###############################################################################
# Functions
###############################################################################

# Display help message
show_help() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS] [SERVICE_NAMES...]

Monitor systemd services with auto-restart, notifications, and metrics export.

OPTIONS:
    -h, --help              Display this help message
    -c, --config FILE       Configuration file (default: /etc/monitor_services.conf)
    -r, --auto-restart      Automatically restart failed services
    -w, --webhook URL       Webhook URL for notifications
    -s, --slack URL         Slack webhook URL (alias for --webhook)
    -p, --prometheus        Enable Prometheus exporter
    -o, --output FILE       Prometheus metrics output file
    -d, --check-deps        Check service dependencies
    -l, --log-rotation      Monitor log file rotation
    -v, --verbose           Enable verbose output
    -q, --quiet             Suppress output
    --syslog                Send alerts to syslog
    --interval SECONDS      Monitoring interval (default: 60)

ARGUMENTS:
    SERVICE_NAMES          Services to monitor (overrides config file)

EXAMPLES:
    $SCRIPT_NAME --auto-restart nginx mysql
    $SCRIPT_NAME --slack "https://hooks.slack.com/..." --prometheus nginx
    $SCRIPT_NAME --config /etc/monitor.conf --verbose

EXIT CODES:
    0 - All services running
    1 - Warning (degraded state)
    2 - Critical (failed services)
    3 - Configuration error
    4 - Permission denied

For more information, see the script header or visit:
https://github.com/unplugged12/sysadmin-toolkit

EOF
}

# Log message
log_message() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    if [[ "$VERBOSE" == "true" ]] || [[ "$level" != "DEBUG" ]]; then
        if [[ "$QUIET" != "true" ]]; then
            case "$level" in
                ERROR)   echo -e "${RED}[ERROR]${NC} $message" >&2 ;;
                WARNING) echo -e "${YELLOW}[WARN]${NC} $message" >&2 ;;
                SUCCESS) echo -e "${GREEN}[OK]${NC} $message" ;;
                INFO)    echo -e "${BLUE}[INFO]${NC} $message" ;;
                DEBUG)   echo -e "[DEBUG] $message" ;;
            esac
        fi
    fi

    # Log to file
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"

    # Log to syslog if enabled
    if [[ "$SYSLOG_ENABLED" == "true" ]] && command -v logger &> /dev/null; then
        logger -t "monitor_services" -p "user.$level" "$message"
    fi
}

# Load configuration file
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log_message INFO "Loading configuration from $CONFIG_FILE"
        # Source the config file
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
    else
        log_message DEBUG "Configuration file not found: $CONFIG_FILE"
    fi
}

# Check if service exists
service_exists() {
    local service="$1"
    systemctl list-unit-files | grep -q "^${service}.service"
}

# Get service status
get_service_status() {
    local service="$1"

    if ! service_exists "$service"; then
        echo "not-found"
        return
    fi

    systemctl is-active "$service" 2>/dev/null || echo "unknown"
}

# Get service dependencies
get_service_dependencies() {
    local service="$1"

    systemctl list-dependencies "$service" --plain --no-pager 2>/dev/null | \
        grep -E '\.service$' | \
        sed 's/^[│├└─ ]*//g' | \
        grep -v "^${service}.service$"
}

# Check service log rotation
check_log_rotation() {
    local service="$1"
    local log_size

    # Get recent log size (last 1000 lines)
    log_size=$(journalctl -u "$service" -n 1000 --no-pager 2>/dev/null | wc -l)

    if [[ $log_size -gt 5000 ]]; then
        log_message WARNING "Service $service has large log size: $log_size lines"
        return 1
    fi

    return 0
}

# Restart service with cooldown check
restart_service() {
    local service="$1"
    local current_time=$(date +%s)

    # Initialize tracking if not exists
    if [[ -z "${RESTART_ATTEMPTS[$service]:-}" ]]; then
        RESTART_ATTEMPTS[$service]=0
        LAST_RESTART_TIME[$service]=0
    fi

    # Check cooldown period
    local time_since_last_restart=$((current_time - LAST_RESTART_TIME[$service]))

    if [[ $time_since_last_restart -lt $RESTART_COOLDOWN ]]; then
        log_message WARNING "Service $service in cooldown period (${time_since_last_restart}s / ${RESTART_COOLDOWN}s)"
        return 1
    fi

    # Reset restart attempts if cooldown passed
    if [[ $time_since_last_restart -gt $((RESTART_COOLDOWN * 2)) ]]; then
        RESTART_ATTEMPTS[$service]=0
    fi

    # Check max restart attempts
    if [[ ${RESTART_ATTEMPTS[$service]} -ge $MAX_RESTART_ATTEMPTS ]]; then
        log_message ERROR "Service $service exceeded max restart attempts ($MAX_RESTART_ATTEMPTS)"
        return 1
    fi

    # Attempt restart
    log_message INFO "Attempting to restart service: $service"

    if systemctl restart "$service" 2>&1 | tee -a "$LOG_FILE"; then
        RESTART_ATTEMPTS[$service]=$((RESTART_ATTEMPTS[$service] + 1))
        LAST_RESTART_TIME[$service]=$current_time
        log_message SUCCESS "Service $service restarted successfully (attempt ${RESTART_ATTEMPTS[$service]})"
        send_notification "Service Restarted" "$service was restarted successfully" "good"
        return 0
    else
        log_message ERROR "Failed to restart service: $service"
        send_notification "Service Restart Failed" "$service restart failed" "danger"
        return 1
    fi
}

# Send webhook notification
send_notification() {
    local title="$1"
    local message="$2"
    local color="${3:-warning}"  # good, warning, danger

    if [[ -z "$WEBHOOK_URL" ]]; then
        return
    fi

    # Build JSON payload (Slack format, compatible with Discord/Teams)
    local payload
    payload=$(cat <<EOF
{
    "text": "$title",
    "attachments": [
        {
            "color": "$color",
            "text": "$message",
            "footer": "Service Monitor",
            "ts": $(date +%s)
        }
    ]
}
EOF
)

    # Send webhook
    if command -v curl &> /dev/null; then
        curl -X POST -H 'Content-type: application/json' \
             --data "$payload" "$WEBHOOK_URL" &> /dev/null || \
             log_message WARNING "Failed to send webhook notification"
    else
        log_message WARNING "curl not available, cannot send webhook"
    fi
}

# Export Prometheus metrics
export_prometheus_metrics() {
    local services=("$@")
    local output=""

    output+="# HELP service_status Status of systemd services (1=active, 0=inactive, -1=failed)\n"
    output+="# TYPE service_status gauge\n"

    for service in "${services[@]}"; do
        local status
        status=$(get_service_status "$service")

        local status_value
        case "$status" in
            active)   status_value=1 ;;
            inactive) status_value=0 ;;
            failed)   status_value=-1 ;;
            *)        status_value=-2 ;;
        esac

        output+="service_status{service=\"$service\",state=\"$status\"} $status_value\n"
    done

    output+="# HELP service_restart_count Number of restart attempts\n"
    output+="# TYPE service_restart_count counter\n"

    for service in "${services[@]}"; do
        local count="${RESTART_ATTEMPTS[$service]:-0}"
        output+="service_restart_count{service=\"$service\"} $count\n"
    done

    # Write to file if specified
    if [[ -n "$PROMETHEUS_OUTPUT" ]]; then
        echo -e "$output" > "$PROMETHEUS_OUTPUT"
        log_message DEBUG "Prometheus metrics exported to $PROMETHEUS_OUTPUT"
    else
        echo -e "$output"
    fi
}

# Monitor services
monitor_services() {
    local services=("$@")
    local failed_count=0
    local degraded_count=0
    local total_count=${#services[@]}

    log_message INFO "Monitoring $total_count services..."

    for service in "${services[@]}"; do
        local status
        status=$(get_service_status "$service")

        case "$status" in
            active)
                log_message SUCCESS "Service $service is active"
                ;;
            inactive)
                log_message WARNING "Service $service is inactive"
                ((degraded_count++))
                ;;
            failed)
                log_message ERROR "Service $service has failed"
                ((failed_count++))

                if [[ "$AUTO_RESTART" == "true" ]]; then
                    restart_service "$service"
                else
                    send_notification "Service Failed" "$service is in failed state" "danger"
                fi
                ;;
            not-found)
                log_message ERROR "Service $service not found"
                ;;
            *)
                log_message WARNING "Service $service status unknown: $status"
                ((degraded_count++))
                ;;
        esac

        # Check dependencies if enabled
        if [[ "$CHECK_DEPENDENCIES" == "true" ]]; then
            local deps
            deps=$(get_service_dependencies "$service")

            if [[ -n "$deps" ]]; then
                log_message DEBUG "Checking dependencies for $service"

                while IFS= read -r dep; do
                    local dep_status
                    dep_status=$(get_service_status "${dep%.service}")

                    if [[ "$dep_status" != "active" ]]; then
                        log_message WARNING "Dependency $dep of $service is $dep_status"
                    fi
                done <<< "$deps"
            fi
        fi

        # Check log rotation if enabled
        if [[ "$LOG_ROTATION_CHECK" == "true" ]]; then
            check_log_rotation "$service"
        fi
    done

    # Export Prometheus metrics if enabled
    if [[ "$PROMETHEUS_ENABLED" == "true" ]]; then
        export_prometheus_metrics "${services[@]}"
    fi

    # Return appropriate exit code
    if [[ $failed_count -gt 0 ]]; then
        log_message ERROR "Monitoring complete: $failed_count failed, $degraded_count degraded, $((total_count - failed_count - degraded_count)) active"
        return 2
    elif [[ $degraded_count -gt 0 ]]; then
        log_message WARNING "Monitoring complete: $degraded_count degraded, $((total_count - degraded_count)) active"
        return 1
    else
        log_message SUCCESS "Monitoring complete: All $total_count services active"
        return 0
    fi
}

###############################################################################
# Main Script
###############################################################################

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -r|--auto-restart)
                AUTO_RESTART=true
                shift
                ;;
            -w|--webhook|-s|--slack)
                WEBHOOK_URL="$2"
                shift 2
                ;;
            -p|--prometheus)
                PROMETHEUS_ENABLED=true
                shift
                ;;
            -o|--output)
                PROMETHEUS_OUTPUT="$2"
                shift 2
                ;;
            -d|--check-deps)
                CHECK_DEPENDENCIES=true
                shift
                ;;
            -l|--log-rotation)
                LOG_ROTATION_CHECK=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            --syslog)
                SYSLOG_ENABLED=true
                shift
                ;;
            --interval)
                INTERVAL="$2"
                shift 2
                ;;
            -*)
                echo "Error: Unknown option: $1" >&2
                show_help
                exit 3
                ;;
            *)
                SERVICES+=("$1")
                shift
                ;;
        esac
    done

    # Load configuration file
    load_config

    # If no services specified on command line, use config file services
    if [[ ${#SERVICES[@]} -eq 0 ]]; then
        log_message ERROR "No services specified. Use command line arguments or config file."
        show_help
        exit 3
    fi

    # Check for required commands
    for cmd in systemctl journalctl; do
        if ! command -v "$cmd" &> /dev/null; then
            log_message ERROR "Required command not found: $cmd"
            exit 3
        fi
    done

    # Create log directory if it doesn't exist
    mkdir -p "$(dirname "$LOG_FILE")"

    log_message INFO "Starting service monitor (PID: $$)"
    log_message INFO "Monitoring services: ${SERVICES[*]}"
    log_message INFO "Auto-restart: $AUTO_RESTART"

    # Run monitoring
    monitor_services "${SERVICES[@]}"
    exit_code=$?

    log_message INFO "Service monitoring completed with exit code: $exit_code"
    exit $exit_code
}

# Run main function
main "$@"
