#!/usr/bin/env bash
###############################################################################
# Script Name: check_ports.sh
# Description: Compares listening network ports against UFW firewall allow
#              rules to identify security gaps and unused firewall rules.
#              Helps audit firewall configuration for proper coverage.
#
# Usage: ./check_ports.sh
#
# Options:
#   None - Script runs automatically
#
# Examples:
#   ./check_ports.sh
#   ./check_ports.sh > port_audit_$(date +%Y%m%d).txt
#
# Prerequisites:
#   - ss command available (standard in modern Linux)
#   - ufw firewall installed and enabled
#   - Read access to UFW status (no root required)
#
# Exit Codes:
#   0   Success - Comparison completed (findings reported in output)
#   1   General error - Required commands not found
#
# Risk Level: LOW
#   - Read-only operation
#   - No system changes made
#   - Safe to run on production systems
#
# Output Sections:
#   1. Listening ports - All TCP/UDP ports currently bound by services
#   2. UFW allowed ports - Ports explicitly allowed in firewall rules
#   3. Listening but NOT allowed - Services without firewall rules (security gap)
#   4. Allowed but NOT listening - Firewall rules for inactive services (cleanup candidate)
#
# Security Considerations:
#   - "Listening but NOT allowed" indicates potential security issues:
#     * Services exposed locally but blocked by firewall (good)
#     * Services that should have firewall rules but don't (investigate)
#   - "Allowed but NOT listening" may indicate:
#     * Stopped services that still have firewall rules (safe, but can cleanup)
#     * Services that should be running but aren't (investigate)
#
# Author: System Administrator
# Created: 2024-10-05
# Modified: 2024-10-05
# Version: 1.0.0
#
# Notes:
#   - Script uses process substitution - requires bash (not sh)
#   - Port comparison is numeric only (doesn't match service names)
#   - Only checks ports, not IP address restrictions
#   - UFW rules with IP restrictions show port only
#   - Loopback-only services appear in "Listening but NOT allowed"
#
# Interpretation Guide:
#   Listening but NOT allowed:
#     - Expected for localhost-only services (127.0.0.1)
#     - Investigate if public services appear here
#
#   Allowed but NOT listening:
#     - Normal for on-demand services
#     - May indicate stopped services
#     - Consider cleanup if service permanently removed
#
# Post-Execution Steps:
#   - Review "Listening but NOT allowed" for security gaps
#   - Investigate any unexpected public services without firewall rules
#   - Clean up unused firewall rules if services permanently disabled
###############################################################################

# Compare listening ports vs. UFW allow rules

listening=$(ss -tuln | awk '{print $5}' | grep -oE '[0-9]+$' | sort -un | uniq)
allowed=$(ufw status | awk '/ALLOW/ {print $NF}' | grep -oE '[0-9]+' | sort -un | uniq)

echo "=== Listening ports ==="
echo "$listening"
echo
echo "=== UFW allowed ports ==="
echo "$allowed"
echo
echo "=== Listening but NOT allowed ==="
comm -23 <(echo "$listening") <(echo "$allowed")
echo
echo "=== Allowed but NOT listening ==="
comm -13 <(echo "$listening") <(echo "$allowed")
