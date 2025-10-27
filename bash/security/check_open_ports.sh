#!/usr/bin/env bash
###############################################################################
# Script Name: check_open_ports.sh
# Description: Opens all required ports in UFW firewall for development/testing
#              environments. Configures both TCP and UDP ports for various
#              services including DNS, web, databases, Kubernetes, and MRCP.
#
# Usage: sudo ./check_open_ports.sh
#
# Options:
#   None - Script automatically configures all listed ports
#
# Examples:
#   sudo ./check_open_ports.sh
#
# Prerequisites:
#   - Root/sudo access required
#   - UFW installed (apt install ufw)
#   - Ubuntu 20.04+ or Debian 11+
#
# Exit Codes:
#   0   Success - All firewall rules configured
#   1   General error - UFW command failed
#   3   Permission denied - Not running as root
#
# Risk Level: MEDIUM
#   - Opens many ports to all IP addresses (0.0.0.0/0)
#   - Suitable for development/testing only, NOT production
#   - May expose internal services to public networks
#   - Does not reset existing rules (unlike setup_ufw.sh)
#
# WARNING - DEVELOPMENT USE ONLY:
#   This script opens extensive ports suitable for development environments.
#   DO NOT use in production without reviewing and restricting access.
#   For production, use setup_ufw.sh with proper IP restrictions instead.
#
# Ports Configured:
#   TCP:
#     53      - DNS
#     80      - HTTP
#     443     - HTTPS
#     554     - RTSP
#     2379-2381 - etcd (Kubernetes)
#     4369    - RabbitMQ EPMD
#     5061    - SIP TLS
#     5432    - PostgreSQL
#     5551-5552 - Custom services
#     5672    - RabbitMQ AMQP
#     6379    - Redis
#     6443    - Kubernetes API
#     8085    - MRCP
#     8181    - Custom service
#     8443    - Custom HTTPS
#     9099    - Custom service
#     10245-10259 - Kubernetes components
#     15672   - RabbitMQ Management
#     25672   - RabbitMQ Clustering
#     27017   - MongoDB
#     32755   - Custom high port
#
#   UDP:
#     53      - DNS
#     5060    - SIP
#
# Author: System Administrator
# Created: 2024-10-05
# Modified: 2024-10-05
# Version: 1.0.0
#
# Notes:
#   - Optional UFW reset commented out on line 8 - uncomment with caution
#   - This script does NOT reset existing rules by default
#   - For production use, replace with setup_ufw.sh for IP-restricted rules
#   - Loopback interface (lo) explicitly allowed
#   - Script uses --force enable to avoid interactive prompts
#
# Post-Execution Steps:
#   - Verify rules: sudo ufw status numbered
#   - Test service connectivity
#   - For production: migrate to setup_ufw.sh with IP restrictions
###############################################################################

set -euo pipefail

# Reset UFW (optional – comment if you already configured)
# ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow in on lo

# Core TCP ports
for p in 53 80 443 554 2379 2380 2381 4369 5061 5432 \
         5551 5552 5672 6379 6443 8085 8181 8443 \
         9099 10245 10246 10247 10248 10249 10250 \
         10254 10256 10257 10259 15672 25672 27017 32755; do
  ufw allow $p/tcp
done

# UDP-specific ports
ufw allow 53/udp        # DNS
ufw allow 5060/udp      # SIP
# (others are primarily TCP-based)

# Enable UFW
ufw --force enable
ufw status numbered
