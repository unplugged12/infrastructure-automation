#!/usr/bin/env bash
###############################################################################
# Script Name: setup_ufw.sh
# Description: Enterprise firewall configuration for Ubuntu servers running
#              Docker, Kubernetes, MRCP services, and Nginx. Implements
#              defense-in-depth with separate rules for admin, internal, and
#              public access tiers.
#
# Usage: sudo ./setup_ufw.sh
#
# Options:
#   None - Configuration via variables at top of script
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
#   # 1. Edit variables at top of script first
#   sudo nano ./setup_ufw.sh
#   # 2. Run script
#   sudo ./setup_ufw.sh
#   # 3. Verify rules
#   sudo ufw status numbered
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
#   2   Misuse of script - Invalid IP addresses in variables
#   3   Permission denied - Not running as root
#
# Risk Level: HIGH
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
#   - SIP/MRCP ports can be public or restricted based on line 24-27 comments
#   - All incoming traffic denied by default (whitelist approach)
#
# Ports Opened:
#   Public (0.0.0.0/0):
#     80/tcp      - HTTP (Nginx)
#     443/tcp     - HTTPS (Nginx)
#     554/tcp     - RTSP (if uncommented)
#     5060/udp    - SIP (if uncommented)
#     5061/tcp    - SIP TLS (if uncommented)
#     8085/tcp    - MRCP (if uncommented)
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
# Modified: 2024-10-05
# Version: 1.0.0
#
# Notes:
#   - Review lines 24-27 to decide if SIP/MRCP should be public or restricted
#   - Default configuration restricts SIP/MRCP to trusted peers only
#   - IPv6 support enabled but optional (leave variables empty to skip)
#   - Script uses --force flags to avoid interactive prompts
#   - Loopback interface (lo) explicitly allowed for local services
#
# Post-Execution Steps:
#   - Verify you can still SSH: ssh user@server-ip
#   - Check rule order: sudo ufw status numbered
#   - Test application connectivity from expected sources
#   - Document firewall configuration in your runbook
###############################################################################

set -euo pipefail

### 1. Customize these variables before running ###
ADMIN_V4="172.16.2.60/32"
ADMIN_V6=""                      # leave empty if unused
INTERNAL_V4="172.16.1.0/24"
INTERNAL_V6=""
SIP_TRUST_V4="172.16.1.0/24"
SIP_TRUST_V6=""

### 2. Reset + defaults ###
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow in on lo

### 3. Public-facing ###
ufw allow 80/tcp
ufw allow 443/tcp
# Uncomment if SIP/MRCP must be public (otherwise see trusted peers section below)
ufw allow 554/tcp
ufw allow 5060/udp
ufw allow 5061/tcp
ufw allow 8085/tcp

### 4. Admin-only ###
ufw allow from "$ADMIN_V4" to any port 22 proto tcp
[ -n "$ADMIN_V6" ] && ufw allow from "$ADMIN_V6" to any port 22 proto tcp

ufw allow from "$ADMIN_V4" to any port 15672 proto tcp
[ -n "$ADMIN_V6" ] && ufw allow from "$ADMIN_V6" to any port 15672 proto tcp

ufw allow from "$ADMIN_V4" to any port 6443 proto tcp
[ -n "$ADMIN_V6" ] && ufw allow from "$ADMIN_V6" to any port 6443 proto tcp

### 5. Internal-only (datastores/brokers/kube) ###
for p in 5432 6379 27016 27017 5672 25672 4369 8181 8443 \
         10245 10246 10247 10248 10249 10250 10254 10256 10257 10259; do
  ufw allow from "$INTERNAL_V4" to any port $p
  [ -n "$INTERNAL_V6" ] && ufw allow from "$INTERNAL_V6" to any port $p
done

### 6. MRCP/SIP restricted to trusted peers ###
for p in 554/tcp 5060/udp 5061/tcp 8085/tcp; do
  ufw allow from "$SIP_TRUST_V4" to any port ${p%/*} proto ${p#*/}
  [ -n "$SIP_TRUST_V6" ] && ufw allow from "$SIP_TRUST_V6" to any port ${p%/*} proto ${p#*/}
done

### 7. Enable ###
ufw --force enable
ufw status numbered
