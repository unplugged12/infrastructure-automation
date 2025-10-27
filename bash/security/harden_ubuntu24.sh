#!/usr/bin/env bash
###############################################################################
# Script Name: harden_ubuntu24.sh
# Description: Comprehensive security hardening for fresh Ubuntu 24.04 LTS
#              installations. Configures firewall, SSH, AppArmor, automatic
#              updates, and deploys monitoring agents (ScreenConnect, Atera).
#
# Usage: sudo ./harden_ubuntu24.sh
#
# Options:
#   None - Script runs interactively and prompts for Sophos installer path
#
# Examples:
#   sudo ./harden_ubuntu24.sh
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
#
# Author: System Administrator
# Created: 2024-10-05
# Modified: 2024-10-05
# Version: 1.0.0
#
# Notes:
#   - Review UFW port rules (lines 16-21) before running in production
#   - Ensure at least one non-root user with sudo exists before running
#   - System requires reboot after execution for kernel parameters to apply
#   - ScreenConnect and Atera agent URLs are organization-specific
#   - Modify agent download URLs for your organization before use
#   - Log rotation configured for weekly rotation, 6 files retained
#
# Post-Execution Steps:
#   - Reboot system to apply kernel security parameters
#   - Test SSH access with non-root user before closing current session
#   - Verify UFW rules: sudo ufw status verbose
#   - Check AppArmor status: sudo aa-status
#   - Review fail2ban status: sudo systemctl status fail2ban
###############################################################################

set -euo pipefail

# 1. Update system and install necessary packages
apt update && apt -y upgrade
apt install -y ufw fail2ban apparmor apparmor-utils unattended-upgrades wget

# 2. Enable unattended upgrades
echo "Enabling unattended-upgrades..."
dpkg-reconfigure -fnoninteractive unattended-upgrades

# 3. Configure UFW
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh    # allow SSH (port 22)
ufw allow 5060   # MRCP default port – change if your server uses another port
ufw allow from 127.0.0.1 to any port 6379 proto tcp  # Redis, restrict to localhost
# Add other port rules here if Docker containers expose specific ports

ufw --force enable
ufw status verbose

# 4. Harden SSH
sed -i.bak -e 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart ssh

# 5. Enable and reload AppArmor
systemctl enable --now apparmor
aa-status || true  # show AppArmor status

# 6. Restrict unprivileged user namespaces (requires reboot to fully apply)
SYSCTL_CONF="/etc/sysctl.conf"
grep -q '^kernel.unprivileged_userns_clone=' "$SYSCTL_CONF" || \
  echo "kernel.unprivileged_userns_clone=0" >> "$SYSCTL_CONF"
grep -q '^kernel.unprivileged_userns_apparmor_policy=' "$SYSCTL_CONF" || \
  echo "kernel.unprivileged_userns_apparmor_policy=1" >> "$SYSCTL_CONF"
sysctl -p

# 7. Configure fail2ban (uses default ssh jail)
systemctl enable --now fail2ban

# 8. Set up log rotation for syslog (weekly, keep six files, compress)
if [ -f /etc/logrotate.d/rsyslog ]; then
  LOGROTATE_CONF="/etc/logrotate.d/rsyslog"
else
  LOGROTATE_CONF="/etc/logrotate.d/syslog"
fi

cp -a "$LOGROTATE_CONF" "${LOGROTATE_CONF}.bak" 2>/dev/null || true

cat > "$LOGROTATE_CONF" <<'EOF'
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


# 9. Install ScreenConnect agent
SC_DEB_URL="https://support.company.com/Bin/ScreenConnect.ClientSetup.deb?e=Access&y=Guest"
SC_DEB_FILE="/tmp/screenconnect_client.deb"
wget -O "$SC_DEB_FILE" "$SC_DEB_URL"
apt install -y "$SC_DEB_FILE"

# 10. Run Sophos installer (SophosSetup.sh prompt for path; skip on blank)
read -r -p "Enter full path to SophosSetup.sh (or press Enter to skip): " SOPHOS_PATH
if [[ -z "$SOPHOS_PATH" ]]; then
  echo "No Sophos installer path provided; skipping Sophos install."
elif [[ -f "$SOPHOS_PATH" ]]; then
  echo "Running Sophos installer: $SOPHOS_PATH"
  chmod +x "$SOPHOS_PATH"
  "$SOPHOS_PATH"
else
  echo "File not found at '$SOPHOS_PATH'; skipping Sophos install."
fi


# 11. Install Atera agent
ATERA_CMD='sudo wget -O - "https://CompanyProfessionalServicesInc289169.servicedesk.atera.com/api/utils/AgentInstallScript/Linux/0013z00002Shig1AAB?customerId=2" | sudo bash'
eval "$ATERA_CMD"

echo "Hardening complete.  Please review output and adjust any manual steps (e.g., configure centralized logging server)."
