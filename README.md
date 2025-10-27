# Infrastructure Automation Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20SQL-lightgrey)](https://github.com/unplugged12/infrastructure-automation)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-success)](https://github.com/unplugged12/infrastructure-automation)

> **Enterprise-grade automation scripts for Windows, Linux, and SQL Server infrastructure management.**

## Overview

This repository contains **35+ production-tested scripts** demonstrating enterprise infrastructure automation across multiple platforms. These scripts showcase real-world operational experience in managing complex, multi-platform environments with a focus on **security, reliability, and operational excellence**.

### What This Repository Demonstrates

- **🏢 Enterprise Experience** - Scripts used in production environments managing 500+ systems
- **🔒 Security-First Approach** - Hardening, compliance, and least-privilege automation
- **⚙️ Cross-Platform Expertise** - Windows (PowerShell), Linux (Bash), SQL Server (T-SQL)
- **📊 Operational Excellence** - Monitoring, patching, backup, and high-availability operations
- **🧪 Production Quality** - Comprehensive error handling, logging, and documentation

### Key Capabilities

| Category | Description | Scripts |
|----------|-------------|---------|
| **Active Directory** | User lifecycle management, group administration, security policies | 6 scripts |
| **Security Hardening** | CIS benchmarks, firewall automation, certificate management | 9 scripts |
| **System Monitoring** | Disk space, event logs, port scanning, service health | 4 scripts |
| **SQL Server HA** | Availability group operations, failover automation, monitoring | 8 scripts |
| **Patch Management** | Automated Windows/Linux updates, compliance reporting | 3 scripts |
| **System Maintenance** | Cleanup operations, file management, backup automation | 5 scripts |

---

## 🔒 Security Notice

**IMPORTANT:** All scripts in this repository have been **sanitized for public sharing**. Company-specific information, credentials, and internal network details have been replaced with placeholders.

### Before Using These Scripts

1. ✅ **Replace all `<YOUR_*>` placeholders** with your environment values
2. ✅ **Replace `company.local`** with your actual domain
3. ✅ **Never use default/example passwords** in production
4. ✅ **Review and test in non-production** environment first
5. ✅ **Understand what each script does** before execution

---

## 📁 Repository Structure

```
infrastructure-automation/
├── powershell/              # Windows automation scripts
│   ├── user-management/         # AD user lifecycle (onboarding, offboarding)
│   ├── security/                # Security hardening, certificate management
│   ├── monitoring/              # System health monitoring
│   ├── maintenance/             # Cleanup and maintenance tasks
│   ├── device-management/       # Autopilot, device enrollment
│   └── FolderRedirection/       # User profile management
│
├── bash/                    # Linux administration scripts
│   ├── security/                # UFW firewall, Ubuntu hardening (CIS/STIG)
│   └── monitoring/              # Port scanning, service health checks
│
├── sql/                     # SQL Server administration
│   └── high-availability/
│       ├── failover/            # Availability group failover operations
│       └── monitoring/          # AG health monitoring queries
│
├── scripts/                 # Cross-cutting operations
│   ├── backup/                  # Backup automation
│   └── patch-management/        # Update deployment and compliance
│
└── docs/                    # Documentation
    ├── POWERSHELL.md           # PowerShell scripts guide
    ├── BASH.md                 # Linux scripts guide
    └── SQL.md                  # SQL scripts guide
```

---

## 🚀 Quick Start

### Prerequisites

**For PowerShell Scripts:**
- PowerShell 5.1+ (Windows) or PowerShell 7+ (cross-platform)
- Active Directory PowerShell module (for AD operations)
- Appropriate permissions (varies by script)

**For Bash Scripts:**
- Bash 4.0+
- Root or sudo access (for system-level operations)
- Ubuntu/Debian-based system (scripts are tailored for Ubuntu 24.04)

**For SQL Scripts:**
- SQL Server 2016+ (compatible with 2008R2+)
- VIEW SERVER STATE permission (for monitoring)
- CONTROL SERVER permission (for failover operations)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/unplugged12/infrastructure-automation.git
   cd infrastructure-automation
   ```

2. **Review scripts before execution:**
   ```powershell
   # PowerShell: View script help
   Get-Help .\powershell\user-management\New-UserOnboarding.ps1 -Detailed
   ```

3. **Customize for your environment:**
   - Replace all placeholders (`<YOUR_*>`, `company.local`, etc.)
   - Update domain names, IP addresses, and credentials
   - Review security settings and adjust for your policies

### Example Usage

**PowerShell - User Onboarding:**
```powershell
# Review the script first
Get-Help .\powershell\user-management\New-UserOnboarding.ps1 -Full

# Run with WhatIf to preview actions
.\powershell\user-management\New-UserOnboarding.ps1 -WhatIf

# Execute (after customization)
.\powershell\user-management\New-UserOnboarding.ps1
```

**Bash - Ubuntu Hardening:**
```bash
# Make executable
chmod +x bash/security/harden_ubuntu24.sh

# Review script contents
less bash/security/harden_ubuntu24.sh

# Execute with sudo
sudo ./bash/security/harden_ubuntu24.sh
```

**SQL - Availability Group Monitoring:**
```sql
-- Open in SQL Server Management Studio
-- Run against primary replica
-- File: sql/high-availability/monitoring/ListAvailabilityGroups.sql
```

---

## Skills Showcase

### Technical Leadership

- **Infrastructure Architecture** - Design and implementation of multi-platform automation
- **Security Governance** - Compliance automation (CIS, STIG), security hardening
- **High Availability** - SQL Server Always On configuration and failover operations
- **Operational Excellence** - Monitoring, alerting, and proactive maintenance

### Platform Expertise

**Windows/Active Directory:**
- User lifecycle automation (onboarding, offboarding, modification)
- Group Policy and security baseline enforcement
- Certificate management and PKI operations
- PowerShell DSC and advanced scripting

**Linux:**
- Security hardening (UFW firewall, fail2ban, AppArmor)
- CIS benchmark automation for Ubuntu
- Service monitoring and health checks
- Bash scripting with error handling

**SQL Server:**
- Always On Availability Group operations
- Automated failover procedures
- Health monitoring and alerting
- T-SQL stored procedures and automation

### DevOps Practices

- **Infrastructure as Code** - Scripts version-controlled and repeatable
- **Documentation** - Comprehensive inline help and README guides
- **Testing** - Pester tests for PowerShell functions
- **Security** - Secrets management, least privilege, audit logging

---

## 📖 Documentation

### Script Documentation

All scripts include comprehensive inline documentation:
- **Synopsis** - Brief description of purpose
- **Description** - Detailed functionality explanation
- **Parameters** - Input parameter documentation
- **Examples** - Usage examples with explanations
- **Notes** - Prerequisites, permissions, security considerations

### Platform-Specific Guides

- **[PowerShell Scripts Guide](docs/POWERSHELL.md)** - Windows automation reference
- **[Bash Scripts Guide](docs/BASH.md)** - Linux operations reference
- **[SQL Scripts Guide](docs/SQL.md)** - Database administration reference

### Security & Contributing

- **[SECURITY.md](SECURITY.md)** - Security policy and best practices
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Contribution guidelines

---

## ⚠️ Risk Levels & Usage Guidelines

Scripts are categorized by operational risk:

### 🔴 High Risk - Requires Approval
- User onboarding/offboarding scripts
- Password hash extraction utilities
- System hardening with external dependencies
- SQL Server failover operations

**Guidelines:** Test in lab environment, require peer review, document changes

### 🟡 Medium Risk - Requires Testing
- File deletion/cleanup operations
- Permission modifications
- Firewall configuration changes
- System configuration changes

**Guidelines:** Test with `-WhatIf` flag, verify backup exists, review logs

### ✅ Low Risk - Safe for Production
- Monitoring and reporting scripts
- Read-only information gathering
- Health check queries
- Audit log analysis

**Guidelines:** Safe for direct use, minimal testing required

---

## 🔧 Development & Testing

### Testing PowerShell Scripts

```powershell
# View script help
Get-Help .\script.ps1 -Detailed

# Test with WhatIf (dry-run)
.\script.ps1 -WhatIf

# Run with verbose output
.\script.ps1 -Verbose

# Run Pester tests (where available)
Invoke-Pester -Path .\powershell\FolderRedirection\Tests\
```

### Testing Bash Scripts

```bash
# Check syntax
bash -n script.sh

# Run with verbose/debug output
bash -x script.sh

# Run with dry-run flag (if supported)
./script.sh --dry-run
```

### Required Dependencies

**PowerShell Modules:**
```powershell
# Install required modules
Install-Module ActiveDirectory -Force
Install-Module Microsoft.Graph -Force
```

**Linux Packages:**
```bash
# Ubuntu/Debian
sudo apt install ufw fail2ban apparmor-utils

# Verify bash version
bash --version  # Requires 4.0+
```

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-script`)
3. Test your changes thoroughly
4. Document your code with inline help
5. Submit a pull request

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🎯 Use Cases

### For System Administrators
- Ready-to-use automation for common tasks
- Best practices for security hardening
- Templates for creating custom automation

### For IT Leaders
- Demonstration of automation capabilities
- Examples of infrastructure as code
- Security and compliance automation patterns

### For DevOps Engineers
- Cross-platform scripting examples
- CI/CD integration patterns
- Infrastructure automation templates

---

## 📞 Support & Questions

For questions, issues, or feature requests:
- **Issues:** [GitHub Issues](https://github.com/unplugged12/infrastructure-automation/issues)
- **Discussions:** [GitHub Discussions](https://github.com/unplugged12/infrastructure-automation/discussions)

---

## 🙏 Acknowledgments

These scripts were developed and refined over 10+ years of enterprise IT operations, managing infrastructure across multiple industries and company sizes.

**Technologies:** PowerShell, Bash, T-SQL, Active Directory, SQL Server Always On, Ubuntu Server, Windows Server, Azure AD

---

**Built with a focus on security, reliability, and operational excellence.**
