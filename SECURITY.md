# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in these automation scripts, please report it responsibly:

### Preferred Method: GitHub Security Advisories
1. Go to the [Security tab](../../security/advisories)
2. Click "Report a vulnerability"
3. Fill out the form with detailed information

### Alternative Method: Email
If you prefer email or the issue is particularly sensitive:
- **Email:** Create a GitHub issue and mention `@unplugged12` for private discussion
- **Response Time:** We aim to acknowledge reports within 48 hours
- **Resolution:** Security fixes are prioritized and typically addressed within 7-14 days

### What to Include
When reporting a vulnerability, please provide:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Suggested remediation (if applicable)
- Your contact information (if you want credit)

## Security Best Practices

### For Deployment

#### Never Commit Secrets
- ✅ **DO:** Use Portainer Edge Configs for laptops
- ✅ **DO:** Use environment files on agent hosts (`/run/mcp/mcp.env`)
- ✅ **DO:** Store secrets in Portainer's encrypted database
- ❌ **DON'T:** Commit `.env` files, API keys, or passwords to Git
- ❌ **DON'T:** Store secrets in compose files

#### Secret Management
```bash
# Good: Reference environment file
env_file: ${MCP_ENV_FILE:-/run/mcp/mcp.env}

# Good: Use Portainer secrets
environment:
  - API_KEY=${PORTAINER_SECRET}

# Bad: Hardcoded credentials
environment:
  - API_KEY=sk-1234567890abcdef  # NEVER DO THIS
```

#### Access Control
- **Portainer Access:** Use role-based access control (RBAC)
- **API Keys:** Generate unique keys per user/service
- **SSH Keys:** Use key-based authentication, disable password auth
- **Network Segmentation:** Isolate management plane from workload plane

#### Container Security
- **Image Sources:** Only use trusted registries
- **Image Scanning:** Run security scans on images (Trivy, Grype)
- **Read-Only Root:** Use `read_only: true` where possible
- **Drop Capabilities:** Remove unnecessary Linux capabilities
- **User Namespaces:** Run containers as non-root users

#### Network Security
- **TLS Everywhere:** Use HTTPS for all web interfaces
- **Certificate Validation:** Never disable TLS verification
- **Firewall Rules:** Restrict ports to minimum required
- **VPN/Tailscale:** Use encrypted tunnels for remote access

#### Logging & Monitoring
- **Centralized Logging:** Aggregate logs for security analysis
- **Audit Trail:** Enable Portainer audit logging
- **Anomaly Detection:** Monitor for unusual behavior
- **Secret Scanning:** Use tools like `gitleaks` in CI/CD

### For Development

#### Before Committing
Run security checks locally:
```bash
# Scan for secrets
gitleaks detect --source . --verbose

# Scan for vulnerabilities
trivy config .
trivy fs .

# Validate configurations
docker compose -f stacks/desktop/docker-compose.yml config
```

#### CI/CD Security
- **Branch Protection:** Require reviews for main branch
- **Status Checks:** Mandate security scans pass before merge
- **Signed Commits:** Use GPG signing for commit verification
- **Dependency Scanning:** Monitor for vulnerable dependencies

### For Operations

#### Incident Response
1. **Detect:** Monitor logs and alerts
2. **Contain:** Isolate affected systems
3. **Investigate:** Analyze logs and forensics
4. **Remediate:** Apply patches and configuration changes
5. **Document:** Record lessons learned

#### Regular Maintenance
- **Update Images:** Pull latest security patches monthly
- **Rotate Secrets:** Change credentials every 90 days
- **Review Access:** Audit user permissions quarterly
- **Backup Configs:** Regular Portainer database backups

#### Disaster Recovery
- **Backup Strategy:** Automated backups of Portainer DB
- **Tested Restores:** Verify backups can be restored
- **Documentation:** Maintain runbooks for common scenarios
- **Rollback Plan:** Use Git history for configuration rollback

## Known Security Considerations

### Portainer CE Limitations
- Edge Stacks don't auto-sync via GitOps (manual redeploy required)
- No built-in secret encryption at rest (use OS-level encryption)
- Limited RBAC compared to Business Edition

**Mitigations:**
- Use manual redeploy workflow for Edge Stacks
- Encrypt Portainer database volume at OS level
- Implement network segmentation and access controls

### Container Escape Risks
Running privileged containers or mounting Docker socket presents risks.

**Mitigations:**
- Avoid `privileged: true` unless absolutely necessary
- Never mount `/var/run/docker.sock` in untrusted containers
- Use rootless Docker where possible
- Enable AppArmor/SELinux profiles

### Supply Chain Security
Third-party images may contain vulnerabilities or malicious code.

**Mitigations:**
- Use official images from trusted publishers
- Pin image versions (avoid `latest` tag in production)
- Scan images before deployment
- Maintain private registry for vetted images

## Security Tools & Resources

### Recommended Tools
- **Secret Scanning:** [gitleaks](https://github.com/gitleaks/gitleaks)
- **Container Scanning:** [Trivy](https://github.com/aquasecurity/trivy)
- **SAST Analysis:** [Semgrep](https://semgrep.dev/)
- **Image Signing:** [Cosign](https://github.com/sigstore/cosign)
- **Policy Enforcement:** [OPA/Gatekeeper](https://www.openpolicyagent.org/)

### Learning Resources
- [OWASP Container Security](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/security-checklist/)
- [NIST Container Security Guide](https://csrc.nist.gov/publications/detail/sp/800-190/final)

## Scope

This security policy applies to:
- ✅ Docker Compose configurations in `stacks/`
- ✅ Deployment scripts in `scripts/`
- ✅ CI/CD workflows in `.github/workflows/`
- ✅ Documentation and examples

This policy does NOT cover:
- ❌ Security of individual MCP server implementations (report to respective projects)
- ❌ Portainer CE security (report to [Portainer](https://github.com/portainer/portainer))
- ❌ Docker Engine security (report to [Docker](https://www.docker.com/security))

## Acknowledgments

We appreciate responsible disclosure and will credit security researchers who report valid vulnerabilities (unless they prefer to remain anonymous).

---

**Last Updated:** October 2025
**Policy Version:** 1.0

For questions about this security policy, open a GitHub Discussion or contact the maintainer.
