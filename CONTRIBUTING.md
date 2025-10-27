# Contributing to MCP Stacks

Thank you for your interest in contributing to **mcp-stacks**! We welcome contributions from the community to help improve this GitOps platform.

This guide will help you understand our development process, coding standards, and how to submit quality contributions.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Community](#community)

## Code of Conduct

This project adheres to a code of conduct that all contributors are expected to follow. Be respectful, inclusive, and professional in all interactions. Harassment, discrimination, and abusive behavior will not be tolerated.

## Getting Started

### Prerequisites

Before contributing, ensure you have:
- **Git** installed and configured
- **Docker Desktop** (or Docker Engine + Docker Compose)
- **PowerShell 7+** (`pwsh`) for PowerShell scripts
- **Bash** (WSL, Git Bash, or native) for shell scripts
- **GitHub CLI** (`gh`) - recommended for workflow automation
- **A Portainer instance** for testing (optional but recommended)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/mcp-stacks.git
   cd mcp-stacks
   ```
3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/unplugged12/mcp-stacks.git
   ```

### Stay Synchronized

Keep your fork up to date with upstream:
```bash
git fetch upstream
git checkout main
git merge upstream/main
git push origin main
```

## Development Setup

### Install Development Dependencies

**PowerShell:**
```powershell
# Install PSScriptAnalyzer for linting
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser
```

**Shell Scripts:**
```bash
# Install shellcheck (Linux/macOS)
# Ubuntu/Debian:
sudo apt install shellcheck

# macOS:
brew install shellcheck

# Windows (via scoop):
scoop install shellcheck
```

### Validate Your Setup

Run local checks before making changes:
```powershell
# PowerShell validation
pwsh ./tools/lint.ps1 -Mode Analyze

# Docker Compose validation
docker compose -f stacks/desktop/docker-compose.yml config
docker compose -f stacks/laptop/docker-compose.yml config
```

## How to Contribute

### Types of Contributions

We welcome various types of contributions:
- **Bug Fixes** - Fix issues reported in GitHub Issues
- **Features** - Add new MCP servers or deployment capabilities
- **Documentation** - Improve README, guides, or inline documentation
- **Scripts** - Add automation or helper scripts
- **Tests** - Improve test coverage or validation scripts
- **CI/CD** - Enhance GitHub Actions workflows

### Contribution Workflow

1. **Check Existing Issues**: Search [Issues](../../issues) to avoid duplicate work
2. **Open an Issue**: For significant changes, open an issue first to discuss
3. **Create a Branch**: Use descriptive branch names (`feature/add-mcp-server`, `fix/edge-config-bug`)
4. **Make Changes**: Follow coding standards (see below)
5. **Test Locally**: Validate your changes work as expected
6. **Commit**: Write clear commit messages (see [Commit Guidelines](#commit-guidelines))
7. **Push**: Push your branch to your fork
8. **Open PR**: Submit a pull request with detailed description

### What to Work On

- Check [Good First Issue](../../issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label
- Review [Enhancement](../../issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement) requests
- See [ROADMAP.md](docs/ROADMAP.md) for planned features

## Coding Standards

## PowerShell formatting and linting

We run [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) and the PowerShell formatter in CI. To reproduce the checks locally you need PowerShell 7+ (`pwsh`) and the `PSScriptAnalyzer` module.

1. Install the module if necessary:

   ```powershell
   Install-Module -Name PSScriptAnalyzer -Scope CurrentUser
   ```

2. Check formatting (fails if a file would be reformatted):

   ```powershell
   pwsh ./tools/lint.ps1 -Mode FormatCheck
   ```

3. Automatically apply formatting fixes:

   ```powershell
   pwsh ./tools/lint.ps1 -Mode FormatFix
   ```

4. Run the analyzer (prints a formatted table of diagnostics and fails only on errors):

   ```powershell
   pwsh ./tools/lint.ps1 -Mode Analyze
   ```

### Working with the warning baseline (optional)

If you want CI to fail only on new warnings, generate or refresh the baseline file before pushing:

```powershell
pwsh ./tools/lint.ps1 -Mode Analyze -UpdateWarningBaseline
```

This writes `.pssa-warning-baseline.json` in the repository root. When present, CI compares warnings to that file so that only newly introduced warnings cause failures (`./tools/lint.ps1 -Mode Analyze -FailOnNewWarnings`). Remove warnings from the code and re-run the command above to keep the baseline accurate.

## Fixing common analyzer findings

PSScriptAnalyzer enforces a curated set of rules. Some common findings and their fixes include:

- **Avoid `Invoke-Expression`** (`PSAvoidUsingInvokeExpression`): refactor to use splatting or `&` with explicit command arguments.
- **Add `ShouldProcess` support** (`PSUseSupportsShouldProcess`): decorate advanced functions that mutate state with `[CmdletBinding(SupportsShouldProcess)]` and wrap operations inside `if ($PSCmdlet.ShouldProcess(...))`.
- **Avoid empty catch blocks** (`PSAvoidUsingEmptyCatchBlock`): handle the exception explicitly, log, or rethrow via `throw`.
- **Prefer approved verbs and singular nouns** (`PSUseApprovedVerbs`, `PSUseSingularNouns`): adjust function names to use standard PowerShell verb-noun patterns.
- **Declare and use variables deliberately** (`PSUseDeclaredVarsMoreThanAssignments`): remove unused variables or use them meaningfully.
- **Document functions** (`PSProvideCommentHelp`): add comment-based help for public functions and scripts.

Run the analyzer after applying fixes to ensure the issue is resolved.

## Shell Script Standards

### Shellcheck Validation

All shell scripts (`.sh`) must pass shellcheck:
```bash
# Check a single script
shellcheck scripts/install/install-agent.sh

# Check all scripts
find scripts/ -name "*.sh" -exec shellcheck {} +
```

### Shell Script Best Practices

- Use `#!/usr/bin/env bash` shebang for portability
- Enable strict mode: `set -euo pipefail`
- Quote all variables: `"$variable"` not `$variable`
- Use functions for reusable logic
- Add comments for complex operations
- Test on multiple shells if possible (bash, zsh)

## Docker Compose Standards

### Validation

Always validate compose files before committing:
```bash
docker compose -f stacks/desktop/docker-compose.yml config
```

### Best Practices

- **Version Pinning**: Use specific image tags, avoid `latest`
- **Health Checks**: Include health checks for all services
- **Resource Limits**: Define CPU and memory limits
- **Logging**: Configure log rotation (max-size, max-file)
- **Labels**: Add descriptive labels for filtering
- **Restart Policies**: Use `unless-stopped` for production services
- **Secrets**: Never hardcode secrets, use env_file or variables

## Testing

### Local Testing

**Test Compose Syntax:**
```bash
docker compose -f stacks/desktop/docker-compose.yml config
```

**Test Stack Deployment (if you have Portainer):**
```bash
# Deploy locally
docker compose -f stacks/desktop/docker-compose.yml up -d

# Check health
docker ps
docker compose logs

# Cleanup
docker compose -f stacks/desktop/docker-compose.yml down
```

**Test Scripts:**
```powershell
# PowerShell script dry-run
pwsh scripts/install/configure-agent-env.ps1 -WhatIf

# Bash script with verbose output
bash -x scripts/install/install-agent.sh
```

### CI/CD Testing

All pull requests automatically run:
- PowerShell linting (PSScriptAnalyzer)
- Shell script linting (shellcheck)
- Docker Compose validation
- Security scanning (Trivy, Semgrep)
- SBOM generation

Check the Actions tab to see test results.

## Pull Request Process

### Before Submitting

- [ ] Code follows project standards
- [ ] All tests pass locally
- [ ] Documentation is updated (if applicable)
- [ ] Commit messages are clear and descriptive
- [ ] No sensitive data (secrets, IPs, hostnames) committed
- [ ] Compose files validated
- [ ] Scripts linted and tested

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Script improvement
- [ ] CI/CD enhancement

## Testing Done
- Tested on: (OS, Docker version, Portainer version)
- Test commands:
  ```
  # Commands you ran to test
  ```

## Screenshots (if applicable)
Add screenshots for UI changes or deployment results

## Checklist
- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review
- [ ] I have commented complex code
- [ ] I have updated documentation
- [ ] My changes generate no new warnings
- [ ] I have tested locally
```

### Review Process

1. **Automated Checks**: CI/CD runs automatically
2. **Code Review**: Maintainer reviews code quality and functionality
3. **Testing**: Changes may be tested in a staging environment
4. **Feedback**: Address any requested changes
5. **Approval**: Once approved, PR is merged to main
6. **Deployment**: Changes deploy via GitOps

### Merge Strategy

- **Squash and Merge**: Preferred for feature branches
- **Rebase and Merge**: For clean, atomic commits
- **Merge Commit**: For complex, multi-commit features

## Commit Guidelines

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style (formatting, no functional changes)
- `refactor`: Code restructuring without changing behavior
- `test`: Adding or updating tests
- `chore`: Maintenance (dependencies, tooling)
- `ci`: CI/CD changes

**Examples:**
```
feat(stacks): add new mcp-postgres server

Add PostgreSQL MCP server to desktop compose file with:
- Health checks
- Resource limits
- Logging configuration
- Documentation

Closes #123

---

fix(scripts): correct Edge Config path in build script

The Edge Config was using wrong mount path. Updated to
/var/edge/configs/mcp.env per Portainer documentation.

Fixes #456

---

docs(readme): update Tailscale setup instructions

Added Windows-specific steps for Tailscale installation
and updated hostname examples.
```

### Commit Best Practices

- **Atomic Commits**: One logical change per commit
- **Clear Subject**: 50 chars or less, imperative mood
- **Detailed Body**: Explain "what" and "why", not "how"
- **Reference Issues**: Use "Closes #123" or "Fixes #456"
- **Sign Commits**: Use GPG signing for verification (optional)

## Security Considerations

### Never Commit Secrets

- ❌ API keys, tokens, passwords
- ❌ Internal hostnames or IP addresses
- ❌ `.env` files with credentials
- ❌ Portainer API keys

### Run Secret Scanning Locally

```bash
# Install gitleaks
brew install gitleaks  # macOS
# OR
go install github.com/gitleaks/gitleaks/v8@latest

# Scan before committing
gitleaks detect --source . --verbose
```

### Security Checklist

- [ ] No secrets in code
- [ ] No internal network details
- [ ] Sensitive data in .gitignore
- [ ] Security.md reviewed for policy
- [ ] Compose files use env_file for secrets

## Community

### Getting Help

- **GitHub Issues**: Report bugs or request features
- **GitHub Discussions**: Ask questions or share ideas
- **Documentation**: Check [README.md](README.md) and [docs/](docs/)

### Recognition

Contributors who submit quality PRs will be recognized in:
- GitHub contributor graph
- Release notes (for significant contributions)
- README acknowledgments (for major features)

### Communication

- Be patient and respectful
- Assume positive intent
- Provide constructive feedback
- Help others when you can

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to **mcp-stacks**! Your efforts help make GitOps infrastructure more accessible and reliable for everyone.

**Questions?** Open a [GitHub Discussion](../../discussions) or [Issue](../../issues).
