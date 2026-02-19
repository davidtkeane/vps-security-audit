# VPS Security Audit

Comprehensive security audit toolkit for Ubuntu/Debian VPS servers. Built by David Keane (IrishRanger) and Ranger (AIRanger).

## Features

- **SSH hardening check** — root login, password auth, key-only, max retries
- **Firewall audit** — UFW status, default policy, open port analysis
- **Brute force protection** — fail2ban status, banned IPs, jail config
- **Port scanning** — all listening TCP/UDP ports with process identification
- **User audit** — login shells, empty passwords, failed login attempts
- **File permissions** — .env files, SSH keys, world-writable files, SUID binaries
- **Package updates** — pending security patches, unattended-upgrades status
- **Docker containers** — running containers, host networking, port exposure
- **Resource monitoring** — disk, memory, swap, CPU load
- **Cron job review** — user and system scheduled tasks
- **Telegram alerts** — send audit summary to Telegram bot
- **Auto-fix mode** — automatically fix common security issues

## Quick Start

```bash
# Download and run
chmod +x vps_security_audit.sh
./vps_security_audit.sh

# Save report to file
./vps_security_audit.sh --report

# Send summary to Telegram
export TELEGRAM_BOT_TOKEN="your-bot-token"
export TELEGRAM_CHAT_ID="your-chat-id"
./vps_security_audit.sh --telegram

# Auto-fix common issues (installs fail2ban, enables firewall, etc.)
./vps_security_audit.sh --fix
```

## What It Checks

| Category | Checks |
|----------|--------|
| **SSH** | Root login, password auth, max retries, X11, login grace time, empty passwords, port |
| **Firewall** | UFW active, default deny, open ports to internet |
| **Fail2ban** | Installed, running, active jails, banned IPs |
| **Ports** | All TCP/UDP listeners, processes, internet-exposed services |
| **Users** | Login shells, empty passwords, recent logins, failed attempts |
| **Permissions** | .env files, SSH keys, .bashrc, world-writable files, SUID binaries |
| **Updates** | Pending packages, unattended-upgrades, needrestart |
| **Docker** | Running containers, host networking |
| **Resources** | Disk usage, memory, swap, load average |
| **Cron** | User and system cron jobs |

## Auto-Fix Mode

With `--fix`, the script will automatically:
- Install and configure `fail2ban` (SSH brute force protection)
- Install and enable `unattended-upgrades` (automatic security patches)
- Enable UFW firewall with deny-by-default
- Fix file permissions on .env files (chmod 600)
- Apply pending package updates

## Output

```
╔═══════════════════════════════════════════╗
║   VPS Security Audit v1.0.0              ║
║   2026-02-19 13:50:00                    ║
║   Host: red-team                         ║
╚═══════════════════════════════════════════╝

═══════════════════════════════════════════
  SSH CONFIGURATION
═══════════════════════════════════════════
  [PASS] Root login: disabled
  [PASS] Password auth: disabled (key-only)
  [PASS] MaxAuthTries: 3
  ...

═══════════════════════════════════════════
  AUDIT SUMMARY
═══════════════════════════════════════════
  CRITICAL: 0
  WARNINGS: 2
  PASSED:   15
  INFO:     8

  ✅ All checks passed!
```

## Requirements

- Ubuntu 22.04+ or Debian 12+
- `sudo` access for full audit
- Optional: `fail2ban`, `ufw` (installed automatically with `--fix`)

## Cron Integration

Run weekly audit with Telegram alerts:

```bash
# Add to crontab
0 6 * * 1 /path/to/vps_security_audit.sh --report --telegram
```

## License

MIT License - David Keane (davidtkeane)
