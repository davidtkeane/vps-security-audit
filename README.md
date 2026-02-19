# VPS Security Audit

Comprehensive security audit toolkit for Ubuntu/Debian VPS servers. Built by David Keane (IrishRanger) and Ranger (AIRanger).

## Tools

| Script | Purpose |
|--------|---------|
| `vps_security_audit.sh` | Full VPS security audit (SSH, firewall, ports, users, etc.) |
| `credential_scanner.sh` | Scan source code for hardcoded credentials and secrets |

---

## VPS Security Audit

### Features

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

### Quick Start

```bash
chmod +x vps_security_audit.sh
./vps_security_audit.sh

# Save report to file
./vps_security_audit.sh --report

# Send summary to Telegram
export TELEGRAM_BOT_TOKEN="your-bot-token"
export TELEGRAM_CHAT_ID="your-chat-id"
./vps_security_audit.sh --telegram

# Auto-fix common issues
./vps_security_audit.sh --fix
```

### What It Checks

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

### Auto-Fix Mode

With `--fix`, the script will automatically:
- Install and configure `fail2ban` (SSH brute force protection)
- Install and enable `unattended-upgrades` (automatic security patches)
- Enable UFW firewall with deny-by-default
- Fix file permissions on .env files (chmod 600)
- Apply pending package updates

---

## Credential Scanner

Scans source code, config files, and system files for hardcoded credentials, API keys, tokens, and secrets.

### What It Detects

| Category | Examples |
|----------|---------|
| **Cloud Provider Keys** | AWS Access/Secret keys |
| **API Tokens** | GitHub (ghp_, gho_, ghs_, github_pat_), OpenAI (sk-), Anthropic (sk-ant-), Google (AIza) |
| **Payment Keys** | Stripe (sk_live_, pk_live_), SendGrid, Mailgun |
| **Bot Tokens** | Telegram, Discord, Slack (xoxb/xoxp/xoxo) |
| **Service Credentials** | Twilio, Heroku, Firebase |
| **Passwords** | Hardcoded password/secret assignments in code |
| **Database URLs** | Connection strings with inline credentials (mysql://, postgres://, mongodb://) |
| **Auth Headers** | Bearer tokens, Basic auth, Authorization headers |
| **Private Keys** | RSA, DSA, EC, OpenSSH, PGP private key blocks |
| **File Permissions** | World-readable .env files (chmod 644/755/666/777) |
| **Git History** | .env files committed to git history, missing .gitignore |

### Quick Start

```bash
chmod +x credential_scanner.sh

# Scan a project directory
./credential_scanner.sh ./my-project

# Scan with fix suggestions
./credential_scanner.sh ./my-project --fix

# Scan only git-tracked files
./credential_scanner.sh ./my-project --gitcheck

# Scan common system locations (~/.bashrc, ~/.env, etc.)
./credential_scanner.sh --self-check

# Save report + send to Telegram
./credential_scanner.sh ./my-project --report --telegram

# JSON output
./credential_scanner.sh ./my-project --json
```

### Features

- **30+ credential patterns** with severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- **Smart filtering** — skips binary files, node_modules, .git, build dirs
- **Comment awareness** — skips commented-out code (except actual key patterns)
- **Template detection** — ignores placeholder values (YOUR_, CHANGE_ME, example.com)
- **Secret masking** — shows first 4 and last 2 chars only (e.g., `8439****4s`)
- **Fix suggestions** — `--fix` flag shows remediation for each finding
- **.env permission audit** — flags world-readable .env files, auto-fixes with `--fix`
- **Git history check** — warns if .env was ever committed
- **Self-check mode** — scans system files (~/.bashrc, ~/.aws/credentials, etc.)
- **Telegram alerts** — send scan summary to your Telegram bot
- **Report mode** — save full report to `~/.security-audits/`
- **JSON output** — machine-readable results

### Sample Output

```
╔═══════════════════════════════════════════════╗
║   Credential Scanner v1.0.0                  ║
║   2026-02-19 16:57:13                        ║
║   Scanning: ./my-project                     ║
╚═══════════════════════════════════════════════╝

═══════════════════════════════════════════════
  ENVIRONMENT FILE PERMISSIONS
═══════════════════════════════════════════════
  [CRITICAL] .env file is WORLD READABLE!
             File: ./my-project/.env
             Perms: 644 (owner: ranger)
             Fix: chmod 600 ./my-project/.env

═══════════════════════════════════════════════
  CREDENTIAL SCAN
═══════════════════════════════════════════════
  [HIGH]     Telegram Bot Token
             File: ./src/bot.py:24
             Match: 8439****4s
             Fix: Use TELEGRAM_BOT_TOKEN env var

  [CRITICAL] OpenAI API Key
             File: ./config.py:11
             Match: sk-p****Fj
             Fix: Use OPENAI_API_KEY env var

═══════════════════════════════════════════════
  SCAN SUMMARY
═══════════════════════════════════════════════
  Files scanned:  45
  Total findings: 3

  CRITICAL: 1
  HIGH:     1
  LOW:      1

  ACTION REQUIRED: Critical/High findings need immediate attention!
```

---

## Cron Integration

```bash
# Weekly VPS audit (Monday 6AM UTC)
0 6 * * 1 /path/to/vps_security_audit.sh --report --telegram

# Daily credential scan of your projects
0 7 * * * /path/to/credential_scanner.sh /home/user/projects --report --telegram
```

## Requirements

- **VPS Audit:** Ubuntu 22.04+ or Debian 12+, `sudo` access
- **Credential Scanner:** bash 4+, `grep`, `find`, `file` (works on Linux + macOS)
- Optional: `fail2ban`, `ufw` (installed automatically with `--fix`)

## Related

- [openclaw-tools](https://github.com/davidtkeane/openclaw-tools) — VPS automation scripts (monitoring, management)

## License

MIT License - David Keane (davidtkeane)
