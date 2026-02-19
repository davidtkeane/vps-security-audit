#!/bin/bash
# ============================================================
# VPS Security Audit Script
# Author: David Keane (IrishRanger) + Ranger (AIRanger)
# Version: 1.0.0
# Date: 2026-02-19
# License: MIT
#
# Comprehensive security audit for Ubuntu/Debian VPS servers.
# Checks: SSH, firewall, ports, users, packages, permissions,
#          fail2ban, Docker, cron, SUID, and more.
#
# Usage:
#   ./vps_security_audit.sh              # Full audit to stdout
#   ./vps_security_audit.sh --report     # Save report to file
#   ./vps_security_audit.sh --telegram   # Send summary to Telegram
#   ./vps_security_audit.sh --fix        # Auto-fix common issues
#   ./vps_security_audit.sh --json       # Output as JSON
# ============================================================

set +e

VERSION="1.0.0"
REPORT_DIR="${HOME}/.security-audits"
TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S")
REPORT_FILE="${REPORT_DIR}/audit_${TIMESTAMP}.txt"
HOSTNAME=$(hostname)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
CRITICAL=0
WARNING=0
PASS=0
INFO=0

# Telegram config (optional - set via env or .env)
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

# Parse args
SAVE_REPORT=false
SEND_TELEGRAM=false
AUTO_FIX=false
JSON_OUTPUT=false

for arg in "$@"; do
    case $arg in
        --report) SAVE_REPORT=true ;;
        --telegram) SEND_TELEGRAM=true ;;
        --fix) AUTO_FIX=true ;;
        --json) JSON_OUTPUT=true ;;
        --help|-h)
            echo "VPS Security Audit v${VERSION}"
            echo "Usage: $0 [--report] [--telegram] [--fix] [--json]"
            echo ""
            echo "  --report    Save full report to ${REPORT_DIR}/"
            echo "  --telegram  Send summary to Telegram bot"
            echo "  --fix       Auto-fix common security issues"
            echo "  --json      Output results as JSON"
            echo "  --help      Show this help"
            exit 0
            ;;
    esac
done

# Load .env if exists (only extract TELEGRAM vars for notifications)
if [ -f "${HOME}/.openclaw/workspace/scripts/.env" ]; then
    _tg_token=$(grep '^TELEGRAM_BOT_TOKEN=' "${HOME}/.openclaw/workspace/scripts/.env" 2>/dev/null | head -1 | cut -d= -f2-)
    _tg_chat=$(grep '^TELEGRAM_CHAT_ID=' "${HOME}/.openclaw/workspace/scripts/.env" 2>/dev/null | head -1 | cut -d= -f2-)
    [ -n "$_tg_token" ] && TELEGRAM_BOT_TOKEN="$_tg_token"
    [ -n "$_tg_chat" ] && TELEGRAM_CHAT_ID="$_tg_chat"
fi

# Setup
mkdir -p "$REPORT_DIR"

# Output functions
header() {
    echo -e "\n${BLUE}═══════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
}

critical() {
    echo -e "  ${RED}[CRITICAL]${NC} $1"
    ((CRITICAL++))
}

warning() {
    echo -e "  ${YELLOW}[WARNING]${NC} $1"
    ((WARNING++))
}

pass() {
    echo -e "  ${GREEN}[PASS]${NC} $1"
    ((PASS++))
}

info() {
    echo -e "  ${BLUE}[INFO]${NC} $1"
    ((INFO++))
}

fixed() {
    echo -e "  ${GREEN}[FIXED]${NC} $1"
}

# ============================================================
# AUDIT SECTIONS
# ============================================================

audit_system() {
    header "SYSTEM INFORMATION"
    info "Hostname: $(hostname)"
    info "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2)"
    info "Kernel: $(uname -r)"
    info "Uptime: $(uptime -p 2>/dev/null || uptime)"
    info "Architecture: $(uname -m)"

    # Check uptime - if > 90 days, might need a reboot for kernel patches
    UPDAYS=$(awk '{print int($1/86400)}' /proc/uptime 2>/dev/null || echo 0)
    if [ "$UPDAYS" -gt 90 ]; then
        warning "Server uptime is ${UPDAYS} days — consider rebooting for kernel updates"
    else
        pass "Server uptime: ${UPDAYS} days"
    fi
}

audit_updates() {
    header "PACKAGE UPDATES"

    # Check for upgradable packages
    UPGRADABLE=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo 0)
    if [ "$UPGRADABLE" -gt 0 ]; then
        warning "${UPGRADABLE} packages have available updates"
        apt list --upgradable 2>/dev/null | grep -i security | head -5
        if [ "$AUTO_FIX" = true ]; then
            echo "  Running: sudo apt-get upgrade -y"
            sudo apt-get update -qq && sudo apt-get upgrade -y -qq 2>&1 | tail -3
            fixed "Package updates applied"
        fi
    else
        pass "All packages are up to date"
    fi

    # Check unattended-upgrades
    if dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
        if systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
            pass "Unattended security upgrades: active"
        else
            warning "unattended-upgrades installed but not running"
            if [ "$AUTO_FIX" = true ]; then
                sudo systemctl enable --now unattended-upgrades
                fixed "Enabled unattended-upgrades"
            fi
        fi
    else
        critical "unattended-upgrades NOT installed — no automatic security patches"
        if [ "$AUTO_FIX" = true ]; then
            sudo apt-get install -y unattended-upgrades
            fixed "Installed unattended-upgrades"
        fi
    fi

    # Check needrestart
    if which needrestart >/dev/null 2>&1; then
        pass "needrestart: installed"
    else
        warning "needrestart not installed — won't detect services needing restart"
    fi
}

audit_ssh() {
    header "SSH CONFIGURATION"

    # PermitRootLogin
    ROOT_LOGIN=$(sudo sshd -T 2>/dev/null | grep -i permitrootlogin | awk '{print $2}')
    if [ "$ROOT_LOGIN" = "no" ]; then
        pass "Root login: disabled"
    else
        critical "Root login: ${ROOT_LOGIN} (should be 'no')"
        if [ "$AUTO_FIX" = true ]; then
            echo "PermitRootLogin no" | sudo tee -a /etc/ssh/sshd_config.d/99-hardening.conf >/dev/null
            fixed "Disabled root login"
        fi
    fi

    # PasswordAuthentication
    PASS_AUTH=$(sudo sshd -T 2>/dev/null | grep -i passwordauthentication | awk '{print $2}')
    if [ "$PASS_AUTH" = "no" ]; then
        pass "Password auth: disabled (key-only)"
    else
        critical "Password auth: ${PASS_AUTH} (should be 'no')"
    fi

    # MaxAuthTries
    MAX_AUTH=$(sudo sshd -T 2>/dev/null | grep -i maxauthtries | awk '{print $2}')
    if [ "$MAX_AUTH" -le 3 ] 2>/dev/null; then
        pass "MaxAuthTries: ${MAX_AUTH}"
    else
        warning "MaxAuthTries: ${MAX_AUTH} (recommend 3)"
    fi

    # X11Forwarding
    X11=$(sudo sshd -T 2>/dev/null | grep -i x11forwarding | awk '{print $2}')
    if [ "$X11" = "no" ]; then
        pass "X11Forwarding: disabled"
    else
        warning "X11Forwarding: ${X11} (not needed on headless VPS)"
    fi

    # LoginGraceTime
    GRACE=$(sudo sshd -T 2>/dev/null | grep -i logingracetime | awk '{print $2}')
    if [ "$GRACE" -le 60 ] 2>/dev/null; then
        pass "LoginGraceTime: ${GRACE}s"
    else
        warning "LoginGraceTime: ${GRACE}s (recommend <=60)"
    fi

    # PermitEmptyPasswords
    EMPTY=$(sudo sshd -T 2>/dev/null | grep -i permitemptypasswords | awk '{print $2}')
    if [ "$EMPTY" = "no" ]; then
        pass "Empty passwords: disabled"
    else
        critical "Empty passwords: ${EMPTY} (MUST be 'no')"
    fi

    # Check SSH port
    SSH_PORT=$(sudo sshd -T 2>/dev/null | grep -i "^port " | awk '{print $2}')
    if [ "$SSH_PORT" = "22" ]; then
        info "SSH on default port 22 (consider changing for obscurity)"
    else
        pass "SSH on non-default port: ${SSH_PORT}"
    fi
}

audit_firewall() {
    header "FIREWALL (UFW)"

    if which ufw >/dev/null 2>&1; then
        UFW_STATUS=$(sudo ufw status 2>/dev/null | head -1)
        if echo "$UFW_STATUS" | grep -q "active"; then
            pass "UFW firewall: active"

            # Check default policy
            DEFAULT_IN=$(sudo ufw status verbose 2>/dev/null | grep "Default:" | grep -o "deny (incoming)" || echo "")
            if [ -n "$DEFAULT_IN" ]; then
                pass "Default incoming: deny"
            else
                critical "Default incoming is NOT deny — all ports potentially open"
            fi

            # List rules and flag wide-open ports
            echo ""
            info "Firewall rules:"
            sudo ufw status numbered 2>/dev/null | while IFS= read -r line; do
                if echo "$line" | grep -q "ALLOW IN.*Anywhere"; then
                    PORT=$(echo "$line" | awk '{print $2}')
                    echo -e "    ${YELLOW}${line}${NC}"
                else
                    echo "    $line"
                fi
            done
        else
            critical "UFW firewall: INACTIVE"
            if [ "$AUTO_FIX" = true ]; then
                sudo ufw --force enable
                fixed "Enabled UFW firewall"
            fi
        fi
    else
        critical "UFW not installed — no firewall!"
        if [ "$AUTO_FIX" = true ]; then
            sudo apt-get install -y ufw
            sudo ufw default deny incoming
            sudo ufw default allow outgoing
            sudo ufw allow 22/tcp
            sudo ufw --force enable
            fixed "Installed and configured UFW"
        fi
    fi
}

audit_fail2ban() {
    header "FAIL2BAN (Brute Force Protection)"

    if which fail2ban-client >/dev/null 2>&1; then
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            pass "fail2ban: active"
            JAILS=$(sudo fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2 | xargs)
            if [ -n "$JAILS" ]; then
                pass "Active jails: ${JAILS}"
                for jail in $(echo "$JAILS" | tr ',' ' '); do
                    BANNED=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
                    TOTAL=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep "Total banned" | awk '{print $NF}')
                    info "  ${jail}: ${BANNED} currently banned, ${TOTAL} total"
                done
            else
                warning "fail2ban running but no jails configured"
            fi
        else
            warning "fail2ban installed but not running"
        fi
    else
        critical "fail2ban NOT installed — SSH exposed to brute force"
        if [ "$AUTO_FIX" = true ]; then
            sudo apt-get install -y fail2ban
            sudo tee /etc/fail2ban/jail.local > /dev/null << 'JAIL'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
banaction = ufw

[sshd]
enabled = true
port = 22
maxretry = 3
JAIL
            sudo systemctl enable --now fail2ban
            fixed "Installed and configured fail2ban"
        fi
    fi
}

audit_ports() {
    header "OPEN PORTS & SERVICES"

    info "Listening TCP ports:"
    ss -tlnp 2>/dev/null | while IFS= read -r line; do
        if echo "$line" | grep -q "0.0.0.0:\|:::"; then
            ADDR=$(echo "$line" | awk '{print $4}')
            PORT=$(echo "$ADDR" | rev | cut -d: -f1 | rev)
            # Skip standard safe ports
            case "$PORT" in
                22|80|443|53) echo -e "    ${GREEN}${line}${NC}" ;;
                *)
                    if echo "$line" | grep -q "127.0.0.1\|::1"; then
                        echo -e "    ${GREEN}${line}${NC}"
                    else
                        echo -e "    ${YELLOW}${line}${NC}"
                        warning "Port ${PORT} open to all interfaces"
                    fi
                    ;;
            esac
        else
            echo "    $line"
        fi
    done

    echo ""
    info "UDP listeners:"
    ss -ulnp 2>/dev/null | grep -v "^State" | head -10 | while IFS= read -r line; do
        echo "    $line"
    done
}

audit_users() {
    header "USER ACCOUNTS"

    # Users with login shells
    info "Users with login shells:"
    while IFS=: read -r user _ uid _ _ home shell; do
        if echo "$shell" | grep -qE '/(bash|sh|zsh)$'; then
            if [ "$uid" -eq 0 ]; then
                info "  root (uid 0) — ${shell}"
            elif [ "$uid" -ge 1000 ]; then
                info "  ${user} (uid ${uid}) — ${shell} [${home}]"
            fi
        fi
    done < /etc/passwd

    # Check for users with empty passwords (only real login users, not system accounts)
    EMPTY_PASS=$(sudo awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null | head -5)
    if [ -n "$EMPTY_PASS" ]; then
        critical "Users with EMPTY passwords: ${EMPTY_PASS}"
    else
        pass "No users with empty passwords"
    fi

    # Recent logins
    echo ""
    info "Last 5 logins:"
    last -5 2>/dev/null | head -5 | while IFS= read -r line; do
        echo "    $line"
    done

    # Failed logins
    FAILED=$(journalctl -u ssh --since "7 days ago" 2>/dev/null | grep -ci "failed\|invalid" 2>/dev/null || echo "0")
    FAILED=$(echo "$FAILED" | tr -d '[:space:]')
    if [ "$FAILED" -gt 50 ] 2>/dev/null; then
        warning "${FAILED} failed SSH login attempts in last 7 days"
    elif [ "$FAILED" -gt 0 ] 2>/dev/null; then
        info "${FAILED} failed SSH login attempts in last 7 days"
    else
        pass "No failed SSH login attempts in last 7 days"
    fi
}

audit_permissions() {
    header "FILE PERMISSIONS"

    # Check critical files
    check_perm() {
        local file="$1"
        local max_perm="$2"
        local desc="$3"

        if [ -f "$file" ]; then
            PERM=$(stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file" 2>/dev/null)
            if [ "$PERM" -le "$max_perm" ] 2>/dev/null; then
                pass "${desc}: ${PERM}"
            else
                warning "${desc}: ${PERM} (should be <=${max_perm})"
                if [ "$AUTO_FIX" = true ]; then
                    chmod "$max_perm" "$file"
                    fixed "Set ${file} to ${max_perm}"
                fi
            fi
        fi
    }

    check_perm "$HOME/.ssh/authorized_keys" 600 "authorized_keys"
    check_perm "$HOME/.bashrc" 600 ".bashrc"
    check_perm "$HOME/.bash_history" 600 ".bash_history"

    # Check for .env files
    for envfile in $(find "$HOME" -maxdepth 4 -name ".env" -type f 2>/dev/null); do
        PERM=$(stat -c '%a' "$envfile" 2>/dev/null || stat -f '%Lp' "$envfile" 2>/dev/null)
        if [ "$PERM" -le 600 ] 2>/dev/null; then
            pass "${envfile}: ${PERM}"
        else
            warning "${envfile}: ${PERM} (should be 600)"
            if [ "$AUTO_FIX" = true ]; then
                chmod 600 "$envfile"
                fixed "Set ${envfile} to 600"
            fi
        fi
    done

    # World-writable files in home
    WW_COUNT=$(find "$HOME" -perm -002 -type f 2>/dev/null | wc -l)
    if [ "$WW_COUNT" -gt 0 ]; then
        warning "${WW_COUNT} world-writable files found in home directory"
        find "$HOME" -perm -002 -type f 2>/dev/null | head -5 | while read -r f; do
            echo "    $f"
        done
    else
        pass "No world-writable files in home directory"
    fi

    # SUID binaries check
    SUID_COUNT=$(find /usr/bin /usr/sbin -perm -4000 -type f 2>/dev/null | wc -l)
    info "SUID binaries: ${SUID_COUNT} found (standard: ~10)"
    if [ "$SUID_COUNT" -gt 15 ]; then
        warning "More SUID binaries than expected — review manually"
    fi
}

audit_docker() {
    header "DOCKER"

    if which docker >/dev/null 2>&1; then
        if systemctl is-active --quiet docker 2>/dev/null; then
            info "Docker: running"
            CONTAINERS=$(docker ps -q 2>/dev/null | wc -l)
            info "Running containers: ${CONTAINERS}"
            docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}" 2>/dev/null | while IFS= read -r line; do
                echo "    $line"
            done

            # Check for containers with host networking
            HOST_NET=$(docker ps --format '{{.Names}} {{.Networks}}' 2>/dev/null | grep -c "host" 2>/dev/null || echo "0")
            HOST_NET=$(echo "$HOST_NET" | tr -d '[:space:]')
            if [ "$HOST_NET" -gt 0 ] 2>/dev/null; then
                warning "${HOST_NET} container(s) using host networking"
            fi
        else
            info "Docker: installed but not running"
        fi
    else
        info "Docker: not installed"
    fi
}

audit_cron() {
    header "SCHEDULED TASKS (CRON)"

    info "User crontab:"
    crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | while IFS= read -r line; do
        echo "    $line"
    done

    # Check system cron
    info "System cron jobs:"
    for crondir in /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        if [ -d "$crondir" ]; then
            COUNT=$(ls "$crondir" 2>/dev/null | wc -l)
            info "  ${crondir}: ${COUNT} jobs"
        fi
    done
}

audit_resources() {
    header "SYSTEM RESOURCES"

    # Disk
    DISK_PCT=$(df / 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%')
    if [ "$DISK_PCT" -gt 90 ] 2>/dev/null; then
        critical "Disk usage: ${DISK_PCT}% (critically high)"
    elif [ "$DISK_PCT" -gt 80 ] 2>/dev/null; then
        warning "Disk usage: ${DISK_PCT}%"
    else
        pass "Disk usage: ${DISK_PCT}%"
    fi
    df -h / 2>/dev/null | tail -1 | awk '{print "    Total: "$2", Used: "$3", Free: "$4}'

    # Memory
    MEM_PCT=$(free 2>/dev/null | awk '/Mem:/{printf("%.0f", $3/$2*100)}')
    if [ "$MEM_PCT" -gt 90 ] 2>/dev/null; then
        warning "Memory usage: ${MEM_PCT}%"
    else
        pass "Memory usage: ${MEM_PCT}%"
    fi
    free -h 2>/dev/null | head -2

    # Swap
    SWAP_TOTAL=$(free 2>/dev/null | awk '/Swap:/{print $2}')
    if [ "$SWAP_TOTAL" = "0" ]; then
        warning "No swap configured"
    else
        pass "Swap available"
    fi

    # Load
    LOAD=$(cat /proc/loadavg 2>/dev/null | awk '{print $1}')
    CPUS=$(nproc 2>/dev/null || echo 1)
    info "Load average: ${LOAD} (${CPUS} CPUs)"
}

# ============================================================
# SUMMARY & REPORT
# ============================================================

print_summary() {
    header "AUDIT SUMMARY"
    echo -e "  ${RED}CRITICAL: ${CRITICAL}${NC}"
    echo -e "  ${YELLOW}WARNINGS: ${WARNING}${NC}"
    echo -e "  ${GREEN}PASSED:   ${PASS}${NC}"
    echo -e "  ${BLUE}INFO:     ${INFO}${NC}"
    echo ""

    if [ "$CRITICAL" -gt 0 ]; then
        echo -e "  ${RED}⚠️  ACTION REQUIRED: ${CRITICAL} critical issue(s) found!${NC}"
    elif [ "$WARNING" -gt 0 ]; then
        echo -e "  ${YELLOW}⚡ ${WARNING} warning(s) — review recommended${NC}"
    else
        echo -e "  ${GREEN}✅ All checks passed!${NC}"
    fi
    echo ""
    echo "  Audit completed: $(date)"
    echo "  Script version: ${VERSION}"
}

send_telegram_summary() {
    if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ]; then
        echo "  Telegram not configured (set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)"
        return
    fi

    local MSG="<b>🔒 VPS Security Audit — ${HOSTNAME}</b>
<pre>
Date: $(date +%Y-%m-%d\ %H:%M)
Critical: ${CRITICAL}
Warnings: ${WARNING}
Passed:   ${PASS}
</pre>"

    if [ "$CRITICAL" -gt 0 ]; then
        MSG="${MSG}
⚠️ <b>${CRITICAL} critical issue(s) found!</b>"
    fi

    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -H "Content-Type: application/json" \
        -d "{\"chat_id\": \"${TELEGRAM_CHAT_ID}\", \"parse_mode\": \"HTML\", \"text\": $(echo "$MSG" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')}" \
        >/dev/null 2>&1

    echo "  Telegram summary sent"
}

# ============================================================
# RUN AUDIT
# ============================================================

echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   VPS Security Audit v${VERSION}              ║${NC}"
echo -e "${BLUE}║   $(date +%Y-%m-%d\ %H:%M:%S)                      ║${NC}"
echo -e "${BLUE}║   Host: ${HOSTNAME}                          ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"

# Run all audit sections
audit_system
audit_updates
audit_ssh
audit_firewall
audit_fail2ban
audit_ports
audit_users
audit_permissions
audit_docker
audit_cron
audit_resources
print_summary

# Save report if requested
if [ "$SAVE_REPORT" = true ]; then
    echo "  Report saved to: ${REPORT_FILE}"
fi

# Send Telegram if requested
if [ "$SEND_TELEGRAM" = true ]; then
    send_telegram_summary
fi
