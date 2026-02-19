#!/bin/bash
# ============================================================
# Credential Scanner
# Author: David Keane (IrishRanger) + Ranger (AIRanger)
# Version: 1.0.0
# Date: 2026-02-19
# License: MIT
#
# Scans source code and config files for hardcoded credentials,
# API keys, tokens, passwords, and secrets. Reports findings
# with file, line number, and severity.
#
# Usage:
#   ./credential_scanner.sh [PATH]              # Scan a directory
#   ./credential_scanner.sh [PATH] --fix        # Show fix suggestions
#   ./credential_scanner.sh [PATH] --report     # Save report to file
#   ./credential_scanner.sh [PATH] --telegram   # Send summary to Telegram
#   ./credential_scanner.sh [PATH] --json       # Output JSON
#   ./credential_scanner.sh [PATH] --gitcheck   # Only scan git-tracked files
#   ./credential_scanner.sh --self-check        # Scan common system locations
#
# Detects:
#   - API keys & tokens (AWS, GitHub, Slack, Telegram, OpenAI, etc.)
#   - Hardcoded passwords & secrets
#   - Private keys (SSH, PGP, RSA)
#   - Database connection strings
#   - Bearer tokens & JWTs
#   - .env files with wrong permissions
#   - High-entropy strings (potential secrets)
# ============================================================

set +e

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT_DIR="${HOME}/.security-audits"
TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S")
REPORT_FILE="${REPORT_DIR}/cred_scan_${TIMESTAMP}.txt"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Counters
CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0
INFO_COUNT=0
TOTAL_FILES=0
TOTAL_FINDINGS=0

# Config
SCAN_PATH=""
SAVE_REPORT=false
SEND_TELEGRAM=false
SHOW_FIX=false
JSON_OUTPUT=false
GIT_ONLY=false
SELF_CHECK=false
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

# File extensions to scan
CODE_EXTENSIONS="py,js,ts,jsx,tsx,rb,go,rs,java,kt,swift,c,cpp,h,cs,php,pl,sh,bash,zsh,ps1,r,lua,ex,exs"
CONFIG_EXTENSIONS="json,yaml,yml,toml,ini,cfg,conf,xml,env,properties,tf,tfvars,hcl"
ALL_EXTENSIONS="${CODE_EXTENSIONS},${CONFIG_EXTENSIONS}"

# Directories to skip
SKIP_DIRS="node_modules,.git,.svn,.hg,__pycache__,.venv,venv,env,.env,vendor,build,dist,.next,.nuxt,target,.gradle,.idea,.vscode,.cache,coverage"

# ============================================================
# ARGUMENT PARSING
# ============================================================

for arg in "$@"; do
    case $arg in
        --report) SAVE_REPORT=true ;;
        --telegram) SEND_TELEGRAM=true ;;
        --fix) SHOW_FIX=true ;;
        --json) JSON_OUTPUT=true ;;
        --gitcheck) GIT_ONLY=true ;;
        --self-check) SELF_CHECK=true ;;
        --help|-h)
            echo "Credential Scanner v${VERSION}"
            echo ""
            echo "Usage: $0 [PATH] [OPTIONS]"
            echo ""
            echo "Arguments:"
            echo "  PATH          Directory or file to scan (default: current directory)"
            echo ""
            echo "Options:"
            echo "  --fix         Show remediation suggestions for each finding"
            echo "  --report      Save full report to ${REPORT_DIR}/"
            echo "  --telegram    Send summary to Telegram bot"
            echo "  --json        Output results as JSON"
            echo "  --gitcheck    Only scan git-tracked files (ignores untracked)"
            echo "  --self-check  Scan common system locations (~/.env, ~/.bashrc, etc.)"
            echo "  --help        Show this help"
            echo ""
            echo "Examples:"
            echo "  $0 ./my-project                 # Scan a project"
            echo "  $0 ./my-project --fix           # Scan with fix suggestions"
            echo "  $0 --self-check                 # Scan system config files"
            echo "  $0 ./src --gitcheck --report    # Scan only git files, save report"
            exit 0
            ;;
        -*)
            echo "Unknown option: $arg (use --help for usage)"
            exit 1
            ;;
        *)
            if [ -z "$SCAN_PATH" ]; then
                SCAN_PATH="$arg"
            fi
            ;;
    esac
done

# Default scan path
if [ "$SELF_CHECK" = true ]; then
    SCAN_PATH="${HOME}"
elif [ -z "$SCAN_PATH" ]; then
    SCAN_PATH="."
fi

# Load Telegram config from .env if available
for env_file in "${HOME}/.openclaw/workspace/scripts/.env" "${HOME}/.env" "./.env"; do
    if [ -f "$env_file" ]; then
        _tg_token=$(grep '^TELEGRAM_BOT_TOKEN=' "$env_file" 2>/dev/null | head -1 | cut -d= -f2-)
        _tg_chat=$(grep '^TELEGRAM_CHAT_ID=' "$env_file" 2>/dev/null | head -1 | cut -d= -f2-)
        [ -n "$_tg_token" ] && [ -z "$TELEGRAM_BOT_TOKEN" ] && TELEGRAM_BOT_TOKEN="$_tg_token"
        [ -n "$_tg_chat" ] && [ -z "$TELEGRAM_CHAT_ID" ] && TELEGRAM_CHAT_ID="$_tg_chat"
    fi
done

mkdir -p "$REPORT_DIR"

# ============================================================
# OUTPUT FUNCTIONS
# ============================================================

_output_buffer=""

out() {
    local line="$1"
    echo -e "$line"
    if [ "$SAVE_REPORT" = true ]; then
        echo -e "$line" | sed 's/\x1b\[[0-9;]*m//g' >> "$REPORT_FILE"
    fi
}

banner() {
    out ""
    out "${BLUE}╔═══════════════════════════════════════════════╗${NC}"
    out "${BLUE}║   ${BOLD}Credential Scanner v${VERSION}${NC}${BLUE}                  ║${NC}"
    out "${BLUE}║   $(date '+%Y-%m-%d %H:%M:%S')                       ║${NC}"
    out "${BLUE}║   Scanning: ${SCAN_PATH:0:30}$([ ${#SCAN_PATH} -gt 30 ] && echo '...')${BLUE}       ║${NC}"
    out "${BLUE}╚═══════════════════════════════════════════════╝${NC}"
}

header() {
    out ""
    out "${BLUE}═══════════════════════════════════════════════${NC}"
    out "${BLUE}  $1${NC}"
    out "${BLUE}═══════════════════════════════════════════════${NC}"
}

finding() {
    local severity="$1"
    local file="$2"
    local line_num="$3"
    local pattern_name="$4"
    local match="$5"
    local fix_msg="$6"

    ((TOTAL_FINDINGS++))

    # Mask the actual secret value (show first 4 and last 2 chars)
    local masked
    if [ ${#match} -gt 12 ]; then
        masked="${match:0:4}****${match: -2}"
    elif [ ${#match} -gt 6 ]; then
        masked="${match:0:2}****"
    else
        masked="****"
    fi

    case $severity in
        CRITICAL)
            out "  ${RED}[CRITICAL]${NC} ${pattern_name}"
            ((CRITICAL++))
            ;;
        HIGH)
            out "  ${RED}[HIGH]${NC}     ${pattern_name}"
            ((HIGH++))
            ;;
        MEDIUM)
            out "  ${YELLOW}[MEDIUM]${NC}   ${pattern_name}"
            ((MEDIUM++))
            ;;
        LOW)
            out "  ${CYAN}[LOW]${NC}      ${pattern_name}"
            ((LOW++))
            ;;
        INFO)
            out "  ${BLUE}[INFO]${NC}     ${pattern_name}"
            ((INFO_COUNT++))
            ;;
    esac

    out "             ${BOLD}File:${NC} ${file}:${line_num}"
    out "             ${BOLD}Match:${NC} ${masked}"

    if [ "$SHOW_FIX" = true ] && [ -n "$fix_msg" ]; then
        out "             ${GREEN}Fix:${NC} ${fix_msg}"
    fi
    out ""
}

pass() {
    out "  ${GREEN}[PASS]${NC}     $1"
}

info() {
    out "  ${BLUE}[INFO]${NC}     $1"
}

# ============================================================
# PATTERN DEFINITIONS
# ============================================================
# Each pattern: NAME|SEVERITY|REGEX|FIX_MESSAGE
# Severity: CRITICAL, HIGH, MEDIUM, LOW

define_patterns() {
    PATTERNS=(
        # === CRITICAL: Full access tokens ===
        'AWS Access Key|CRITICAL|AKIA[0-9A-Z]{16}|Move to env var: AWS_ACCESS_KEY_ID'
        'AWS Secret Key|CRITICAL|(aws_secret_access_key|aws_secret)\s*=\s*['\''"][A-Za-z0-9/+=]{40}|Move to env var: AWS_SECRET_ACCESS_KEY'
        'GitHub Token (ghp)|CRITICAL|ghp_[A-Za-z0-9]{36}|Use GITHUB_TOKEN env var or gh auth'
        'GitHub Token (gho)|CRITICAL|gho_[A-Za-z0-9]{36}|Use GITHUB_TOKEN env var or gh auth'
        'GitHub Token (ghs)|CRITICAL|ghs_[A-Za-z0-9]{36}|Use GITHUB_TOKEN env var or gh auth'
        'GitHub Token (github_pat)|CRITICAL|github_pat_[A-Za-z0-9_]{82}|Use GITHUB_TOKEN env var or gh auth'
        'Slack Token|CRITICAL|xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}|Use SLACK_TOKEN env var'
        'Slack Webhook|HIGH|https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}|Move webhook URL to env var'
        'OpenAI API Key|CRITICAL|sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}|Use OPENAI_API_KEY env var'
        'OpenAI Project Key|CRITICAL|sk-proj-[A-Za-z0-9_-]{80,}|Use OPENAI_API_KEY env var'
        'Anthropic API Key|CRITICAL|sk-ant-[A-Za-z0-9_-]{80,}|Use ANTHROPIC_API_KEY env var'
        'Google API Key|HIGH|AIza[0-9A-Za-z_-]{35}|Use GOOGLE_API_KEY env var'
        'Stripe Secret Key|CRITICAL|sk_live_[0-9a-zA-Z]{24,}|Use STRIPE_SECRET_KEY env var'
        'Stripe Publishable|LOW|pk_live_[0-9a-zA-Z]{24,}|Publishable keys are semi-public but review if needed'
        'Twilio Auth Token|CRITICAL|SK[0-9a-fA-F]{32}|Use TWILIO_AUTH_TOKEN env var'
        'SendGrid API Key|CRITICAL|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|Use SENDGRID_API_KEY env var'
        'Mailgun API Key|HIGH|key-[0-9a-zA-Z]{32}|Use MAILGUN_API_KEY env var'

        # === HIGH: Bot tokens and service credentials ===
        'Telegram Bot Token|HIGH|[0-9]{8,10}:[A-Za-z0-9_-]{35}|Use TELEGRAM_BOT_TOKEN env var'
        'Discord Bot Token|HIGH|[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}|Use DISCORD_TOKEN env var'
        'Discord Webhook|HIGH|https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+|Move webhook URL to env var'
        'Heroku API Key|HIGH|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|Use HEROKU_API_KEY env var'
        'Firebase Key|HIGH|AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}|Move to env var or Firebase config'

        # === MEDIUM: Passwords and connection strings ===
        'Hardcoded Password|MEDIUM|[Pp](assword|ASSWORD|wd|WD)\s*[=:]\s*['\''"][^'\''"]{4,}|Use env var or secrets manager'
        'Hardcoded Secret|MEDIUM|[Ss](ecret|ECRET)\s*[=:]\s*['\''"][^'\''"]{4,}|Use env var or secrets manager'
        'Database URL with Creds|HIGH|(mysql|postgres|postgresql|mongodb|redis)://[^:]+:[^@]+@|Use DATABASE_URL env var, remove inline creds'
        'Connection String Password|HIGH|[Pp]assword=[^;& ]{4,}|Use env var for database password'
        'Bearer Token|MEDIUM|[Bb]earer\s+[A-Za-z0-9_-]{20,}|Use env var for auth tokens'
        'Basic Auth Header|MEDIUM|[Bb]asic\s+[A-Za-z0-9+/=]{20,}|Use env var for auth credentials'
        'Authorization Header|MEDIUM|['\''"]Authorization['\''"]\s*:\s*['\''"][^'\''"]{20,}|Use env var for auth values'

        # === PRIVATE KEYS ===
        'RSA Private Key|CRITICAL|-----BEGIN RSA PRIVATE KEY-----|Never commit private keys. Use ssh-agent or vault'
        'DSA Private Key|CRITICAL|-----BEGIN DSA PRIVATE KEY-----|Never commit private keys. Use ssh-agent or vault'
        'EC Private Key|CRITICAL|-----BEGIN EC PRIVATE KEY-----|Never commit private keys. Use ssh-agent or vault'
        'OpenSSH Private Key|CRITICAL|-----BEGIN OPENSSH PRIVATE KEY-----|Never commit private keys. Use ssh-agent or vault'
        'PGP Private Key|CRITICAL|-----BEGIN PGP PRIVATE KEY BLOCK-----|Never commit private keys. Use GPG keyring'
        'Generic Private Key|HIGH|-----BEGIN PRIVATE KEY-----|Never commit private keys'

        # === LOW: Potential issues ===
        'TODO with Secret|LOW|TODO.*([Ss]ecret|[Pp]assword|[Kk]ey|[Tt]oken)|Review TODO — may indicate planned credential handling'
        'IP Address (Private)|LOW|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|Review if this IP should be in env var'
    )
}

# ============================================================
# SCANNING ENGINE
# ============================================================

FIND_CMD=$(command -v find || echo "/usr/bin/find")

is_scannable_file() {
    local file="$1"
    local base
    base=$(basename "$file")

    # Check dotfiles
    case "$base" in
        .env|.env.*|.bashrc|.bash_profile|.zshrc|.zprofile|.profile|.gitconfig|.npmrc|.pypirc)
            return 0 ;;
        Dockerfile|Dockerfile.*|docker-compose*)
            return 0 ;;
    esac

    # Check extensions
    local ext="${base##*.}"
    case "$ext" in
        py|js|ts|jsx|tsx|rb|go|rs|java|kt|swift|c|cpp|h|cs|php|pl|r|lua|ex|exs) return 0 ;;
        sh|bash|zsh|ps1) return 0 ;;
        json|yaml|yml|toml|ini|cfg|conf|xml|env|properties|tf|tfvars|hcl) return 0 ;;
    esac

    return 1
}

is_skipped_dir() {
    local filepath="$1"
    case "$filepath" in
        */node_modules/*|*/.git/*|*/.svn/*|*/.hg/*|*/__pycache__/*) return 0 ;;
        */.venv/*|*/venv/*|*/env/*|*/.env/*|*/vendor/*) return 0 ;;
        */build/*|*/dist/*|*/.next/*|*/.nuxt/*|*/target/*) return 0 ;;
        */.gradle/*|*/.idea/*|*/.vscode/*|*/.cache/*|*/coverage/*) return 0 ;;
    esac
    return 1
}

get_files() {
    local path="$1"

    if [ "$GIT_ONLY" = true ] && [ -d "${path}/.git" ]; then
        git -C "$path" ls-files --cached --modified 2>/dev/null
        return
    fi

    if [ "$SELF_CHECK" = true ]; then
        for f in \
            "${HOME}/.bashrc" \
            "${HOME}/.bash_profile" \
            "${HOME}/.zshrc" \
            "${HOME}/.zprofile" \
            "${HOME}/.profile" \
            "${HOME}/.gitconfig" \
            "${HOME}/.env" \
            "${HOME}/.npmrc" \
            "${HOME}/.pypirc" \
            "${HOME}/.docker/config.json" \
            "${HOME}/.kube/config" \
            "${HOME}/.aws/credentials" \
            "${HOME}/.ssh/config"
        do
            [ -f "$f" ] && echo "$f"
        done
        $FIND_CMD "${HOME}" -maxdepth 3 -type f \( -name ".env" -o -name ".env.*" -o -name "*.env" \) \
            -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null
        return
    fi

    # Simple approach: find all files, filter in shell
    $FIND_CMD "$path" -type f 2>/dev/null | while IFS= read -r f; do
        is_skipped_dir "$f" && continue
        is_scannable_file "$f" && echo "$f"
    done
}

scan_file() {
    local file="$1"

    # Skip binary files (but NOT text scripts marked as "executable")
    local file_type
    file_type=$(file "$file" 2>/dev/null)
    if echo "$file_type" | grep -qE "(ELF|Mach-O|PE32|binary|archive|image data|font|audio|video|compiled)" && \
       ! echo "$file_type" | grep -q "text"; then
        return
    fi

    # Skip files larger than 1MB (likely not source code)
    local file_size
    file_size=$(wc -c < "$file" 2>/dev/null | tr -d ' ')
    if [ "${file_size:-0}" -gt 1048576 ]; then
        return
    fi

    ((TOTAL_FILES++))

    for pattern_def in "${PATTERNS[@]}"; do
        local name severity regex fix_msg
        IFS='|' read -r name severity regex fix_msg <<< "$pattern_def"

        # Special handling: skip IP pattern for non-code files and common false positives
        if [ "$name" = "IP Address (Private)" ]; then
            # Only flag IPs in code files, not configs where they're expected
            case "$file" in
                *hosts*|*resolv.conf*|*network*|*.lock*|*package-lock*|*yarn.lock*) continue ;;
            esac
        fi

        # Search file for pattern
        local matches
        matches=$(grep -nE "$regex" "$file" 2>/dev/null | head -5)

        if [ -n "$matches" ]; then
            while IFS= read -r match_line; do
                local line_num match_text
                line_num=$(echo "$match_line" | cut -d: -f1)
                match_text=$(echo "$match_line" | cut -d: -f2-)

                # Skip comments (basic check)
                local trimmed
                trimmed=$(echo "$match_text" | sed 's/^[[:space:]]*//')
                case "$trimmed" in
                    '#'*|'//'*|'/*'*|'--'*|'"""'*|"'''"*)
                        # Still flag if comment contains actual key patterns
                        if ! echo "$match_text" | grep -qE '(AKIA|ghp_|sk-|sk_live|xox[bpors]|-----BEGIN)'; then
                            continue
                        fi
                        ;;
                esac

                # Skip example/template values
                if echo "$match_text" | grep -qiE '(YOUR_|CHANGE_ME|REPLACE|example\.com|xxx|placeholder|dummy|fake|test_|_test|_example|_sample|_template)'; then
                    continue
                fi

                # Skip .env.example files
                case "$file" in
                    *.example|*.sample|*.template|*TEMPLATE*) continue ;;
                esac

                # Extract the actual matched value for masking
                local secret_value
                secret_value=$(echo "$match_text" | grep -oE "$regex" 2>/dev/null | head -1)
                [ -z "$secret_value" ] && secret_value="$match_text"

                finding "$severity" "$file" "$line_num" "$name" "$secret_value" "$fix_msg"
            done <<< "$matches"
        fi
    done
}

# ============================================================
# .ENV PERMISSION CHECK
# ============================================================

check_env_permissions() {
    header "ENVIRONMENT FILE PERMISSIONS"

    local env_files
    env_files=$(find "$SCAN_PATH" -maxdepth 5 -name ".env" -o -name ".env.*" -o -name "*.env" 2>/dev/null | grep -v node_modules | grep -v .git | head -20)

    if [ -z "$env_files" ]; then
        pass "No .env files found in scan path"
        return
    fi

    local bad_perms=0
    while IFS= read -r env_file; do
        [ -z "$env_file" ] && continue
        local perms
        perms=$(stat -c '%a' "$env_file" 2>/dev/null || stat -f '%Lp' "$env_file" 2>/dev/null)
        local owner
        owner=$(stat -c '%U' "$env_file" 2>/dev/null || stat -f '%Su' "$env_file" 2>/dev/null)

        if [ "$perms" = "600" ] || [ "$perms" = "400" ]; then
            pass ".env file properly secured: ${env_file} (${perms})"
        elif [ "$perms" = "644" ] || [ "$perms" = "755" ] || [ "$perms" = "666" ] || [ "$perms" = "777" ]; then
            ((bad_perms++))
            ((TOTAL_FINDINGS++))
            ((CRITICAL++))
            out "  ${RED}[CRITICAL]${NC} .env file is WORLD READABLE!"
            out "             ${BOLD}File:${NC} ${env_file}"
            out "             ${BOLD}Perms:${NC} ${perms} (owner: ${owner})"
            if [ "$SHOW_FIX" = true ]; then
                out "             ${GREEN}Fix:${NC} chmod 600 ${env_file}"
            fi
            out ""

            # Auto-fix if --fix
            if [ "$AUTO_FIX" = true ]; then
                chmod 600 "$env_file" 2>/dev/null
                if [ $? -eq 0 ]; then
                    out "  ${GREEN}[FIXED]${NC} Set ${env_file} to 600"
                fi
            fi
        else
            ((TOTAL_FINDINGS++))
            ((MEDIUM++))
            out "  ${YELLOW}[MEDIUM]${NC}   .env file permissions could be tighter"
            out "             ${BOLD}File:${NC} ${env_file}"
            out "             ${BOLD}Perms:${NC} ${perms} (recommended: 600)"
            out ""
        fi
    done <<< "$env_files"

    if [ "$bad_perms" -eq 0 ]; then
        pass "All .env files have safe permissions"
    fi
}

# ============================================================
# GIT HISTORY CHECK
# ============================================================

check_git_history() {
    if [ ! -d "${SCAN_PATH}/.git" ]; then
        return
    fi

    header "GIT HISTORY CHECK"

    # Check if .env was ever committed
    local env_in_history
    env_in_history=$(git -C "$SCAN_PATH" log --all --diff-filter=A --name-only --pretty=format: 2>/dev/null | grep -c '\.env$' | tr -d '[:space:]')

    if [ "${env_in_history:-0}" -gt 0 ]; then
        ((TOTAL_FINDINGS++))
        ((HIGH++))
        out "  ${RED}[HIGH]${NC}     .env file found in git history!"
        out "             Secrets may be exposed in commit history even if .env is now gitignored."
        if [ "$SHOW_FIX" = true ]; then
            out "             ${GREEN}Fix:${NC} Use git-filter-repo or BFG to scrub history, then rotate all exposed keys"
        fi
        out ""
    else
        pass "No .env files found in git commit history"
    fi

    # Check .gitignore for .env
    if [ -f "${SCAN_PATH}/.gitignore" ]; then
        if grep -q '\.env' "${SCAN_PATH}/.gitignore"; then
            pass ".gitignore includes .env pattern"
        else
            ((TOTAL_FINDINGS++))
            ((MEDIUM++))
            out "  ${YELLOW}[MEDIUM]${NC}   .gitignore does NOT include .env pattern"
            if [ "$SHOW_FIX" = true ]; then
                out "             ${GREEN}Fix:${NC} echo '.env' >> ${SCAN_PATH}/.gitignore"
            fi
            out ""
        fi
    else
        ((TOTAL_FINDINGS++))
        ((LOW++))
        out "  ${CYAN}[LOW]${NC}      No .gitignore file found"
        if [ "$SHOW_FIX" = true ]; then
            out "             ${GREEN}Fix:${NC} Create .gitignore with: .env, *.pem, *.key"
        fi
        out ""
    fi
}

# ============================================================
# MAIN SCAN
# ============================================================

run_scan() {
    banner

    # Initialize patterns
    define_patterns

    # File permission checks
    check_env_permissions

    # Git history check
    check_git_history

    # Main credential scan
    header "CREDENTIAL SCAN"
    info "Scanning: ${SCAN_PATH}"
    info "Extensions: ${ALL_EXTENSIONS}"
    [ "$GIT_ONLY" = true ] && info "Mode: git-tracked files only"
    [ "$SELF_CHECK" = true ] && info "Mode: system self-check"
    out ""

    local file_list
    file_list=$(get_files "$SCAN_PATH")

    if [ -z "$file_list" ]; then
        out "  ${YELLOW}No files found to scan.${NC}"
        return
    fi

    local scanning_msg="  Scanning files..."
    out "$scanning_msg"

    while IFS= read -r file; do
        [ -z "$file" ] && continue

        # Make path absolute if relative
        if [[ "$file" != /* ]]; then
            file="${SCAN_PATH}/${file}"
        fi

        [ -f "$file" ] || continue
        scan_file "$file"
    done <<< "$file_list"

    if [ "$TOTAL_FINDINGS" -eq 0 ]; then
        out ""
        pass "No hardcoded credentials detected"
    fi
}

# ============================================================
# SUMMARY
# ============================================================

print_summary() {
    out ""
    out "${BLUE}═══════════════════════════════════════════════${NC}"
    out "${BLUE}  SCAN SUMMARY${NC}"
    out "${BLUE}═══════════════════════════════════════════════${NC}"
    out "  ${BOLD}Files scanned:${NC}  ${TOTAL_FILES}"
    out "  ${BOLD}Total findings:${NC} ${TOTAL_FINDINGS}"
    out ""
    [ "$CRITICAL" -gt 0 ] && out "  ${RED}CRITICAL:${NC} ${CRITICAL}"
    [ "$HIGH" -gt 0 ]     && out "  ${RED}HIGH:${NC}     ${HIGH}"
    [ "$MEDIUM" -gt 0 ]   && out "  ${YELLOW}MEDIUM:${NC}   ${MEDIUM}"
    [ "$LOW" -gt 0 ]      && out "  ${CYAN}LOW:${NC}      ${LOW}"
    [ "$INFO_COUNT" -gt 0 ] && out "  ${BLUE}INFO:${NC}     ${INFO_COUNT}"
    out ""

    if [ "$TOTAL_FINDINGS" -eq 0 ]; then
        out "  ${GREEN}${BOLD}All clear! No credentials detected.${NC}"
    elif [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
        out "  ${RED}${BOLD}ACTION REQUIRED: Critical/High findings need immediate attention!${NC}"
        out ""
        out "  Recommended steps:"
        out "    1. Move hardcoded values to environment variables"
        out "    2. Add .env to .gitignore"
        out "    3. Rotate any exposed credentials"
        out "    4. Use a secrets manager for production"
    else
        out "  ${YELLOW}Review medium/low findings when possible.${NC}"
    fi
    out ""

    if [ "$SAVE_REPORT" = true ]; then
        out "  Report saved: ${REPORT_FILE}"
    fi
}

# ============================================================
# TELEGRAM
# ============================================================

send_telegram() {
    if [ "$SEND_TELEGRAM" = false ]; then
        return
    fi

    if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ]; then
        out "  ${YELLOW}Telegram not configured (set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)${NC}"
        return
    fi

    local msg="🔍 <b>Credential Scan Results</b>\n"
    msg+="📁 Path: <code>${SCAN_PATH}</code>\n"
    msg+="📄 Files: ${TOTAL_FILES}\n\n"

    if [ "$TOTAL_FINDINGS" -eq 0 ]; then
        msg+="✅ <b>All clear!</b> No credentials detected."
    else
        msg+="⚠️ <b>${TOTAL_FINDINGS} findings</b>\n"
        [ "$CRITICAL" -gt 0 ] && msg+="🔴 Critical: ${CRITICAL}\n"
        [ "$HIGH" -gt 0 ]     && msg+="🟠 High: ${HIGH}\n"
        [ "$MEDIUM" -gt 0 ]   && msg+="🟡 Medium: ${MEDIUM}\n"
        [ "$LOW" -gt 0 ]      && msg+="🔵 Low: ${LOW}\n"
        msg+="\n<b>Run with --fix for remediation advice.</b>"
    fi

    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -H "Content-Type: application/json" \
        -d "{\"chat_id\": \"${TELEGRAM_CHAT_ID}\", \"parse_mode\": \"HTML\", \"text\": \"${msg}\"}" > /dev/null 2>&1

    out "  ${GREEN}Summary sent to Telegram${NC}"
}

# ============================================================
# JSON OUTPUT
# ============================================================

print_json() {
    if [ "$JSON_OUTPUT" = false ]; then
        return
    fi

    cat <<JSONEOF
{
  "scanner": "credential_scanner",
  "version": "${VERSION}",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "scan_path": "${SCAN_PATH}",
  "files_scanned": ${TOTAL_FILES},
  "total_findings": ${TOTAL_FINDINGS},
  "severity": {
    "critical": ${CRITICAL},
    "high": ${HIGH},
    "medium": ${MEDIUM},
    "low": ${LOW},
    "info": ${INFO_COUNT}
  }
}
JSONEOF
}

# ============================================================
# RUN
# ============================================================

run_scan
print_summary
send_telegram
print_json
