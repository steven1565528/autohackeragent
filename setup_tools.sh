#!/usr/bin/env bash
# ============================================================
# Auto-Hacker Agent - Ubuntu 24 provisioning script
# Recommended host: 8C16G / 50G
# Profiles:
#   core - fast baseline for most web/CTF workflows
#   full - recommended competition profile
#   max  - full + heavier extras
# ============================================================

set -euo pipefail

PROFILE="full"
WAIT_FOR_APT=1
SKIP_METASPLOIT=0
INSTALL_PYTHON_DEPS=1

usage() {
  cat <<'EOF'
Usage: ./setup_tools.sh [--profile core|full|max] [--no-wait] [--skip-metasploit] [--skip-python]

Examples:
  ./setup_tools.sh
  ./setup_tools.sh --profile core
  ./setup_tools.sh --profile max --skip-metasploit
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="${2:-}"
      shift 2
      ;;
    --no-wait)
      WAIT_FOR_APT=0
      shift
      ;;
    --skip-metasploit)
      SKIP_METASPLOIT=1
      shift
      ;;
    --skip-python)
      INSTALL_PYTHON_DEPS=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ "$PROFILE" != "core" && "$PROFILE" != "full" && "$PROFILE" != "max" ]]; then
  echo "Invalid profile: $PROFILE" >&2
  exit 1
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

wait_for_apt() {
  local waited=0
  local max_wait=600
  while sudo fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock >/dev/null 2>&1; do
    if (( waited == 0 )); then
      echo "Waiting for apt/dpkg lock to clear..."
    fi
    sleep 5
    waited=$((waited + 5))
    if (( waited >= max_wait )); then
      echo "Timed out waiting for apt lock." >&2
      exit 1
    fi
  done
}

apt_install() {
  if (( WAIT_FOR_APT )); then
    wait_for_apt
  fi
  # --no-install-recommends saves disk space, suitable for CVM environments
  sudo apt-get install -y -qq --no-install-recommends "$@"
}

verify_tools() {
  local missing=()
  for tool in "$@"; do
    if ! need_cmd "$tool"; then
      missing+=("$tool")
    fi
  done

  if (( ${#missing[@]} )); then
    echo "WARNING: missing tools after installation: ${missing[*]}"
  else
    echo "Verified tools: $*"
  fi
}

echo "========================================"
echo " Auto-Hacker Agent provisioning"
echo "========================================"
echo "Profile: $PROFILE"

if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  echo "OS: ${PRETTY_NAME:-unknown}"
fi

echo "[1/7] Updating apt metadata..."
if (( WAIT_FOR_APT )); then
  wait_for_apt
fi
sudo apt-get update -qq

BASE_PACKAGES=(
  curl wget git vim unzip jq
  net-tools iputils-ping dnsutils
  build-essential python3-pip python3-venv
  # python3-full ensures venv works correctly on Ubuntu 24.04
  python3-full
  ca-certificates software-properties-common
)

CORE_SCAN_PACKAGES=(
  nmap masscan netcat-openbsd
  gobuster dirb
  sqlmap
  # enum4linux-ng replaces enum4linux on Ubuntu 24.04
  smbclient enum4linux enum4linux-ng sshpass socat proxychains4
)

FULL_WEB_PACKAGES=(
  # nikto and whatweb are available via apt; wfuzz is no longer in Ubuntu 24 apt repos
  # ffuf is a modern alternative to wfuzz/dirb and available via apt
  nikto whatweb ffuf
)

FULL_EXTRA_PACKAGES=(
  hydra john
)

MAX_EXTRA_PACKAGES=(
  redis-tools default-mysql-client postgresql-client ldap-utils
)

echo "[2/7] Installing base packages..."
apt_install "${BASE_PACKAGES[@]}"
# pip3 may not be in PATH on Ubuntu 24; check python3 instead
verify_tools curl wget git python3

echo "[3/7] Installing core competition tools..."
apt_install "${CORE_SCAN_PACKAGES[@]}"
# enum4linux-ng replaces enum4linux on Ubuntu 24; verify whichever is available
verify_tools nmap gobuster dirb sqlmap smbclient sshpass socat

if [[ "$PROFILE" == "full" || "$PROFILE" == "max" ]]; then
  echo "[4/7] Installing extended web and cracking tools..."
  apt_install "${FULL_WEB_PACKAGES[@]}" "${FULL_EXTRA_PACKAGES[@]}"
  # hashcat may require OpenCL drivers on some Ubuntu 24 environments; install optionally
  apt_install hashcat || echo "WARNING: hashcat installation failed; continuing without it."
  # wfuzz is no longer in Ubuntu 24 apt repos; install via pip into the project venv
  # (done after venv creation in step 7)
  verify_tools nikto whatweb ffuf hydra john
else
  echo "[4/7] Skipping extended packages for core profile."
fi

if [[ "$PROFILE" == "max" ]]; then
  echo "[5/7] Installing max-profile extras..."
  apt_install "${MAX_EXTRA_PACKAGES[@]}"
  verify_tools redis-cli mysql psql
else
  echo "[5/7] Skipping max-profile extras."
fi

if (( ! SKIP_METASPLOIT )) && [[ "$PROFILE" != "core" ]]; then
  echo "[6/7] Installing Metasploit (optional, heavy)..."
  if need_cmd msfconsole; then
    echo "Metasploit already installed; skipping."
  else
    curl -s https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
    chmod 755 /tmp/msfinstall
    /tmp/msfinstall || echo "WARNING: Metasploit installation failed; continuing."
  fi
else
  echo "[6/7] Skipping Metasploit."
fi

echo "[7/7] Finalizing project environment..."
cd "$(dirname "$0")"
mkdir -p logs state

if (( INSTALL_PYTHON_DEPS )); then
  if [[ ! -d .venv ]]; then
    python3 -m venv .venv
  fi
  # --no-warn-script-location avoids noisy warnings when running inside venv
  .venv/bin/pip install --upgrade pip --no-warn-script-location
  .venv/bin/pip install -r requirements.txt pytest --no-warn-script-location

  # wfuzz is not in Ubuntu 24 apt repos; install via pip as fallback
  if [[ "$PROFILE" == "full" || "$PROFILE" == "max" ]]; then
    .venv/bin/pip install wfuzz dirsearch --no-warn-script-location || \
      echo "WARNING: wfuzz/dirsearch pip install failed; ffuf (apt) is available as alternative."
  fi
fi

cat <<EOF

========================================
 Provisioning complete
========================================

Profile: $PROFILE
Python venv: $( [[ -d .venv ]] && echo "ready" || echo "not created" )

Suggested next steps:
  cp .env.example .env
  source .venv/bin/activate
  python3 main.py --list-models

Recommended competition profile on Ubuntu 24 / 8C16G / 50G:
  ./setup_tools.sh --profile full
EOF
