#!/usr/bin/env bash
# EnvHarvester – Ubuntu dependency installer
# Run once before launching harvester.py:
#   chmod +x setup.sh && ./setup.sh
set -euo pipefail

TRUFFLEHOG_VERSION="3.78.0"
SHHGIT_REPO="github.com/eth0izzle/shhgit"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; }

require_root_or_sudo() {
    if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
        error "This script needs sudo for apt operations. Run with sudo or as root."
        exit 1
    fi
}

install_system_deps() {
    info "Updating apt and installing system packages…"
    sudo apt-get update -qq
    sudo apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        curl wget git ca-certificates \
        golang-go 2>/dev/null || \
    sudo apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        curl wget git ca-certificates
}

install_python_deps() {
    info "Installing Python dependencies into a virtual environment…"
    if [[ ! -d .venv ]]; then
        python3 -m venv .venv
    fi
    # shellcheck disable=SC1091
    source .venv/bin/activate
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
    info "Python deps installed. Activate with: source .venv/bin/activate"
}

install_trufflehog() {
    if command -v trufflehog &>/dev/null; then
        info "trufflehog already installed: $(trufflehog --version 2>&1 | head -1)"
        return
    fi
    info "Installing TruffleHog v${TRUFFLEHOG_VERSION}…"
    ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
    case "$ARCH" in
        amd64|x86_64) ARCH_TAG="linux_amd64" ;;
        arm64|aarch64) ARCH_TAG="linux_arm64" ;;
        *) error "Unsupported arch: $ARCH"; return 1 ;;
    esac
    TH_URL="https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_${ARCH_TAG}.tar.gz"
    TMP=$(mktemp -d)
    curl -fsSL "$TH_URL" | tar -xz -C "$TMP"
    sudo mv "$TMP/trufflehog" /usr/local/bin/trufflehog
    sudo chmod +x /usr/local/bin/trufflehog
    rm -rf "$TMP"
    info "TruffleHog installed: $(trufflehog --version 2>&1 | head -1)"
}

install_shhgit() {
    if command -v shhgit &>/dev/null; then
        info "shhgit already installed"
        return
    fi
    if ! command -v go &>/dev/null; then
        warn "Go not found – attempting to install via apt…"
        sudo apt-get install -y golang-go || {
            error "Could not install Go. Install manually and re-run."
            return 1
        }
    fi
    info "Installing shhgit via go install…"
    export GOPATH="${HOME}/go"
    export PATH="${GOPATH}/bin:${PATH}"
    go install "${SHHGIT_REPO}@latest"
    # symlink into /usr/local/bin for convenience
    if [[ -f "${GOPATH}/bin/shhgit" ]]; then
        sudo ln -sf "${GOPATH}/bin/shhgit" /usr/local/bin/shhgit
        info "shhgit installed"
    else
        warn "shhgit binary not found in \$GOPATH/bin – add ${GOPATH}/bin to \$PATH"
    fi
}

copy_shhgit_config() {
    SHHGIT_CFG_DIR="${HOME}/.shhgit"
    mkdir -p "$SHHGIT_CFG_DIR"
    if [[ ! -f "${SHHGIT_CFG_DIR}/config.yaml" ]]; then
        cp config.yaml "${SHHGIT_CFG_DIR}/config.yaml"
        info "Copied config.yaml to ${SHHGIT_CFG_DIR}/config.yaml"
    else
        warn "${SHHGIT_CFG_DIR}/config.yaml already exists – not overwriting"
    fi
}

print_usage() {
    echo ""
    echo "──────────────────────────────────────────────────────"
    echo "  EnvHarvester setup complete."
    echo ""
    echo "  Activate the venv:   source .venv/bin/activate"
    echo ""
    echo "  Usage examples:"
    echo "    # All discovery methods (dorking + real-time + deep scan)"
    echo "    python harvester.py --mode all"
    echo ""
    echo "    # Dorking only, using Serper.dev (recommended)"
    echo "    python harvester.py --mode dork --serper-key <YOUR_KEY>"
    echo ""
    echo "    # Real-time GitHub stream only (runs for 2 hours)"
    echo "    python harvester.py --mode monitor --monitor-minutes 120"
    echo ""
    echo "    # One-off deep scan of a specific repo"
    echo "    python harvester.py --repo https://github.com/owner/repo"
    echo ""
    echo "    # Print the current findings table"
    echo "    python harvester.py --show-db"
    echo ""
    echo "  Optional env vars:"
    echo "    SERPER_API_KEY   – Serper.dev key (avoids Google CAPTCHAs)"
    echo "    SEARCHAPI_KEY    – SearchAPI.io key (alternative to Serper)"
    echo "──────────────────────────────────────────────────────"
}

# ── main ───────────────────────────────────────────────────────────────────────
require_root_or_sudo
install_system_deps
install_python_deps
install_trufflehog
install_shhgit
copy_shhgit_config
print_usage
