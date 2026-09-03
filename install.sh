#!/bin/bash
set -e

RED='\033[38;5;196m'
GREEN='\033[38;5;46m'
YELLOW='\033[38;5;208m'
CYAN='\033[38;5;51m'
BOLD='\033[1m'
RESET='\033[0m'

banner() {
  echo -e "${RED}${BOLD}"
  echo " ███╗   ███╗ █████╗ ███╗   ██╗████████╗██████╗  █████╗ "
  echo " ████╗ ████║██╔══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗"
  echo " ██╔████╔██║███████║██╔██╗ ██║   ██║   ██████╔╝███████║"
  echo " ██║╚██╔╝██║██╔══██║██║╚██╗██║   ██║   ██╔══██╗██╔══██║"
  echo " ██║ ╚═╝ ██║██║  ██║██║ ╚████║   ██║   ██║  ██║██║  ██║"
  echo " ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝"
  echo -e "${RESET}"
  echo -e "${CYAN}${BOLD}  Installer v6.1.0${RESET}"
  echo ""
}

info()  { echo -e "${GREEN}[+]${RESET} $1"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $1"; }
err()   { echo -e "${RED}[✘]${RESET} $1"; }
step()  { echo -e "${CYAN}${BOLD}[*]${RESET} $1"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

detect_os() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    OS_FAMILY=$ID_LIKE
  elif [ "$(uname)" = "Darwin" ]; then
    OS="macos"
  else
    OS="unknown"
  fi
}

install_build_deps() {
  step "Installing build dependencies..."

  case "$OS" in
    kali|debian|ubuntu|linuxmint|pop)
      sudo apt update -qq
      sudo apt install -y build-essential libcurl4-openssl-dev wget
      ;;
    fedora)
      sudo dnf install -y gcc-c++ libcurl-devel wget make
      ;;
    centos|rhel|rocky|alma)
      sudo yum install -y gcc-c++ libcurl-devel wget make
      ;;
    arch|manjaro|endeavouros)
      sudo pacman -Sy --noconfirm base-devel curl wget
      ;;
    opensuse*|sles)
      sudo zypper install -y gcc-c++ libcurl-devel wget make
      ;;
    macos)
      if ! command -v brew &>/dev/null; then
        err "Install Homebrew first: https://brew.sh"
        exit 1
      fi
      brew install curl wget
      ;;
    *)
      if echo "$OS_FAMILY" | grep -qi debian; then
        sudo apt update -qq
        sudo apt install -y build-essential libcurl4-openssl-dev wget
      elif echo "$OS_FAMILY" | grep -qi rhel; then
        sudo yum install -y gcc-c++ libcurl-devel wget make
      else
        err "Unsupported OS: $OS. Install manually: g++, libcurl-dev, wget"
        exit 1
      fi
      ;;
  esac

  info "Build dependencies installed"
}

fetch_headers() {
  step "Fetching single-header libraries..."

  if [ ! -f "$SCRIPT_DIR/nlohmann/json.hpp" ]; then
    mkdir -p "$SCRIPT_DIR/nlohmann"
    wget -q --show-progress -O "$SCRIPT_DIR/nlohmann/json.hpp" \
      "https://raw.githubusercontent.com/nlohmann/json/develop/single_include/nlohmann/json.hpp"
    info "nlohmann/json.hpp downloaded"
  else
    info "nlohmann/json.hpp already exists"
  fi

  if [ ! -f "$SCRIPT_DIR/httplib.h" ]; then
    wget -q --show-progress -O "$SCRIPT_DIR/httplib.h" \
      "https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h"
    info "httplib.h downloaded"
  else
    info "httplib.h already exists"
  fi
}

build_binaries() {
  step "Building MANTRA..."

  cd "$SCRIPT_DIR"

  echo -e "  ${CYAN}Compiling server...${RESET}"
  g++ -std=c++17 -pthread -O2 main.cpp -lcurl -o mantra
  info "mantra server built"

  echo -e "  ${CYAN}Compiling MCP bridge...${RESET}"
  g++ -std=c++17 -O2 mantra_mcp.cpp -lcurl -o mantra_bridge
  info "mantra_bridge built"

  chmod +x mantra mantra_bridge
}

install_security_tools() {
  step "Installing core security tools..."

  case "$OS" in
    kali)
      info "Kali detected — most tools pre-installed"
      sudo apt install -y nmap nikto sqlmap whatweb wafw00f \
        gobuster dirb ffuf nuclei subfinder httpx-toolkit \
        amass john hashcat hydra metasploit-framework \
        binwalk foremost steghide exiftool gdb radare2 \
        smbclient enum4linux netcat-openbsd curl wget whois dig 2>/dev/null || true
      ;;
    debian|ubuntu|linuxmint|pop)
      sudo apt install -y nmap nikto sqlmap whatweb \
        gobuster dirb john hydra binwalk foremost \
        steghide exiftool gdb radare2 smbclient \
        netcat-openbsd curl wget whois dnsutils 2>/dev/null || true
      warn "Some tools (nuclei, subfinder, httpx, ffuf) need Go install:"
      warn "  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
      warn "  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
      warn "  go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
      warn "  go install github.com/ffuf/ffuf/v2@latest"
      ;;
    fedora|centos|rhel|rocky|alma)
      sudo dnf install -y nmap nikto john hydra binwalk \
        gdb radare2 curl wget whois bind-utils 2>/dev/null || true
      ;;
    arch|manjaro|endeavouros)
      sudo pacman -Sy --noconfirm nmap nikto sqlmap john hydra \
        binwalk gdb radare2 curl wget whois bind 2>/dev/null || true
      ;;
    macos)
      brew install nmap nikto sqlmap john-jumbo hydra binwalk \
        radare2 curl wget whois 2>/dev/null || true
      ;;
    *)
      warn "Install security tools manually for your OS"
      ;;
  esac

  info "Core security tools installed"
}

verify() {
  step "Verifying installation..."

  local ok=0 fail=0

  for bin in mantra mantra_bridge; do
    if [ -x "$SCRIPT_DIR/$bin" ]; then
      info "$bin — OK"
      ((ok++))
    else
      err "$bin — MISSING"
      ((fail++))
    fi
  done

  for hdr in httplib.h nlohmann/json.hpp; do
    if [ -f "$SCRIPT_DIR/$hdr" ]; then
      info "$hdr — OK"
      ((ok++))
    else
      err "$hdr — MISSING"
      ((fail++))
    fi
  done

  echo ""
  local tool_count=0
  for tool in nmap nuclei sqlmap nikto gobuster dirb ffuf subfinder httpx \
    amass hydra john hashcat metasploit whatweb wafw00f radare2 gdb \
    binwalk foremost steghide exiftool curl wget whois dig; do
    if command -v "$tool" &>/dev/null; then
      ((tool_count++))
    fi
  done
  info "$tool_count/25 security tools detected"

  echo ""
  if [ $fail -eq 0 ]; then
    echo -e "${GREEN}${BOLD}✅ Installation complete!${RESET}"
  else
    echo -e "${YELLOW}${BOLD}⚠ Installed with $fail warnings${RESET}"
  fi
}

print_usage() {
  echo ""
  echo -e "${BOLD}Quick Start:${RESET}"
  echo -e "  ${CYAN}1.${RESET} ./mantra                         # start server"
  echo -e "  ${CYAN}2.${RESET} Add mantra_bridge to Claude Desktop config"
  echo -e "  ${CYAN}3.${RESET} Restart Claude Desktop"
  echo -e "  ${CYAN}4.${RESET} Ask Claude: \"scan example.com with nmap\""
  echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────

banner
detect_os
info "Detected OS: $OS"
echo ""

case "${1:-all}" in
  deps)
    install_build_deps
    ;;
  headers)
    fetch_headers
    ;;
  build)
    build_binaries
    ;;
  tools)
    install_security_tools
    ;;
  all)
    install_build_deps
    fetch_headers
    build_binaries
    install_security_tools
    verify
    print_usage
    ;;
  *)
    echo "Usage: $0 [deps|headers|build|tools|all]"
    echo "  deps    — install build dependencies (g++, libcurl)"
    echo "  headers — download nlohmann/json.hpp and httplib.h"
    echo "  build   — compile mantra and mantra_bridge"
    echo "  tools   — install core security tools"
    echo "  all     — everything (default)"
    exit 1
    ;;
esac
