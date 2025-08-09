#!/usr/bin/env bash
#
# setup.sh - Dependency installer for Ultimate Vuln Scan MEGA
# Author: prakashchand72
# License: MIT
#
# This script installs all dependencies required for Ultimate Vuln Scan MEGA.
# It is idempotent: re-running will update existing tools instead of reinstalling.
#
# Tested on: Ubuntu, Debian, Kali Linux
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
#

set -e

# Colors
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
RESET="\033[0m"

echo -e "${GREEN}[+] Starting Ultimate Vuln Scan MEGA setup...${RESET}"

# Ensure script is run as a non-root user with sudo privileges
if [[ "$EUID" -eq 0 ]]; then
  echo -e "${RED}[-] Please do NOT run as root. Run as a regular user with sudo privileges.${RESET}"
  exit 1
fi

# Detect OS
if [[ -f /etc/debian_version ]]; then
  OS="debian"
else
  echo -e "${RED}[-] Unsupported OS. This script only works on Debian/Ubuntu/Kali.${RESET}"
  exit 1
fi

# Install system packages
echo -e "${GREEN}[+] Installing system packages...${RESET}"
sudo apt update -y
sudo apt install -y git curl wget unzip jq python3 python3-pip build-essential

# Install Go if missing
if ! command -v go &>/dev/null; then
  echo -e "${YELLOW}[~] Installing Go...${RESET}"
  GO_VERSION="1.22.5"
  wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
  rm "go${GO_VERSION}.linux-amd64.tar.gz"
  echo "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" >> ~/.bashrc
  source ~/.bashrc
else
  echo -e "${GREEN}[+] Go already installed. Skipping...${RESET}"
fi

# Install Node.js if missing
if ! command -v node &>/dev/null; then
  echo -e "${YELLOW}[~] Installing Node.js...${RESET}"
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt install -y nodejs
else
  echo -e "${GREEN}[+] Node.js already installed. Skipping...${RESET}"
fi

# Function to install/update Go tools
install_go_tool() {
  local tool=$1
  local repo=$2
  if ! command -v "$tool" &>/dev/null; then
    echo -e "${YELLOW}[~] Installing $tool...${RESET}"
    go install "$repo"@latest
  else
    echo -e "${GREEN}[+] Updating $tool...${RESET}"
    go install "$repo"@latest
  fi
}

# Install/Update Go-based tools
install_go_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei
install_go_tool httpx github.com/projectdiscovery/httpx/cmd/httpx
install_go_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder
install_go_tool waybackurls github.com/tomnomnom/waybackurls
install_go_tool gf github.com/tomnomnom/gf
install_go_tool ffuf github.com/ffuf/ffuf
install_go_tool gobuster github.com/OJ/gobuster/v3
install_go_tool anew github.com/tomnomnom/anew
install_go_tool unfurl github.com/tomnomnom/unfurl
install_go_tool uro github.com/s0md3v/uro
install_go_tool qsreplace github.com/tomnomnom/qsreplace
install_go_tool amass github.com/owasp-amass/amass/v4/...

# Python-based tools
pip3 install --upgrade pip
pip3 install waymore arjun xsstrike dalfox

# Update Nuclei templates
echo -e "${GREEN}[+] Updating Nuclei templates...${RESET}"
nuclei --update-templates

# Update Jaeles signatures if installed
if command -v jaeles &>/dev/null; then
  echo -e "${GREEN}[+] Updating Jaeles signatures...${RESET}"
  jaeles config update
fi

echo -e "${GREEN}[+] Setup complete! All tools are ready to use.${RESET}"
