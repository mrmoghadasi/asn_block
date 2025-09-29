#!/bin/bash

# Exit on any error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}This script must be run as root (use sudo).${NC}"
  exit 1
fi

echo -e "${GREEN}Starting installation of asn_block...${NC}"

# Install system dependencies
echo "Installing system dependencies..."
apt update
apt install -y iptables iptables-persistent python3 python3-pip git ipset jq

# Create directory for configuration
CONFIG_DIR="/etc/as-blocklist"
mkdir -p "$CONFIG_DIR"
mkdir -p "$CONFIG_DIR/blocklist"
mkdir -p "$CONFIG_DIR/iptable_rule_backup"
chmod 755 "$CONFIG_DIR"

# Download the repository
TEMP_DIR=$(mktemp -d)
echo "Downloading asn_block repository to $TEMP_DIR..."
git clone https://github.com/mrmoghadasi/asn_block.git "$TEMP_DIR/asn_block"

# Copy configuration file
echo "Copying as-blocklist.yaml to $CONFIG_DIR..."
cp "$TEMP_DIR/asn_block/as-blocklist.yaml" "$CONFIG_DIR/as-blocklist.yaml"
chmod 644 "$CONFIG_DIR/as-blocklist.yaml"

# Copy Python scripts to $CONFIG_DIR
echo "Installing scripts to $CONFIG_DIR..."
cp "$TEMP_DIR/asn_block/asblock_fetch.py" "$CONFIG_DIR/asblock_fetch.py"
cp "$TEMP_DIR/asn_block/asblock_apply.py" "$CONFIG_DIR/asblock_apply.py"
chmod 755 "$CONFIG_DIR/asblock_fetch.py"
chmod 755 "$CONFIG_DIR/asblock_apply.py"

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install requests pyyaml

# Copy systemd service and timer files
echo "Setting up systemd services and timers..."
cp "$TEMP_DIR/asn_block/asblock-fetch.service" /etc/systemd/system/
cp "$TEMP_DIR/asn_block/asblock-fetch.timer" /etc/systemd/system/
cp "$TEMP_DIR/asn_block/asblock-apply.service" /etc/systemd/system/
cp "$TEMP_DIR/asn_block/asblock-apply.timer" /etc/systemd/system/
chmod 644 /etc/systemd/system/asblock-fetch.service
chmod 644 /etc/systemd/system/asblock-fetch.timer
chmod 644 /etc/systemd/system/asblock-apply.service
chmod 644 /etc/systemd/system/asblock-apply.timer

# Reload systemd and enable timers
echo "Enabling and starting systemd timers..."
systemctl daemon-reload
systemctl enable asblock-fetch.timer
systemctl enable asblock-apply.timer
systemctl start asblock-fetch.timer
systemctl start asblock-apply.timer

# Ensure iptables-persistent saves rules
echo "Configuring iptables-persistent..."
if [ ! -f /etc/iptables/rules.v4 ]; then
  iptables-save > /etc/iptables/rules.v4
fi
if [ ! -f /etc/iptables/rules.v6 ]; then
  ip6tables-save > /etc/iptables/rules.v6
fi

# Clean up
echo "Cleaning up temporary files..."
rm -rf "$TEMP_DIR"

echo -e "${GREEN}Installation completed successfully!${NC}"
echo "The as-blocklist.yaml configuration file is located at $CONFIG_DIR/as-blocklist.yaml."
echo "Edit it to specify the ASNs to block."
echo "The fetch and apply scripts will run automatically based on the timer configurations."
echo "To manually trigger the scripts, run:"
echo "  sudo systemctl start asblock-fetch.service"
echo "  sudo systemctl start asblock-apply.service"