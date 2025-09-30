# ASN Block

This repository provides scripts and systemd services to periodically fetch IP ranges associated with specified Autonomous System Numbers (ASNs) and block them using `iptables` on a Linux system.

## Overview

The `asn_block` project automates blocking IP ranges for specified ASNs. It uses:
- A configuration file (`as-blocklist.yaml`) to define ASNs and settings.
- A script (`asblock_fetch.py`) to fetch IP ranges for those ASNs from an external source.
- A script (`asblock_apply.py`) to apply the fetched IP ranges to `iptables`.
- Systemd services and timers (`asblock-fetch.service`, `asblock-fetch.timer`, `asblock-apply.service`, `asblock-apply.timer`) to run these scripts periodically.

## Files

- **as-blocklist.yaml**: Configuration file listing ASNs to block and related settings.
- **asblock_fetch.py**: Python script to fetch IP ranges for the specified ASNs.
- **asblock_apply.py**: Python script to apply the fetched IP ranges to `iptables`.
- **asblock-fetch.service**: Systemd service for running the fetch script.
- **asblock-fetch.timer**: Systemd timer to schedule periodic execution of the fetch script.
- **asblock-apply.service**: Systemd service for running the apply script.
- **asblock-apply.timer**: Systemd timer to schedule periodic execution of the apply script.

## How It Works

1. **Configuration**: Define ASNs and settings (e.g., source URL for IP ranges) in `as-blocklist.yaml`.
2. **Fetching IP Ranges**: The `asblock_fetch.py` script, triggered by `asblock-fetch.timer`, fetches IP ranges for the listed ASNs.
3. **Applying Blocks**: The `asblock_apply.py` script, triggered by `asblock-apply.timer`, updates `iptables` to block the fetched IP ranges.
4. **Automation**: Systemd timers ensure the scripts run at specified intervals.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/mrmoghadasi/asn_block.git
   cd asn_block
   ```

2. Install system dependencies:
   ```bash
   sudo apt update
   sudo apt install iptables iptables-persistent python3 python3-pip
   ```

3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure `as-blocklist.yaml` with the desired ASNs and settings.

5. Copy the systemd service and timer files:
   ```bash
   sudo cp asblock-fetch.service asblock-fetch.timer asblock-apply.service asblock-apply.timer /etc/systemd/system/
   ```

6. Reload systemd and enable the timers:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable asblock-fetch.timer
   sudo systemctl enable asblock-apply.timer
   sudo systemctl start asblock-fetch.timer
   sudo systemctl start asblock-apply.timer
   ```

## Easy Installation

```bash
sh <(curl -s https://raw.githubusercontent.com/mrmoghadasi/asn_block/main/setup_asn_block.sh)
```

## Usage

- Edit `as-blocklist.yaml` to specify the ASNs to block and any source settings.
- The scripts will run automatically based on the timer configurations.
- To manually trigger the scripts:
  ```bash
  sudo systemctl start asblock-fetch.service
  sudo systemctl start asblock-apply.service
  ```

## Requirements

- **System**:
  - `iptables`: For manipulating firewall rules.
  - `iptables-persistent`: To persist `iptables` rules across reboots.
  - Python 3.x: To run the scripts.
- **Python Libraries** (see `requirements.txt`):
  - `requests`: For fetching IP range data.
  - `pyyaml`: For parsing the YAML configuration file.

## Notes

- Ensure root privileges for modifying `iptables` rules and installing system packages.
- Verify the fetched IP ranges to avoid blocking unintended networks.
- Adjust timer intervals in `asblock-fetch.timer` and `asblock-apply.timer` as needed.
- Ensure the system has internet access to fetch IP range data.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for suggestions or bug reports.

## License

This project is licensed under the MIT License.
