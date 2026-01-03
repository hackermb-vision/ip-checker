# IP Checker Bot

A Telegram bot that monitors your public IP address and notifies you when it changes.

## Features

- Monitors public IP address(es) at configurable intervals
- Sends Telegram notifications when IP changes are detected
- Supports checking multiple network interfaces or specific local addresses
- Manual IP check via `/ip` command

## Requirements

- Python 3.7+
- Telegram Bot Token (from [@BotFather](https://t.me/botfather))

## Installation

1. Clone the repository:
```bash
git clone https://github.com/hackermb-vision/ip-checker.git
cd ip-checker
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file in the project root with your configuration (see Configuration section below).

## Configuration

Create a `.env` file in the project root with the following variables:

```env
BOT_TOKEN=
ALLOWED_CHAT_IDS= # eg ALLOWED_CHAT_IDS=123456789,-1001234567890
CHECK_INTERVAL_SECONDS=60

# Optional:
# Either list interface names (Linux), e.g. eth0,wlan0
INTERFACES=eth0,wlan0

# Or list local IPv4 addresses to bind to (overrides INTERFACES), e.g. 192.168.1.10,10.0.0.5
LOCAL_ADDRS=
```

### Configuration Variables

#### Required:

- **BOT_TOKEN**: Your Telegram bot token from [@BotFather](https://t.me/botfather)
- **ALLOWED_CHAT_IDS**: Comma-separated list of Telegram chat IDs that are allowed to use the bot
  - Example: `123456789,-1001234567890`
  - You can get your chat ID by messaging [@userinfobot](https://t.me/userinfobot)
- **CHECK_INTERVAL_SECONDS**: How often to check for IP changes (minimum: 10 seconds)
  - Default: `60`

#### Optional:

- **INTERFACES**: Comma-separated list of network interface names (Linux only)
  - Example: `eth0,wlan0`
  - Requires `psutil` to be installed
  - If specified, the bot will check public IPs for each interface
  
- **LOCAL_ADDRS**: Comma-separated list of local IPv4 addresses to bind to
  - Example: `192.168.1.10,10.0.0.5`
  - If specified, this overrides `INTERFACES`
  - Use this to check multiple public IPs by binding to specific local addresses

## Usage

1. Start the bot:
```bash
python bot_ip_watcher.py
```

2. In Telegram, send `/ip` to your bot to get your current public IP address

3. The bot will automatically notify you when your IP address changes

## Systemd Service

You can run the bot as a persistent background service using systemd.

### Create the service file

Create `/etc/systemd/system/ip-checker-bot.service`:
```ini
[Unit]
Description=Telegram IP Checker Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root/ip-checker

# Load environment variables (BOT_TOKEN, ALLOWED_CHAT_IDS, etc.)
EnvironmentFile=/root/ip-checker/.env

# Use system Python (no virtualenv)
ExecStart=/usr/bin/python3 /root/ip-checker/bot_ip_watcher.py

# Run as root (suitable for containers)
User=root
Group=root

Restart=always
RestartSec=5

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target

```

### Enable and start the service

```bash
stemctl daemon-reload
systemctl daemon-reload ip-checker-bot.service

```

### Check service status and logs

```bash
systemctl status ip-checker-bot.service --no-pager
journalctl -u ip-checker-bot.service -f

```

### Notes

- The .env file must be readable by root
- /usr/bin/python3 must have all required dependencies installed
- This service works on systems with systemd (VMs, bare metal, privileged containers)
- For Docker or non-systemd containers, use a container entrypoint instead
- For this exact systemd file to work the project hast to be in `/root/` and the `.env` file has to be in `/root/ip-checker/`
- For security reasons it is recomended to use this inside an container like LXC or modify the systemd file so that it uses a dedicated user

## How It Worksk
- The bot periodically checks your public IP address by querying https://checkip.amazonaws.com/
- If multiple interfaces or local addresses are configured, it checks each one separately
- When a change is detected, it sends a notification to all allowed chat IDs
- You can also manually check your current IP by sending the `/ip` command

## License

This project is open source and available under the MIT License.
