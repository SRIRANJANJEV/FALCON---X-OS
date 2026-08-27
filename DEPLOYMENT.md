# FALCON-X Deployment Guide

## Raspberry Pi 4 Deployment

### Prerequisites

- Raspberry Pi 4 (4GB+ RAM recommended)
- 32GB+ microSD card
- Ethernet cable (recommended)
- Power supply (USB-C, 5V/3A)
- Another computer for initial setup

### Step 1: Flash Raspberry Pi OS

1. Download Raspberry Pi OS Lite 64-bit (Bookworm or later)
2. Flash to SD card using Raspberry Pi Imager or dd:
```bash
# Linux/macOS
sudo dd if=raspios-lite-arm64.img of=/dev/sdX bs=4M status=progress
sync
```

### Step 2: Enable SSH (first boot)

After flashing, create an empty file on the boot partition:
```bash
touch /boot/ssh
```

### Step 3: Boot and Connect

1. Insert SD card into Raspberry Pi 4
2. Connect Ethernet cable
3. Power on the device
4. Find the device on your network (check router DHCP table)
5. SSH in:
```bash
ssh pi@<ip-address>
# Default password: raspberry (change immediately!)
```

### Step 4: Update System

```bash
sudo apt update && sudo apt upgrade -y
sudo reboot
```

### Step 5: Install FALCON-X

Transfer FALCON-X to the Pi and run the installer:

```bash
# From your development machine
scp -r falconx-os/ pi@<pi-ip>:/tmp/falconx-os/

# On the Pi
cd /tmp/falconx-os
sudo chmod +x install.sh
sudo ./install.sh
```

### Step 6: Verify Installation

```bash
# Check status
falconx status

# Check health
falconx health

# View logs
falconx logs falconx-engine
```

### Step 7: Access Dashboard

Open a browser and navigate to:
```
https://<pi-ip-address>:8443
```

## First Boot Behavior

After installation, FALCON-X will:

1. Generate a unique device identity
2. Create service users
3. Configure networking (DHCP)
4. Set up firewall rules
5. Start all services automatically

The first boot is idempotent - if interrupted, running the setup again will safely continue.

## Network Configuration

### DHCP (default)

FALCON-X uses DHCP by default. The device will automatically get an IP address from your router.

### Static IP

Edit `/etc/falconx/network.yaml`:
```yaml
interfaces:
  ethernet:
    method: "static"
static:
  address: "192.168.1.100"
  gateway: "192.168.1.1"
  netmask: "255.255.255.0"
  dns:
    - "1.1.1.1"
    - "8.8.8.8"
```

Then restart networking:
```bash
sudo systemctl restart systemd-networkd
```

## SSH Hardening (Recommended)

After installation, harden SSH access:

```bash
# Generate SSH key on your workstation
ssh-keygen -t ed25519 -C "falconx-admin"

# Copy to Pi
ssh-copy-id pi@<pi-ip>

# On the Pi, edit SSH config
sudo nano /etc/ssh/sshd_config
# Set: PasswordAuthentication no
# Set: PermitRootLogin no

sudo systemctl restart ssh
```

## Updating FALCON-X

```bash
# Transfer new files
scp -r falconx-os/ pi@<pi-ip>:/tmp/falconx-os/

# On the Pi
cd /tmp/falconx-os
sudo ./install.sh

# Restart services
falconx restart
```

## Backup

Important files to backup:
```
/etc/falconx/           # Configuration
/var/lib/falconx/       # Device identity and state
/opt/falconx/bin/       # CLI
/opt/falconx/scripts/   # Health check and setup
```

## Recovery

If FALCON-X becomes unresponsive:

```bash
# SSH in
ssh pi@<pi-ip>

# Check service status
systemctl status falconx-engine

# View logs
journalctl -u falconx-engine -n 100

# Restart all services
falconx restart

# Nuclear option: re-run first boot
sudo rm /var/lib/falconx/.first-boot-done
sudo /opt/falconx/scripts/first-boot.sh
```

## Factory Reset

To completely reset FALCON-X:

```bash
# Stop services
falconx stop

# Remove all FALCON-X data
sudo rm -rf /var/lib/falconx/*
sudo rm -f /var/lib/falconx/.first-boot-done

# Reinstall
sudo /opt/falconx/scripts/first-boot.sh
```
