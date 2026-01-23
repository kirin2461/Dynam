# NCP C++ User Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [GUI Application](#gui-application)
5. [CLI Tool](#cli-tool)
6. [Configuration](#configuration)
7. [Troubleshooting](#troubleshooting)
8. [Russian DPI Bypass](#russian-dpi-bypass)

## Introduction

NCP C++ is a professional implementation of the Network Control Protocol with high-performance cryptography, DPI bypass capabilities, and comprehensive license management.

### Key Features

- **Modern Cryptography**: Ed25519, Curve25519, ChaCha20-Poly1305
- **Network Control**: Packet capture, DPI bypass, traffic analysis
- **Cross-Platform**: Windows, Linux, macOS support
- **GUI & CLI**: Both graphical and command-line interfaces

## Installation

### Linux (Debian/Ubuntu)

```bash
# Download the DEB package
wget https://github.com/kirin2461/ncp-cpp/releases/latest/download/ncp-1.0.0-amd64.deb

# Install
sudo dpkg -i ncp-1.0.0-amd64.deb
sudo apt-get install -f  # Install dependencies
```

### Linux (Tarball)

```bash
tar -xzvf ncp-linux-x64.tar.gz
cd ncp-linux-x64
sudo cp ncp /usr/local/bin/
```

### macOS

```bash
# Download and mount DMG
open NCP-1.0.0.dmg

# Drag NCP.app to Applications folder
```

### Windows

1. Download `NCP-Setup.exe`
2. Run the installer
3. Follow the installation wizard

## Quick Start

### First Launch

1. Launch NCP from your applications menu or terminal
2. The dashboard will show network status
3. Configure your network interface in Settings

### Basic Usage

```bash
# Show help
ncp --help

# List network interfaces
ncp network interfaces

# Start monitoring
ncp monitor start
```

## GUI Application

### Dashboard

The main dashboard displays:
- Network traffic statistics
- Active connections
- System resource usage
- Activity log

### Network Panel

- View all network interfaces
- Monitor traffic in real-time
- Start/stop packet capture

### Settings

- Configure network interface
- Set capture parameters
- Adjust display preferences

## CLI Tool

### Network Commands

```bash
# List interfaces
ncp network interfaces

# Show interface details
ncp network info eth0

# Start capture
ncp capture start --interface eth0

# Stop capture
ncp capture stop
```

### Crypto Commands

```bash
# Generate keypair
ncp crypto keygen

# Sign message
ncp crypto sign -m "message" -k private.key

# Verify signature
ncp crypto verify -m "message" -s signature -k public.key

# Encrypt file
ncp crypto encrypt -i input.txt -o output.enc -k key.bin

# Decrypt file
ncp crypto decrypt -i output.enc -o decrypted.txt -k key.bin
```

### License Commands

```bash
# Get system HWID
ncp license hwid

# Check license status
ncp license status

# Activate license
ncp license activate YOUR-LICENSE-KEY
```

## Russian DPI Bypass

### Overview

В некоторых российских сетях применяется жёсткий DPI‑фильтр, отслеживающий TLS ClientHello и поле SNI.
Модуль DPI обхода в NCP позволяет:

- Фрагментировать ClientHello (TCP fragmentation).
- Разбивать трафик по полю SNI (SNI‑splitting).
- Вставлять фейковые пакеты с низким TTL.
- Искусственно менять порядок доставки сегментов.

### CLI: Быстрый старт для RuNet

1. Запустите локальный DPI‑прокси:

```bash
ncp dpi --mode proxy --port 8080 --target github.com --preset RuNet-Soft
```

2. Настройте браузер на использование HTTP(S)‑прокси:

- Адрес: `127.0.0.1`
- Порт: `8080`

3. Для более агрессивного режима при сильной фильтрации:

```bash
ncp dpi --mode proxy --port 8080 --target github.com --preset RuNet-Strong
```

### Safety & Legal Notes

- В некоторых странах и сетях обход DPI может нарушать локальные правила.
- **Вы несёте личную ответственность** за соответствие местным законам и правилам вашего провайдера.
- Эффективность профилей `RuNet-Soft` и `RuNet-Strong` зависит от конкретной DPI‑реализации и может отличаться в разных сетях.

## Configuration

### Configuration File

Configuration is stored in:
- Linux/macOS: `~/.config/ncp/config.json`
- Windows: `%APPDATA%\NCP\config.json`

### Example Configuration

```json
{
  "network": {
    "interface": "eth0",
    "promiscuous": true,
    "buffer_size": 65536
  },
  "capture": {
    "timeout_ms": 1000,
    "snaplen": 65535,
    "filter": ""
  },
  "gui": {
    "theme": "dark",
    "refresh_rate_ms": 500
  }
}
```

## Troubleshooting

### Common Issues

#### Permission Denied (Linux)

Packet capture requires root privileges or CAP_NET_RAW capability:

```bash
# Run as root
sudo ncp capture start

# Or set capability (one-time)
sudo setcap cap_net_raw+ep /usr/local/bin/ncp
```

#### No Interfaces Found

Ensure network drivers are installed and interfaces are up:

```bash
# Check interfaces
ip link show

# Bring interface up
sudo ip link set eth0 up
```

#### Qt Platform Plugin Error (Linux)

Install required Qt dependencies:

```bash
sudo apt-get install libqt6-xcb-platform-plugin
```

### Getting Help

- GitHub Issues: https://github.com/kirin2461/ncp-cpp/issues
- Documentation: https://github.com/kirin2461/ncp-cpp/docs

---

**Version**: 1.0.0  
**Last Updated**: January 2026
