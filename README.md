# IP Address Allocator (DHCP Server) - V1.00

A small Windows GUI tool that listens on a selected network interface and
answers DHCP **Discover / Request** packets with one fixed IP address
(default `192.168.1.20`). Written in Python with **Scapy** and **PyQt5**,
distributed as a single-file executable.

Version: **V1.00** (first public release)

## Features

- Lists usable network interfaces with their IPv4 addresses
- Configurable IP address to hand out
- Sends a DHCP **Offer** for Discover and a DHCP **ACK** for Request
- Logs successful assignments with a timestamp
- Start / Stop at any time; sniffing and packet sending run in background threads
- English UI, no console window, no installation needed

## Download

Get `DHCP_Server_V1.00.exe` from the
[GitHub Releases](https://github.com/hq8231516/DHCP_SERVER/releases/tag/V1.00)
page. The repository itself contains only source code and documentation.

## Requirements

| Item | Details |
| --- | --- |
| OS | Windows 10 / 11, 64-bit |
| Npcap | Required by Scapy for packet capture and raw Ethernet sending. Install [Npcap](https://npcap.com/) (WinPcap API-compatible mode). |
| Privileges | **Administrator** - the executable requests elevation (UAC) at startup. |
| Network | The selected NIC needs a static IPv4 address in the same subnet as the IP being assigned; no other DHCP server should be active on that segment. |
| Firewall | UDP ports 67 / 68 must not be blocked. |

> This is a lightweight allocator for bench / lab use, not a full DHCP server.
> It does not keep a lease database, does not answer NAK / Release / Inform,
> and always offers the same IP address to every client.

## Usage

1. Run `DHCP_Server_V1.00.exe` (accept the UAC prompt).
2. Choose the **Interface** connected to the device under test.
3. Set the IP to assign in **Assign IP** (default `192.168.1.20`).
4. Click **Start**. The log shows `Started on <interface> (<server IP>), offering <IP>`.
5. Power on or reboot the client device. When it requests an address, the log
   shows `Assigned: MAC=xx:xx:xx:xx:xx:xx -> IP=192.168.1.20`.
6. Click **Stop** (or close the window) when finished. The log shows `Stopped.`

## How it works

```
Client                IP Address Allocator
  |--- DHCP Discover --->|
  |<---- DHCP Offer -----|  yiaddr = configured IP, server_id = NIC IP
  |--- DHCP Request ---->|
  |<----- DHCP ACK ------|  lease 12 h, mask 255.255.255.0, router = NIC IP
```

Packets are captured with `sniff(filter="udp and (port 67 or port 68)")` and
crafted replies are sent at layer 2 with `sendp()`, using the selected
interface's MAC address as source. A dedicated sender thread drains the
outgoing queue so the capture callback never blocks.

## Build from source

```bash
pip install scapy==2.7.0 PyQt5==5.15.2 pyinstaller==6.19.0

python -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin ^
  --name DHCP_Server_V1.00 --collect-all scapy dhcp_server.py
```

The executable is written to `dist/`. Npcap is never bundled - it must be
installed on the target machine.

## Troubleshooting

- **Interface list is empty** - install Npcap, run as administrator, and make
  sure the NIC has a valid IPv4 address (not APIPA / loopback).
- **`Cannot get the MAC address of interface ...`** - check the NIC in
  `ipconfig /all`; try another interface.
- **Client receives no IP** - check cable/link, subnet, local firewall on UDP
  67/68, and whether another DHCP server is present on the same segment.
- **Antivirus flags the executable** - PyInstaller one-file binaries are a
  common false positive. Build from source if you need to verify it.
- **UAC prompt on every start** - expected: raw packet capture needs elevation.

## Files

| File | Description |
| --- | --- |
| `dhcp_server.py` | Application source (English UI, V1.00) |
| `README.md` | This document |
| `.gitignore` | Excludes build artifacts and local state |

## License

Not specified in this release.
