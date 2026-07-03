# lldp-bar
LLDP, network profile, and serial console tool for [SwiftBar](https://github.com/swiftbar/SwiftBar)

![lldp-bar screenshot](swiftbar.png)

## Features
* **LLDP neighbors** — Port ID/description, VLANs and PVID, chassis name/ID, system description, and interface MAC/IP. Click to copy value to clipboard.
* **Switch access** — Each advertised management IP gets one-click actions: open web UI (HTTP/HTTPS), SSH in Terminal, copy IP.
* **IP configuration** — Switch any active interface between DHCP and profiles defined in `netconfig.json`.
* **Serial console** — Launch `screen` sessions.

## Requirements
* [lldpd](https://github.com/lldpd/lldpd) - After being installed, lldpd runs as a daemon. LLDP data is collected on all interfaces. lldp-bar interacts with lldpd via lldpcli.
* [SwiftBar](https://github.com/swiftbar/SwiftBar) - SwiftBar makes it easy to schedule and run scripts right from the mac menubar.
* Python 3 (standard library only)

## Recommended Installation
* Install the [Microsoft LLDP Enablement Package](https://www.microsoft.com/en-us/download/details.aspx?id=103383).  This package is signed and works out of the box with lldp-bar.
* Copy `lldp.py` to the SwiftBar folder.
* Optionally copy `netconfig.example.json` to `netconfig.json` in the same folder and edit it (see Configuration).

## Configuration
To add static-IP profiles or change defaults, copy `netconfig.example.json` to `netconfig.json` next to `lldp.py`:

```json
{
  "ssh_user": "admin",
  "baud_rates": [9600, 19200, 38400, 57600, 115200],
  "profiles": [
    {
      "name": "Lab",
      "ip": "10.0.0.5/24",
      "router": "10.0.0.1",
      "dns": ["10.0.0.1", "1.1.1.1"]
    },
    {
      "name": "Direct Link (no gateway)",
      "ip": "192.0.2.10/24"
    }
  ]
}
```

| Key | Meaning |
| --- | --- |
| `ssh_user` | Username for the per-neighbor SSH action (default `admin`) |
| `baud_rates` | Baud rates listed under each detected serial port |
| `profiles` | Static-IP profiles applied via `networksetup`, one click each |

Profile fields: `name` and `ip` are required (`ip` as `x.x.x.x/NN`, or plain `x.x.x.x` with a separate `subnet`). `router` is optional (omit for no gateway). `dns` is optional — omit to leave DNS untouched, `[]` to clear back to DHCP-supplied.

## Other lldpd Sources
lldpd can be installed via brew or from the [lldpd project page](https://github.com/lldpd/lldpd). These other sources may require additional steps.

After installation, confirm that that your user has access to `lldpd`.

```sh
karl@litz-dev ~ % /usr/local/sbin/lldpcli show neighbors
2025-09-28T15:32:22 [WARN/control] unable to connect to socket /var/run/lldpd.socket: Permission denied
```

If unable to connect, add your user to the _lldpd group.
```sh
karl@litz-dev ~ % sudo dseditgroup -o edit -a karl -t user _lldpd
Password:
karl@litz-dev ~ % /usr/local/sbin/lldpcli show neighbors         
-------------------------------------------------------------------------------
LLDP neighbors:
-------------------------------------------------------------------------------
```
