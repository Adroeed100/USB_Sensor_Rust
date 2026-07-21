# USB Sensor

A lightweight, zero-dependency Rust utility that monitors USB activity on Linux in real time. It detects USB device connections and disconnections, fingerprints devices via sysfs, watches the filesystem for changes while a device is connected, scans for malware with ClamAV, and reports all security-relevant events as structured JSON incidents.

---

## What the Sensor Can Do

### Incident Taxonomy

Every output JSON record contains an `incident_type_id` (1–17) and a numeric `severity_id` (1=low, 2=medium, 3=high, 4=critical) matching the project's incident taxonomy:

| ID | Incident Name | Severity |
|----|---------------|----------|
| 1  | USB Device Connected | Low |
| 2  | USB Device Disconnected | Low |
| 3  | Port / Bus Topology Change | High |
| 4  | Device Class / Subclass / Protocol Change (BadUSB) | Critical |
| 5  | Serial Number Change | Critical |
| 6  | Devpath Change | High |
| 7  | Rapid Connect / Disconnect — Flapping (≥5 in 30 s) | Medium |
| 8  | Unauthorized Device Class Connected | High |
| 9  | Filesystem: File Created | Low |
| 10 | Filesystem: File Modified | Medium |
| 11 | Filesystem: File Deleted | High |
| 12 | Filesystem: File Moved / Renamed | Medium |
| 13 | Mass File Upload / Possible Exfiltration (≥10 uploads in 60 s) | Critical |
| 14 | udevadm Monitor Crash / Restart (≥3 in 300 s) | Medium |
| 15 | Malformed USB Event / Parse Failure | Critical |
| 16 | Anomalous Enumeration Burst (≥20 sub-devices in 10 s) | Medium |
| 17 | ClamAV Threat Found | Critical |

---

### 1. Real-Time USB Device Monitoring
- Listens to the Linux kernel's `udevadm monitor` for USB subsystem events (`add`, `bind`, `remove`, `unbind`, `change`).
- Automatically restarts the monitor if `udevadm` exits unexpectedly (and tracks restart rate for type 14).

### 2. USB Device Fingerprinting
For every USB event, the sensor captures a full device snapshot from sysfs:
- Vendor ID (`idVendor`) and Product ID (`idProduct`)
- Serial number
- Device class, subclass, and protocol (e.g. mass storage, HID, hub)
- Manufacturer and product strings
- Bus topology (`busnum` / `devnum`) and port path (`ID_PATH` / `ID_PATH_TAG`)

### 3. Device Anomaly Detection (types 3–6)
The sensor tracks known devices and detects suspicious attribute changes on `change` events:
- **Type 3** – Port or bus topology change (device re-appeared on a different port/hub)
- **Type 4** – Class/subclass/protocol change — classic BadUSB / USB spoofing indicator
- **Type 5** – Serial number change with same VID/PID
- **Type 6** – Kernel devpath change outside a normal reconnect cycle

### 4. Rapid Reconnection Detection — Flapping (type 7)
Tracks connect + disconnect events per device key in a 30-second sliding window. Emits a `medium` incident when a device toggles ≥5 times, which can indicate a failing device or a deliberate reconnection attack.

### 5. Unauthorized Device Class Check (type 8)
When `ALLOWED_USB_CLASSES` is set, any newly connected device whose `bDeviceClass` is not in the allow-list triggers a `high` incident. Devices with class `00` (interface-defined) are excluded from the check.

### 6. Filesystem Monitoring — inotify (types 9–13)
When a USB device is connected, a background inotify watcher starts automatically:
- **Type 9** – File created
- **Type 10** – File modified or attribute changed
- **Type 11** – File deleted (high severity)
- **Type 12** – File moved / renamed
- **Type 13** – Upload burst: ≥10 close-after-write events in 60 seconds (possible exfiltration)

Only one watcher thread runs at a time. It stops automatically on USB disconnect.

### 7. ClamAV Malware Scanning (type 17)
On every USB connect, a ClamAV scan is started in a background thread:
- Runs `clamscan --no-summary --infected -r <watched_dir>`
- Emits a `critical` JSON incident **only** for files flagged as `FOUND`
- All clean-scan output goes to stderr
- The scan is automatically aborted if the USB device is disconnected before completion to prevent CPU/memory leaks.

### 8. Udevadm Crash Tracking (type 14)
Tracks how often `udevadm monitor` exits or fails to launch. Emits a `medium` incident when ≥3 restarts occur within 300 seconds, which may indicate a crash-inducing device.

### 9. Malformed Event Detection (type 15)
Detects structurally invalid udev events — a header is present but neither the header text nor any property resolves to a valid action, and `DEVPATH` is also absent. Emits a `critical` incident.

### 10. Enumeration Burst Detection (type 16)
Counts `add`/`bind` sub-device events within a 10-second window. Emits a `medium` incident when ≥20 are seen in one burst, which may indicate a malicious composite or hub device.

### 11. Output Channel Separation
- **stdout** — structured JSON incident records only (pipe to SIEM, log collector, etc.)
- **stderr** — diagnostic messages (USB event details, watcher status, clamscan clean results)

---

## Requirements

- Linux
- `udevadm` available on `PATH` (part of `systemd`)
- `clamscan` available on `PATH` (`sudo apt install clamav` or equivalent)
- Rust toolchain (edition 2024)

## Build

```bash
cargo build --release
```

## Run

```bash
cargo run
```

To capture only JSON incidents to a file while watching diagnostics in the terminal:

```bash
cargo run > incidents.json
```

---

## Configuration

All configuration is via environment variables — no config files needed.

| Variable | Description | Default |
|---|---|---|
| `FS_MONITOR_TARGET` | Directory or file to watch with inotify and ClamAV | `~/Projects/rust/sensor` |
| `INCIDENT_SENSOR_ID` | `sensor_id` field in every incident record | `sensor-01` |
| `INCIDENT_ECU_ID` | `ecu_id` field in every incident record | `unknown_ecu` |
| `ALLOWED_USB_CLASSES` | Comma-separated hex USB class codes that are permitted (e.g. `03,09`). Type-8 check is skipped when unset. | _(unset)_ |
| `IDSM_IP` | IP address of the Intrusion Detection System Manager | `127.0.0.1` |
| `IDSM_PORT` | Port of the Intrusion Detection System Manager | `8081` |

### Example

```bash
FS_MONITOR_TARGET=/media/usb0 \
INCIDENT_SENSOR_ID=sensor-lab-01 \
INCIDENT_ECU_ID=ecu-gateway \
ALLOWED_USB_CLASSES=03,09 \
cargo run
```

---

## How It Works

1. `main.rs` spawns `udevadm monitor --kernel --udev --property --subsystem-match=usb` and reads its output line by line.
2. Events are parsed into key/value property maps and dispatched to `usb_monitor::process_udev_event`.
3. On the first `add`/`bind` event of a plug cycle, a **type 1** incident is emitted, the inotify watcher starts, and a ClamAV scan is launched.
4. On the first `remove`/`unbind` event, a **type 2** incident is emitted and the watcher stops.
5. Subsequent events for the same physical device are deduplicated.
6. On `change` events for a known device, anomaly checks run (types 3–6).
7. The inotify watcher thread emits typed incidents (9–13) for every filesystem event it sees.
8. If `udevadm` exits, it is restarted after 2 seconds; repeated crashes trigger a type-14 incident.

---

## Output Format

Every incident is a JSON object on a single logical block written to **stdout** and also forwarded to the IDSM over HTTP POST (to integrate with the automotive IDPS framework).

```json
{
  "event_id": "USB_LIFECYCLE_1753000000000_a1b2c3d4e5f67890",
  "incident_type_id": 1,
  "sensor_id": "sensor-01",
  "timestamp": "2026-07-20T06:46:00Z",
  "ecu_id": "unknown_ecu",
  "bus_type": "USB",
  "source": "/devices/pci0000:00/0000:00:14.0/usb1/1-2",
  "can_id": "n/a",
  "direction": "rx",
  "severity": "low",
  "severity_id": 1,
  "confidence": 100,
  "signature": "connected",
  "usb_class": null,
  "usb_subclass": null,
  "usb_protocol": null,
  "evidence_hash": "sha256:0123456789abcdef",
  "action_hint": "watcher_started"
}
```

---

## Project Structure

| File | Responsibility |
|---|---|
| [src/main.rs](src/main.rs) | `udevadm` process management, event dispatch loop, type-14 restart tracking |
| [src/usb_monitor.rs](src/usb_monitor.rs) | USB event parsing, device fingerprinting, tracker, types 1–8 / 15–16 |
| [src/incident.rs](src/incident.rs) | `IncidentRecord` struct, JSON serializer, shared timestamp/hash utilities |
| [src/fs_monitor.rs](src/fs_monitor.rs) | inotify watcher (types 9–13), ClamAV integration (type 17) |

---

## Notes

- The program is intended to run continuously as a background service or daemon.
- Only one filesystem watcher thread exists at any time, regardless of how many USB devices are connected.
- Anomaly detection (types 3–6) only triggers on `change` events, not during the initial `add`/`bind` enumeration burst, to avoid false positives.
- Zero external Rust crate dependencies — only the standard library and raw Linux syscalls (`inotify`, `read`, `close`).
- ClamAV signatures should be kept up to date with `freshclam`.
