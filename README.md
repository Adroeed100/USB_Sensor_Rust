# USB Sensor

USB Sensor is a lightweight, zero-dependency Rust utility that monitors USB activity on Linux in real time. It detects USB device connections and disconnections, tracks device attributes, watches the filesystem for changes while a device is connected, and reports security-relevant incidents as structured JSON.

## What the Sensor Can Do

### 1. Real-Time USB Device Monitoring
- Listens to the Linux kernel's `udevadm monitor` for USB subsystem events (`add`, `bind`, `remove`, `unbind`, `change`).
- Automatically restarts the monitor if `udevadm` exits unexpectedly.

### 2. USB Device Fingerprinting
For every USB event, the sensor captures a full device snapshot by reading sysfs attributes:
- **Vendor ID** (`idVendor`) and **Product ID** (`idProduct`)
- **Serial number**
- **Device class**, **subclass**, and **protocol** (e.g., mass storage, HID, hub)
- **Manufacturer** and **product** strings
- **Bus topology** (`busnum` / `devnum`)
- **Port path** (`ID_PATH` / `ID_PATH_TAG`)

### 3. Device Anomaly Detection
The sensor tracks known devices and detects suspicious attribute changes between events:
- Port or bus topology changes (device moved to a different port)
- Device class, subclass, or protocol changes (potential USB spoofing)
- Serial number changes
- Devpath changes

When an anomaly is detected, a high-severity incident JSON is emitted with details about what changed.

### 4. Filesystem Monitoring (inotify)
When a USB device is connected, the sensor automatically starts an `inotify`-based filesystem watcher:
- Watches a configurable target directory or file
- Detects file **creation**, **modification**, **deletion**, **moves**, **metadata changes**, and **uploads** (close-after-write)
- Only one watcher thread runs at a time, regardless of how many USB devices are connected
- The watcher stops automatically when the USB device is removed

### 5. Structured Incident Reporting
The sensor emits structured JSON incident records to **stdout** for:
- **USB lifecycle events** — one JSON per physical connect/disconnect (deduplicated across sub-device events)
- **USB anomalies** — when a known device's attributes change unexpectedly

Each incident includes:
| Field            | Description                                       |
|------------------|---------------------------------------------------|
| `event_id`       | Unique identifier with timestamp and hash          |
| `sensor_id`      | Configurable sensor identifier                     |
| `timestamp`      | RFC 3339 UTC timestamp                             |
| `ecu_id`         | ECU identifier for automotive context              |
| `bus_type`       | Always `"USB"`                                     |
| `source`         | Device path (e.g., `/devices/pci0000:00/...`)      |
| `severity`       | `"low"` for lifecycle, `"high"` for anomalies      |
| `confidence`     | Confidence score (0–100)                           |
| `signature`      | Human-readable description of the event            |
| `usb_class`      | USB device class (when available)                  |
| `usb_subclass`   | USB device subclass (when available)               |
| `usb_protocol`   | USB device protocol (when available)               |
| `evidence_hash`  | Hash of the evidence data                          |
| `action_hint`    | Suggested action (`watcher_started`, `log_and_alert`, etc.) |

### 6. Event Deduplication
A single physical USB plug/unplug triggers many kernel sub-device events. The sensor deduplicates these so that:
- Only **one JSON** is emitted per connect
- Only **one JSON** is emitted per disconnect
- Anomaly detection is skipped during the initial `add`/`bind` burst to avoid false positives from normal sub-device enumeration

### 7. Diagnostic Logging
All diagnostic output (USB event details, filesystem watcher status, inotify events) goes to **stderr**, keeping **stdout** clean for JSON-only incident output. This makes it easy to pipe incidents to a log collector or SIEM.

## Requirements

- Linux
- `udevadm` available on `PATH`
- Rust toolchain

## Build

```bash
cargo +stable build
```

## Run

From the project root:

```bash
cargo +stable run
```

To pipe only incident JSON to a file while seeing diagnostics in the terminal:

```bash
cargo +stable run > incidents.json
```

## Configuration

| Environment Variable   | Description                              | Default               |
|------------------------|------------------------------------------|-----------------------|
| `FS_MONITOR_TARGET`    | Directory or file to watch with inotify  | `~/Projects/rust/sensor` |
| `INCIDENT_SENSOR_ID`   | Sensor ID in incident records            | `sensor-01`           |
| `INCIDENT_ECU_ID`      | ECU ID in incident records               | `unknown_ecu`         |

```bash
FS_MONITOR_TARGET=/media/usb0 INCIDENT_SENSOR_ID=sensor-42 cargo +stable run
```

You can point `FS_MONITOR_TARGET` at:
- A **directory** — watches that directory directly
- A **file** — watches the file's parent directory and filters events for that file

## How It Works

1. The program starts and launches `udevadm monitor --kernel --udev --property --subsystem-match=usb`.
2. It reads USB events continuously, parsing headers and key=value properties.
3. When a USB `add` or `bind` event is seen (first one only), the filesystem watcher starts and a `connected` incident JSON is emitted.
4. When a USB `remove`, `detach`, or `unbind` event is seen (first one only), the watcher stops and a `disconnected` incident JSON is emitted.
5. If a known device sends a `change` event with altered attributes, an anomaly incident JSON is emitted.
6. If `udevadm` exits, the sensor waits 2 seconds and restarts it automatically.

## Output Example

**Incident JSON** (stdout):

```json
{
  "event_id": "USB_LIFECYCLE_1751968680000_a1b2c3d4e5f67890",
  "sensor_id": "sensor-01",
  "timestamp": "2026-07-08T07:18:00Z",
  "ecu_id": "unknown_ecu",
  "bus_type": "USB",
  "source": "/devices/pci0000:00/0000:00:14.0/usb1/1-2",
  "can_id": "n/a",
  "direction": "rx",
  "severity": "low",
  "confidence": 100,
  "signature": "connected",
  "usb_class": null,
  "usb_subclass": null,
  "usb_protocol": null,
  "evidence_hash": "sha256:0123456789abcdef",
  "action_hint": "watcher_started"
}
```

**Diagnostic output** (stderr):

```text
usb detected: starting filesystem watcher
starting filesystem watcher
starting inotify watch on /home/user/Projects/rust/sensor
filesystem watcher is running
[1751968680000] usb add key=serial:ABC123 devpath=/devices/... topology=bus 1 dev 5 vid=0781 pid=5567 ...
fs watch action=created file=test.txt dir=/home/user/Projects/rust/sensor
```

## Project Structure

- [src/main.rs](src/main.rs) — `udevadm` process management and event dispatch loop
- [src/usb_monitor.rs](src/usb_monitor.rs) — USB event parsing, device fingerprinting, tracking, anomaly detection, and deduplication
- [src/incident.rs](src/incident.rs) — incident record structure and JSON serialization
- [src/fs_monitor.rs](src/fs_monitor.rs) — inotify-based filesystem watcher (raw syscalls, no external dependencies)

## Notes

- The program is intended to run continuously as a background service.
- `udevadm monitor` stays active for the lifetime of the process.
- The filesystem watcher is managed as a USB-driven lifecycle: connect starts it, disconnect stops it.
- Only one filesystem watcher thread runs at a time, regardless of how many USB devices are connected.
- Zero external crate dependencies — uses only the Rust standard library and raw Linux syscalls.
