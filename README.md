# USB Sensor

USB Sensor is a small Rust utility that monitors USB activity on Linux and starts a filesystem watcher when a USB device is connected. The watcher stops when the device is removed and can be started again on the next connection.

## Features

- Continuously runs `udevadm monitor` for USB events
- Starts an `inotify` watcher on USB connect
- Stops the watcher on USB disconnect
- Tracks USB device attributes such as vendor ID, product ID, serial number, and device class
- Supports watching either a directory or a single file

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

## Configuration

Set `FS_MONITOR_TARGET` to control what the filesystem watcher monitors.

```bash
FS_MONITOR_TARGET=/path/to/watch cargo +stable run
```

If `FS_MONITOR_TARGET` is not set, the program uses:

```text
~/Projects/rust/fs_monitor
```

You can override the default incident metadata with `INCIDENT_SENSOR_ID` and `INCIDENT_ECU_ID`.

You can point it at:

- a directory, to watch that directory directly
- a file, to watch the file's parent directory and filter events for that file

## How it works

1. The program starts and launches `udevadm monitor`.
2. It reads USB events continuously.
3. When a USB `add` or `bind` event is seen, the filesystem watcher starts.
4. When a USB `remove` or `detach` event is seen, the watcher stops.
5. If the same device changes class, subclass, protocol, or serial number, the program logs an anomaly.

## Output

USB connect and disconnect events are printed as JSON. Example:

```text
{
	"event_id": "USB_ANOMALY_...",
	"sensor_id": "sensor-01",
	"timestamp": "2026-06-30T12:58:00Z",
	"ecu_id": "unknown_ecu",
	"bus_type": "USB",
	"source": "/dev/...",
	"can_id": "n/a",
	"direction": "rx",
	"severity": "high",
	"confidence": 92,
	"signature": "...",
	"evidence_hash": "sha256:...",
	"action_hint": "log_and_alert"
}
```

Filesystem events are reported immediately as plain text while the watcher is active, showing the filename, action, and directory.

## Project Structure

- [src/main.rs](src/main.rs) contains the `udevadm` pump and event dispatch loop
- [src/usb_monitor.rs](src/usb_monitor.rs) contains USB event parsing, device tracking, and anomaly detection
- [src/incident.rs](src/incident.rs) contains incident serialization and append-only JSON logging
- [src/fs_monitor.rs](src/fs_monitor.rs) contains the filesystem watcher implementation

## Notes

- The program is intended to run continuously.
- `udevadm monitor` stays active for the lifetime of the process.
- The filesystem watcher is managed as a USB-driven lifecycle: connect starts it, disconnect stops it.
