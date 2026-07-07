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

USB events are printed to standard output in a single-line format. Examples:

```text
[1234567890] usb add key=... devpath=... vid=... pid=... serial=...
[1234567890] usb anomaly detected key=... devpath=... reason=...
```

Filesystem events are also printed while the watcher is active:

```text
[1234567890] fs watch created path=/path/to/watch/example.txt
```

## Project Structure

- [src/main.rs](src/main.rs) contains the USB event loop and device tracking logic
- [src/fs_monitor.rs](src/fs_monitor.rs) contains the filesystem watcher implementation

## Notes

- The program is intended to run continuously.
- `udevadm monitor` stays active for the lifetime of the process.
- The filesystem watcher is managed as a USB-driven lifecycle: connect starts it, disconnect stops it.
