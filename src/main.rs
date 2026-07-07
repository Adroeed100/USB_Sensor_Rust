use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod fs_monitor;

fn main() {
    if let Err(err) = run_sensor() {
        eprintln!("sensor exited with error: {err}");
    }
}

fn run_sensor() -> io::Result<()> {
    loop {
        match Command::new("udevadm")
            .args([
                "monitor",
                "--kernel",
                "--udev",
                "--property",
                "--subsystem-match=usb",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
        {
            Ok(mut child) => {
                if let Some(stdout) = child.stdout.take() {
                    let mut reader = BufReader::new(stdout);
                    let mut tracker = DeviceTracker::default();
                    let mut event = UdevEvent::default();
                    let mut line = String::new();

                    loop {
                        line.clear();
                        let read = reader.read_line(&mut line)?;
                        if read == 0 {
                            break;
                        }

                        let trimmed = line.trim_end();
                        if trimmed.is_empty() {
                            if event.has_data() {
                                process_udev_event(&event, &mut tracker);
                                event = UdevEvent::default();
                            }
                            continue;
                        }

                        if is_udev_header(trimmed) {
                            if event.has_data() {
                                process_udev_event(&event, &mut tracker);
                                event = UdevEvent::default();
                            }
                            event.header = Some(trimmed.to_owned());
                            continue;
                        }

                        if let Some((key, value)) = trimmed.split_once('=') {
                            event
                                .properties
                                .insert(key.trim().to_owned(), value.trim().to_owned());
                        }
                    }

                    if event.has_data() {
                        process_udev_event(&event, &mut tracker);
                    }
                }

                let status = child.wait()?;
                eprintln!("udevadm monitor stopped with status {status}; restarting in 2 seconds");
            }
            Err(err) => {
                eprintln!("failed to start udevadm monitor: {err}; retrying in 5 seconds");
            }
        }

        thread::sleep(Duration::from_secs(2));
    }
}

#[derive(Debug, Default)]
struct UdevEvent {
    header: Option<String>,
    properties: HashMap<String, String>,
}

impl UdevEvent {
    fn has_data(&self) -> bool {
        self.header.is_some() || !self.properties.is_empty()
    }

    fn action(&self) -> String {
        self.properties
            .get("ACTION")
            .cloned()
            .or_else(|| self.header.as_deref().and_then(parse_action_from_header))
            .unwrap_or_else(|| "change".to_owned())
    }

    fn devpath(&self) -> Option<&str> {
        self.properties.get("DEVPATH").map(String::as_str)
    }
}

#[derive(Debug, Clone)]
struct DeviceSnapshot {
    key: String,
    timestamp_ms: u128,
    action: String,
    devpath: String,
    bus_topology: Option<String>,
    vendor_id: Option<String>,
    product_id: Option<String>,
    serial: Option<String>,
    device_class: Option<String>,
    device_subclass: Option<String>,
    device_protocol: Option<String>,
    manufacturer: Option<String>,
    product: Option<String>,
    port_id: Option<String>,
}

#[derive(Debug, Default)]
struct DeviceTracker {
    known_devices: HashMap<String, DeviceSnapshot>,
}

fn process_udev_event(event: &UdevEvent, tracker: &mut DeviceTracker) {
    let action = event.action();

    if matches!(action.as_str(), "add" | "bind") {
        eprintln!("usb detected: starting filesystem watcher");
        fs_monitor::start_fs_watch_thread();
    }

    if matches!(action.as_str(), "remove" | "detach" | "unbind") {
        eprintln!("usb removed: stopping filesystem watcher");
        fs_monitor::stop_fs_watch_thread();
    }

    let devpath = match event.devpath() {
        Some(path) => path.to_owned(),
        None => return,
    };

    let snapshot = capture_device_snapshot(event, &action, &devpath);
    log_usb_event(&snapshot);

    if matches!(action.as_str(), "remove" | "detach" | "unbind") {
        tracker.known_devices.remove(&snapshot.key);
        return;
    }

    if let Some(previous) = tracker
        .known_devices
        .insert(snapshot.key.clone(), snapshot.clone())
    {
        let mut reasons = Vec::new();

        if previous.port_id != snapshot.port_id {
            reasons.push(format!(
                "port changed from {:?} to {:?}",
                previous.port_id, snapshot.port_id
            ));
        }

        if previous.bus_topology != snapshot.bus_topology {
            reasons.push(format!(
                "bus topology changed from {:?} to {:?}",
                previous.bus_topology, snapshot.bus_topology
            ));
        }

        if previous.devpath != snapshot.devpath {
            reasons.push(format!(
                "devpath changed from {:?} to {:?}",
                previous.devpath, snapshot.devpath
            ));
        }

        if previous.device_class != snapshot.device_class {
            reasons.push(format!(
                "device class changed from {:?} to {:?}",
                previous.device_class, snapshot.device_class
            ));
        }

        if previous.device_subclass != snapshot.device_subclass {
            reasons.push(format!(
                "device subclass changed from {:?} to {:?}",
                previous.device_subclass, snapshot.device_subclass
            ));
        }

        if previous.device_protocol != snapshot.device_protocol {
            reasons.push(format!(
                "device protocol changed from {:?} to {:?}",
                previous.device_protocol, snapshot.device_protocol
            ));
        }

        if previous.serial != snapshot.serial {
            reasons.push(format!(
                "serial changed from {:?} to {:?}",
                previous.serial, snapshot.serial
            ));
        }

        if !reasons.is_empty() {
            log_anomaly(&snapshot, &reasons.join("; "));
        }
    }
}

fn capture_device_snapshot(event: &UdevEvent, action: &str, devpath: &str) -> DeviceSnapshot {
    let sysfs_path = sysfs_path_from_devpath(devpath);

    let vendor_id = read_attr_upwards(&sysfs_path, "idVendor");
    let product_id = read_attr_upwards(&sysfs_path, "idProduct");
    let serial = read_attr_upwards(&sysfs_path, "serial");
    let device_class = read_attr_upwards(&sysfs_path, "bDeviceClass");
    let device_subclass = read_attr_upwards(&sysfs_path, "bDeviceSubClass");
    let device_protocol = read_attr_upwards(&sysfs_path, "bDeviceProtocol");
    let manufacturer = read_attr_upwards(&sysfs_path, "manufacturer");
    let product = read_attr_upwards(&sysfs_path, "product");
    let busnum = read_attr_upwards(&sysfs_path, "busnum");
    let devnum = read_attr_upwards(&sysfs_path, "devnum");
    let port_id = event
        .properties
        .get("ID_PATH")
        .cloned()
        .or_else(|| event.properties.get("ID_PATH_TAG").cloned());

    let bus_topology = match (busnum.clone(), devnum.clone()) {
        (Some(bus), Some(dev)) => Some(format!("bus {bus} dev {dev}")),
        (Some(bus), None) => Some(format!("bus {bus}")),
        (None, Some(dev)) => Some(format!("dev {dev}")),
        (None, None) => None,
    };

    let key = stable_device_key(
        devpath,
        vendor_id.as_deref(),
        product_id.as_deref(),
        serial.as_deref(),
    );

    DeviceSnapshot {
        key,
        timestamp_ms: current_timestamp_ms(),
        action: action.to_owned(),
        devpath: devpath.to_owned(),
        bus_topology,
        vendor_id,
        product_id,
        serial,
        device_class,
        device_subclass,
        device_protocol,
        manufacturer,
        product,
        port_id,
    }
}

fn stable_device_key(
    devpath: &str,
    vendor_id: Option<&str>,
    product_id: Option<&str>,
    serial: Option<&str>,
) -> String {
    if let Some(serial) = serial {
        if !serial.is_empty() {
            return format!("serial:{serial}");
        }
    }

    if let (Some(vendor), Some(product)) = (vendor_id, product_id) {
        return format!("vidpid:{vendor}:{product}:{devpath}");
    }

    format!("devpath:{devpath}")
}

fn log_usb_event(snapshot: &DeviceSnapshot) {
    println!(
        "[{}] usb {} key={} devpath={} topology={} vid={} pid={} serial={} class={} subclass={} protocol={} manufacturer={} product={} port={}",
        snapshot.timestamp_ms,
        snapshot.action,
        snapshot.key,
        snapshot.devpath,
        snapshot.bus_topology.as_deref().unwrap_or("unknown"),
        snapshot.vendor_id.as_deref().unwrap_or("unknown"),
        snapshot.product_id.as_deref().unwrap_or("unknown"),
        snapshot.serial.as_deref().unwrap_or("unknown"),
        snapshot.device_class.as_deref().unwrap_or("unknown"),
        snapshot.device_subclass.as_deref().unwrap_or("unknown"),
        snapshot.device_protocol.as_deref().unwrap_or("unknown"),
        snapshot.manufacturer.as_deref().unwrap_or("unknown"),
        snapshot.product.as_deref().unwrap_or("unknown"),
        snapshot.port_id.as_deref().unwrap_or("unknown"),
    );
}

fn log_anomaly(snapshot: &DeviceSnapshot, reason: &str) {
    eprintln!(
        "[{}] usb anomaly detected key={} devpath={} reason={}",
        snapshot.timestamp_ms, snapshot.key, snapshot.devpath, reason
    );
}

fn read_attr_upwards(start: &Path, attr_name: &str) -> Option<String> {
    let mut current = Some(start);

    while let Some(path) = current {
        let candidate = path.join(attr_name);
        if let Ok(contents) = fs::read_to_string(&candidate) {
            let value = contents.trim().to_owned();
            if !value.is_empty() {
                return Some(value);
            }
        }

        current = path.parent();
    }

    None
}

fn sysfs_path_from_devpath(devpath: &str) -> PathBuf {
    PathBuf::from("/sys").join(devpath.trim_start_matches('/'))
}

fn parse_action_from_header(header: &str) -> Option<String> {
    for candidate in ["add", "remove", "change", "bind", "unbind"] {
        if header.contains(candidate) {
            return Some(candidate.to_owned());
        }
    }

    None
}

fn is_udev_header(line: &str) -> bool {
    line.starts_with("UDEV") || line.starts_with("KERNEL")
}

fn current_timestamp_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
