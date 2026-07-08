use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::fs_monitor;
use crate::incident::{
    build_evidence_hash, build_event_id, current_timestamp_rfc3339, incident_ecu_id,
    incident_sensor_id, record_incident, IncidentRecord,
};

#[derive(Debug, Default)]
pub(crate) struct UdevEvent {
    pub(crate) header: Option<String>,
    pub(crate) properties: HashMap<String, String>,
}

impl UdevEvent {
    pub(crate) fn has_data(&self) -> bool {
        self.header.is_some() || !self.properties.is_empty()
    }

    pub(crate) fn action(&self) -> String {
        self.properties
            .get("ACTION")
            .cloned()
            .or_else(|| self.header.as_deref().and_then(parse_action_from_header))
            .unwrap_or_else(|| "change".to_owned())
    }

    pub(crate) fn devpath(&self) -> Option<&str> {
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
pub(crate) struct DeviceTracker {
    known_devices: HashMap<String, DeviceSnapshot>,
    /// Tracks the last lifecycle action we emitted ("connected" or "disconnected")
    /// so we only emit one JSON per physical plug/unplug.
    last_lifecycle_action: Option<String>,
    /// Devpaths we've already logged in the current action burst.
    seen_devpaths: std::collections::HashSet<String>,
}

pub(crate) fn process_udev_event(event: &UdevEvent, tracker: &mut DeviceTracker) {
    let action = event.action();

    // Determine the lifecycle label for deduplication.
    let lifecycle_label = if matches!(action.as_str(), "add" | "bind") {
        Some("connected")
    } else if matches!(action.as_str(), "remove" | "detach" | "unbind") {
        Some("disconnected")
    } else {
        // A "change" event resets the dedup state so the next
        // plug/unplug is reported again.
        tracker.last_lifecycle_action = None;
        tracker.seen_devpaths.clear();
        None
    };

    if let Some(label) = lifecycle_label {
        let already_emitted = tracker
            .last_lifecycle_action
            .as_deref()
            == Some(label);

        if !already_emitted {
            tracker.last_lifecycle_action = Some(label.to_owned());
            tracker.seen_devpaths.clear();

            if label == "connected" {
                eprintln!("usb detected: starting filesystem watcher");
                if fs_monitor::start_fs_watch_thread() {
                    log_usb_lifecycle_event(event, "connected", "low", "watcher_started");
                }
            } else {
                eprintln!("usb removed: stopping filesystem watcher");
                if fs_monitor::stop_fs_watch_thread() {
                    log_usb_lifecycle_event(event, "disconnected", "low", "watcher_stopped");
                }
            }
        }
    }

    let devpath = match event.devpath() {
        Some(path) => path.to_owned(),
        None => return,
    };

    let snapshot = capture_device_snapshot(event, &action, &devpath);

    // Only log the first event per devpath in the current burst.
    if tracker.seen_devpaths.insert(devpath.clone()) {
        log_usb_event(&snapshot);
    }

    if matches!(action.as_str(), "remove" | "detach" | "unbind") {
        tracker.known_devices.remove(&snapshot.key);
        return;
    }

    // Only run anomaly detection on "change" events.  During add/bind
    // bursts the sub-device attributes naturally differ (different
    // devpath, class, etc.) and would produce false-positive anomaly
    // JSON.  Real anomalies happen when an already-known device sends
    // a "change" with unexpected attribute values.
    if !matches!(action.as_str(), "add" | "bind") {
        if let Some(previous) = tracker
            .known_devices
            .get(&snapshot.key)
        {
            let previous = previous.clone();
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

    // Always update the tracker with the latest snapshot.
    tracker.known_devices.insert(snapshot.key.clone(), snapshot);
}

fn log_usb_lifecycle_event(event: &UdevEvent, signature: &str, severity: &str, action_hint: &str) {
    let devpath = event.devpath().unwrap_or("unknown");
    let incident = IncidentRecord {
        event_id: build_event_id(
            "USB_LIFECYCLE",
            devpath,
            current_timestamp_ms(),
        ),
        sensor_id: incident_sensor_id(),
        timestamp: current_timestamp_rfc3339(),
        ecu_id: incident_ecu_id(),
        bus_type: "USB".to_owned(),
        source: devpath.to_owned(),
        can_id: "n/a".to_owned(),
        direction: "rx".to_owned(),
        severity: severity.to_owned(),
        confidence: 100,
        signature: signature.to_owned(),
        usb_class: None,
        usb_subclass: None,
        usb_protocol: None,
        evidence_hash: build_evidence_hash(devpath, signature, action_hint),
        action_hint: action_hint.to_owned(),
    };

    record_incident(&incident);
}

pub(crate) fn is_udev_header(line: &str) -> bool {
    line.starts_with("UDEV") || line.starts_with("KERNEL")
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
    eprintln!(
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
    let incident = IncidentRecord {
        event_id: build_event_id("USB_ANOMALY", &snapshot.key, snapshot.timestamp_ms),
        sensor_id: incident_sensor_id(),
        timestamp: current_timestamp_rfc3339(),
        ecu_id: incident_ecu_id(),
        bus_type: "USB".to_owned(),
        source: snapshot.devpath.clone(),
        can_id: "n/a".to_owned(),
        direction: "rx".to_owned(),
        severity: "high".to_owned(),
        confidence: 92,
        signature: reason.to_owned(),
        usb_class: snapshot.device_class.clone(),
        usb_subclass: snapshot.device_subclass.clone(),
        usb_protocol: snapshot.device_protocol.clone(),
        evidence_hash: build_evidence_hash(&snapshot.key, reason, &snapshot.devpath),
        action_hint: "log_and_alert".to_owned(),
    };

    record_incident(&incident);
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

fn current_timestamp_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}