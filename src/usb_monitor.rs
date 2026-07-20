use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::fs_monitor;
use crate::incident::{
    build_evidence_hash, build_event_id, current_timestamp_ms, current_timestamp_rfc3339,
    incident_ecu_id, incident_sensor_id, record_incident, severity_id_for, IncidentRecord,
};

// ── UdevEvent ──────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub(crate) struct UdevEvent {
    pub(crate) header:     Option<String>,
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

// ── DeviceSnapshot ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DeviceSnapshot {
    key:             String,
    timestamp_ms:    u128,
    action:          String,
    devpath:         String,
    bus_topology:    Option<String>,
    vendor_id:       Option<String>,
    product_id:      Option<String>,
    serial:          Option<String>,
    device_class:    Option<String>,
    device_subclass: Option<String>,
    device_protocol: Option<String>,
    manufacturer:    Option<String>,
    product:         Option<String>,
    port_id:         Option<String>,
}

// ── DeviceTracker ──────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub(crate) struct DeviceTracker {
    known_devices: HashMap<String, DeviceSnapshot>,

    /// Tracks the last lifecycle action emitted ("connected"/"disconnected")
    /// so we emit only one JSON per physical plug/unplug.
    last_lifecycle_action: Option<String>,

    /// Devpaths already logged in the current action burst.
    seen_devpaths: std::collections::HashSet<String>,

    /// Type 7 – Rapid Connect/Disconnect (Flapping):
    /// device-key → timestamps of recent lifecycle events.
    connect_history: HashMap<String, Vec<u128>>,

    /// Type 16 – Anomalous Enumeration Burst:
    /// number of add/bind sub-device events in the current plug burst.
    enum_burst_count:    u32,
    /// Timestamp of the first add/bind in the current 10-second window.
    enum_burst_start_ms: Option<u128>,
}

// ── Main entry point ───────────────────────────────────────────────────────────

pub(crate) fn process_udev_event(event: &UdevEvent, tracker: &mut DeviceTracker) {
    let action = event.action();

    // Type 15 – Malformed USB Event / Parse Failure:
    // A header is present but neither the header text nor any property yields
    // a recognisable action, and DEVPATH is also absent.
    if event.header.is_some()
        && event.properties.get("ACTION").is_none()
        && event.header.as_deref().and_then(parse_action_from_header).is_none()
        && event.devpath().is_none()
    {
        log_malformed_event(event);
        return;
    }

    // Determine the lifecycle label (for deduplication and type 7).
    let lifecycle_label = if matches!(action.as_str(), "add" | "bind") {
        Some("connected")
    } else if matches!(action.as_str(), "remove" | "detach" | "unbind") {
        Some("disconnected")
    } else {
        // "change" resets dedup so the next plug/unplug is reported fresh.
        tracker.last_lifecycle_action = None;
        tracker.seen_devpaths.clear();
        tracker.enum_burst_count    = 0;
        tracker.enum_burst_start_ms = None;
        None
    };

    // Type 16 – Anomalous Enumeration Burst:
    // Count every add/bind sub-device event within a 10-second window.
    if matches!(action.as_str(), "add" | "bind") {
        let now = current_timestamp_ms();
        let in_window = tracker
            .enum_burst_start_ms
            .map(|start| now.saturating_sub(start) <= 10_000)
            .unwrap_or(false);

        if in_window {
            tracker.enum_burst_count += 1;
        } else {
            tracker.enum_burst_count    = 1;
            tracker.enum_burst_start_ms = Some(now);
        }

        // Emit exactly once when the threshold is first crossed.
        if tracker.enum_burst_count == 20 {
            log_enum_burst(event, tracker.enum_burst_count);
        }
    }

    // Lifecycle deduplication + types 1, 2, 7, 8.
    if let Some(label) = lifecycle_label {
        let already_emitted = tracker.last_lifecycle_action.as_deref() == Some(label);

        if !already_emitted {
            tracker.last_lifecycle_action = Some(label.to_owned());
            tracker.seen_devpaths.clear();

            // Type 7 – Flapping: record this lifecycle event and check threshold.
            if let Some(device_key) = derive_key_from_event(event) {
                let history = tracker.connect_history.entry(device_key.clone()).or_default();
                let now     = current_timestamp_ms();
                history.push(now);
                history.retain(|&ts| now.saturating_sub(ts) <= 30_000);
                if history.len() >= 5 {
                    log_flapping(event, &device_key, history.len() as u32);
                    history.clear(); // avoid re-firing until the next threshold
                }
            }

            if label == "connected" {
                eprintln!("usb detected: starting filesystem watcher");
                if fs_monitor::start_fs_watch_thread() {
                    // Type 1 – USB Device Connected
                    log_usb_lifecycle_event(event, 1, "connected", "low", "watcher_started");
                }
                // Type 8 – Unauthorized Device Class Connected
                check_unauthorized_class(event);
            } else {
                eprintln!("usb removed: stopping filesystem watcher");
                if fs_monitor::stop_fs_watch_thread() {
                    // Type 2 – USB Device Disconnected
                    log_usb_lifecycle_event(event, 2, "disconnected", "low", "watcher_stopped");
                }
                // Reset enum burst on disconnect.
                tracker.enum_burst_count    = 0;
                tracker.enum_burst_start_ms = None;
            }
        }
    }

    let devpath = match event.devpath() {
        Some(path) => path.to_owned(),
        None       => return,
    };

    let snapshot = capture_device_snapshot(event, &action, &devpath);

    // Diagnostic log: one line per unique devpath in the burst.
    if tracker.seen_devpaths.insert(devpath.clone()) {
        log_usb_event(&snapshot);
    }

    if matches!(action.as_str(), "remove" | "detach" | "unbind") {
        tracker.known_devices.remove(&snapshot.key);
        return;
    }

    // Anomaly detection runs only on "change" events (types 3–6).
    // During add/bind bursts, attribute differences between sub-devices are
    // normal enumeration and would produce false-positive incidents.
    if !matches!(action.as_str(), "add" | "bind") {
        if let Some(previous) = tracker.known_devices.get(&snapshot.key).cloned() {

            // Type 3 – Port/Bus Topology Change
            if previous.port_id != snapshot.port_id
                || previous.bus_topology != snapshot.bus_topology
            {
                let reason = format!(
                    "port/topology changed: port {:?}→{:?}, bus {:?}→{:?}",
                    previous.port_id, snapshot.port_id,
                    previous.bus_topology, snapshot.bus_topology,
                );
                log_typed_anomaly(&snapshot, 3, "high", &reason, "investigate_port_change");
            }

            // Type 4 – Device Class/Subclass/Protocol Change (BadUSB / spoofing)
            if previous.device_class    != snapshot.device_class
                || previous.device_subclass != snapshot.device_subclass
                || previous.device_protocol != snapshot.device_protocol
            {
                let reason = format!(
                    "usb class changed: {:?}/{:?}/{:?} → {:?}/{:?}/{:?}",
                    previous.device_class, previous.device_subclass, previous.device_protocol,
                    snapshot.device_class, snapshot.device_subclass, snapshot.device_protocol,
                );
                log_typed_anomaly(&snapshot, 4, "critical", &reason, "block_and_alert");
            }

            // Type 5 – Serial Number Change
            if previous.serial != snapshot.serial {
                let reason = format!(
                    "serial changed from {:?} to {:?}",
                    previous.serial, snapshot.serial,
                );
                log_typed_anomaly(&snapshot, 5, "critical", &reason, "block_and_alert");
            }

            // Type 6 – Devpath Change
            if previous.devpath != snapshot.devpath {
                let reason = format!(
                    "devpath changed from {:?} to {:?}",
                    previous.devpath, snapshot.devpath,
                );
                log_typed_anomaly(&snapshot, 6, "high", &reason, "investigate_devpath");
            }
        }
    }

    // Always update the tracker with the latest snapshot.
    tracker.known_devices.insert(snapshot.key.clone(), snapshot);
}

// ── Incident emitters ──────────────────────────────────────────────────────────

/// Types 1 and 2 – USB Device Connected / Disconnected.
fn log_usb_lifecycle_event(
    event:            &UdevEvent,
    incident_type_id: u8,
    signature:        &str,
    severity:         &str,
    action_hint:      &str,
) {
    let devpath = event.devpath().unwrap_or("unknown");
    let ts      = current_timestamp_ms();
    let incident = IncidentRecord {
        event_id:         build_event_id("USB_LIFECYCLE", devpath, ts),
        incident_type_id,
        sensor_id:        incident_sensor_id(),
        timestamp:        current_timestamp_rfc3339(),
        ecu_id:           incident_ecu_id(),
        bus_type:         "USB".to_owned(),
        source:           devpath.to_owned(),
        can_id:           "n/a".to_owned(),
        direction:        "rx".to_owned(),
        severity:         severity.to_owned(),
        severity_id:      severity_id_for(severity),
        confidence:       100,
        signature:        signature.to_owned(),
        usb_class:        None,
        usb_subclass:     None,
        usb_protocol:     None,
        evidence_hash:    build_evidence_hash(devpath, signature, action_hint),
        action_hint:      action_hint.to_owned(),
    };
    record_incident(&incident);
}

/// Types 3–6 – separate typed anomaly incidents.
fn log_typed_anomaly(
    snapshot:         &DeviceSnapshot,
    incident_type_id: u8,
    severity:         &str,
    reason:           &str,
    action_hint:      &str,
) {
    let prefix = match incident_type_id {
        3 => "USB_TOPOLOGY_CHANGE",
        4 => "USB_CLASS_CHANGE",
        5 => "USB_SERIAL_CHANGE",
        6 => "USB_DEVPATH_CHANGE",
        _ => "USB_ANOMALY",
    };
    let incident = IncidentRecord {
        event_id:         build_event_id(prefix, &snapshot.key, snapshot.timestamp_ms),
        incident_type_id,
        sensor_id:        incident_sensor_id(),
        timestamp:        current_timestamp_rfc3339(),
        ecu_id:           incident_ecu_id(),
        bus_type:         "USB".to_owned(),
        source:           snapshot.devpath.clone(),
        can_id:           "n/a".to_owned(),
        direction:        "rx".to_owned(),
        severity:         severity.to_owned(),
        severity_id:      severity_id_for(severity),
        confidence:       92,
        signature:        reason.to_owned(),
        usb_class:        snapshot.device_class.clone(),
        usb_subclass:     snapshot.device_subclass.clone(),
        usb_protocol:     snapshot.device_protocol.clone(),
        evidence_hash:    build_evidence_hash(&snapshot.key, reason, &snapshot.devpath),
        action_hint:      action_hint.to_owned(),
    };
    record_incident(&incident);
}

/// Type 7 – Rapid Connect/Disconnect (Flapping).
fn log_flapping(event: &UdevEvent, device_key: &str, count: u32) {
    let devpath = event.devpath().unwrap_or("unknown");
    let ts      = current_timestamp_ms();
    let reason  = format!("{count} connect/disconnect events within 30 seconds");
    let incident = IncidentRecord {
        event_id:         build_event_id("USB_FLAPPING", device_key, ts),
        incident_type_id: 7,
        sensor_id:        incident_sensor_id(),
        timestamp:        current_timestamp_rfc3339(),
        ecu_id:           incident_ecu_id(),
        bus_type:         "USB".to_owned(),
        source:           devpath.to_owned(),
        can_id:           "n/a".to_owned(),
        direction:        "rx".to_owned(),
        severity:         "medium".to_owned(),
        severity_id:      severity_id_for("medium"),
        confidence:       85,
        signature:        reason.clone(),
        usb_class:        None,
        usb_subclass:     None,
        usb_protocol:     None,
        evidence_hash:    build_evidence_hash(device_key, &reason, devpath),
        action_hint:      "investigate_device".to_owned(),
    };
    record_incident(&incident);
}

/// Type 8 – Unauthorized Device Class Connected.
/// Only active when the `ALLOWED_USB_CLASSES` env var is set.
fn check_unauthorized_class(event: &UdevEvent) {
    let allowed_env = std::env::var("ALLOWED_USB_CLASSES").unwrap_or_default();
    if allowed_env.is_empty() {
        return; // allow-list not configured; skip check
    }

    let devpath = match event.devpath() {
        Some(p) => p,
        None    => return,
    };
    let sysfs  = sysfs_path_from_devpath(devpath);
    let device_class = match read_attr_upwards(&sysfs, "bDeviceClass") {
        // class "00" means the class is defined at the interface level; skip.
        Some(c) if !c.is_empty() && c != "00" => c,
        _ => return,
    };

    let allowed: Vec<String> = allowed_env
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .collect();

    if !allowed.contains(&device_class.to_lowercase()) {
        let ts     = current_timestamp_ms();
        let reason = format!(
            "device class {device_class} not in allowed list [{allowed_env}]"
        );
        let incident = IncidentRecord {
            event_id:         build_event_id("USB_UNAUTH_CLASS", devpath, ts),
            incident_type_id: 8,
            sensor_id:        incident_sensor_id(),
            timestamp:        current_timestamp_rfc3339(),
            ecu_id:           incident_ecu_id(),
            bus_type:         "USB".to_owned(),
            source:           devpath.to_owned(),
            can_id:           "n/a".to_owned(),
            direction:        "rx".to_owned(),
            severity:         "high".to_owned(),
            severity_id:      severity_id_for("high"),
            confidence:       95,
            signature:        reason.clone(),
            usb_class:        Some(device_class.clone()),
            usb_subclass:     None,
            usb_protocol:     None,
            evidence_hash:    build_evidence_hash(devpath, &device_class, &allowed_env),
            action_hint:      "block_device".to_owned(),
        };
        record_incident(&incident);
    }
}

/// Type 15 – Malformed USB Event / Parse Failure.
fn log_malformed_event(event: &UdevEvent) {
    let header = event.header.as_deref().unwrap_or("unknown");
    let ts     = current_timestamp_ms();
    let reason = format!(
        "malformed udev event: header={header:?}, no action or devpath resolved"
    );
    let incident = IncidentRecord {
        event_id:         build_event_id("USB_MALFORMED", header, ts),
        incident_type_id: 15,
        sensor_id:        incident_sensor_id(),
        timestamp:        current_timestamp_rfc3339(),
        ecu_id:           incident_ecu_id(),
        bus_type:         "USB".to_owned(),
        source:           header.to_owned(),
        can_id:           "n/a".to_owned(),
        direction:        "rx".to_owned(),
        severity:         "critical".to_owned(),
        severity_id:      severity_id_for("critical"),
        confidence:       70,
        signature:        reason.clone(),
        usb_class:        None,
        usb_subclass:     None,
        usb_protocol:     None,
        evidence_hash:    build_evidence_hash(header, "malformed", "parse_failure"),
        action_hint:      "log_and_alert".to_owned(),
    };
    record_incident(&incident);
}

/// Type 16 – Duplicate/Anomalous Enumeration Burst.
fn log_enum_burst(event: &UdevEvent, count: u32) {
    let devpath = event.devpath().unwrap_or("unknown");
    let ts      = current_timestamp_ms();
    let reason  = format!("{count} add/bind sub-device events within 10 seconds");
    let incident = IncidentRecord {
        event_id:         build_event_id("USB_ENUM_BURST", devpath, ts),
        incident_type_id: 16,
        sensor_id:        incident_sensor_id(),
        timestamp:        current_timestamp_rfc3339(),
        ecu_id:           incident_ecu_id(),
        bus_type:         "USB".to_owned(),
        source:           devpath.to_owned(),
        can_id:           "n/a".to_owned(),
        direction:        "rx".to_owned(),
        severity:         "medium".to_owned(),
        severity_id:      severity_id_for("medium"),
        confidence:       75,
        signature:        reason.clone(),
        usb_class:        None,
        usb_subclass:     None,
        usb_protocol:     None,
        evidence_hash:    build_evidence_hash(devpath, &reason, "enum_burst"),
        action_hint:      "investigate_device".to_owned(),
    };
    record_incident(&incident);
}

// ── Diagnostic log (stderr only) ───────────────────────────────────────────────

fn log_usb_event(snapshot: &DeviceSnapshot) {
    eprintln!(
        "[{}] usb {} key={} devpath={} topology={} vid={} pid={} serial={} \
         class={} subclass={} protocol={} manufacturer={} product={} port={}",
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

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Derive a best-effort device key directly from event properties.
/// Used for flapping detection before a full sysfs snapshot is available.
fn derive_key_from_event(event: &UdevEvent) -> Option<String> {
    let vendor  = event.properties.get("ID_VENDOR_ID").map(String::as_str).unwrap_or("");
    let product = event.properties.get("ID_MODEL_ID").map(String::as_str).unwrap_or("");
    let serial  = event.properties.get("ID_SERIAL_SHORT").map(String::as_str).unwrap_or("");
    let devpath = event.devpath().unwrap_or("");

    if !serial.is_empty() {
        Some(format!("serial:{serial}"))
    } else if !vendor.is_empty() && !product.is_empty() {
        Some(format!("vidpid:{vendor}:{product}"))
    } else if !devpath.is_empty() {
        Some(format!("devpath:{devpath}"))
    } else {
        None
    }
}

pub(crate) fn is_udev_header(line: &str) -> bool {
    if line.starts_with("UDEV - ") || line.starts_with("KERNEL - ") {
        return false;
    }
    line.starts_with("UDEV") || line.starts_with("KERNEL")
}

fn capture_device_snapshot(event: &UdevEvent, action: &str, devpath: &str) -> DeviceSnapshot {
    let sysfs_path = sysfs_path_from_devpath(devpath);

    let vendor_id       = read_attr_upwards(&sysfs_path, "idVendor");
    let product_id      = read_attr_upwards(&sysfs_path, "idProduct");
    let serial          = read_attr_upwards(&sysfs_path, "serial");
    let device_class    = read_attr_upwards(&sysfs_path, "bDeviceClass");
    let device_subclass = read_attr_upwards(&sysfs_path, "bDeviceSubClass");
    let device_protocol = read_attr_upwards(&sysfs_path, "bDeviceProtocol");
    let manufacturer    = read_attr_upwards(&sysfs_path, "manufacturer");
    let product         = read_attr_upwards(&sysfs_path, "product");
    let busnum          = read_attr_upwards(&sysfs_path, "busnum");
    let devnum          = read_attr_upwards(&sysfs_path, "devnum");
    let port_id = event
        .properties
        .get("ID_PATH")
        .cloned()
        .or_else(|| event.properties.get("ID_PATH_TAG").cloned());

    let bus_topology = match (busnum, devnum) {
        (Some(bus), Some(dev)) => Some(format!("bus {bus} dev {dev}")),
        (Some(bus), None)      => Some(format!("bus {bus}")),
        (None,      Some(dev)) => Some(format!("dev {dev}")),
        (None,      None)      => None,
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
    devpath:    &str,
    vendor_id:  Option<&str>,
    product_id: Option<&str>,
    serial:     Option<&str>,
) -> String {
    if let Some(s) = serial {
        if !s.is_empty() {
            return format!("serial:{s}");
        }
    }
    if let (Some(v), Some(p)) = (vendor_id, product_id) {
        return format!("vidpid:{v}:{p}");
    }
    format!("devpath:{devpath}")
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