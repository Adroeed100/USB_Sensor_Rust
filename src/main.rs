use std::io::{self, BufRead, BufReader};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

mod incident;
mod fs_monitor;
mod usb_monitor;

use incident::{
    build_event_id, build_evidence_hash, current_timestamp_ms, current_timestamp_rfc3339,
    incident_ecu_id, incident_sensor_id, record_incident, severity_id_for, IncidentRecord,
};
use usb_monitor::{process_udev_event, DeviceTracker, UdevEvent};

fn main() {
    if let Err(err) = run_sensor() {
        eprintln!("sensor exited with error: {err}");
    }
}

fn run_sensor() -> io::Result<()> {
    // Type 14 – udevadm Monitor Crash/Restart:
    // Emit an incident when udevadm exits/fails ≥3 times within 300 seconds.
    let mut restart_times: Vec<u128> = Vec::new();

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
                    let mut reader  = BufReader::new(stdout);
                    let mut tracker = DeviceTracker::default();
                    let mut event   = UdevEvent::default();
                    let mut line    = String::new();

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

                        if usb_monitor::is_udev_header(trimmed) {
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
                eprintln!(
                    "udevadm monitor stopped with status {status}; restarting in 2 seconds"
                );

                // Record this restart and check the type-14 threshold.
                record_restart(&mut restart_times, &format!("udevadm exited: {status}"));
            }

            Err(err) => {
                eprintln!("failed to start udevadm monitor: {err}; retrying in 5 seconds");
                record_restart(&mut restart_times, &format!("udevadm launch failed: {err}"));
                thread::sleep(Duration::from_secs(3)); // extra wait on launch failure
            }
        }

        thread::sleep(Duration::from_secs(2));
    }
}

/// Record a udevadm restart timestamp and emit a type-14 incident if the
/// ≥3-in-300-seconds threshold is crossed.
fn record_restart(restart_times: &mut Vec<u128>, reason: &str) {
    let now = current_timestamp_ms();
    restart_times.push(now);

    // Keep only events within the 300-second window.
    restart_times.retain(|&ts| now.saturating_sub(ts) <= 300_000);

    if restart_times.len() >= 3 {
        let count    = restart_times.len();
        let signature = format!(
            "{count} udevadm restarts within 300 seconds — last: {reason}"
        );
        let incident  = IncidentRecord {
            event_id:         build_event_id("UDEVADM_CRASH", reason, now),
            incident_type_id: 14,
            sensor_id:        incident_sensor_id(),
            timestamp:        current_timestamp_rfc3339(),
            ecu_id:           incident_ecu_id(),
            bus_type:         "USB".to_owned(),
            source:           "udevadm".to_owned(),
            can_id:           "n/a".to_owned(),
            direction:        "rx".to_owned(),
            severity:         "medium".to_owned(),
            severity_id:      severity_id_for("medium"),
            confidence:       88,
            signature:        signature.clone(),
            usb_class:        None,
            usb_subclass:     None,
            usb_protocol:     None,
            evidence_hash:    build_evidence_hash("udevadm", reason, &count.to_string()),
            action_hint:      "investigate_device_instability".to_owned(),
        };
        record_incident(&incident);

        // Clear so the next burst of ≥3 restarts fires again rather than
        // emitting on every subsequent restart.
        restart_times.clear();
    }
}
