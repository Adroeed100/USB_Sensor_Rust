use std::io::{self, BufRead, BufReader};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

mod incident;
mod fs_monitor;
mod usb_monitor;

use usb_monitor::{process_udev_event, DeviceTracker, UdevEvent};

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
                eprintln!("udevadm monitor stopped with status {status}; restarting in 2 seconds");
            }
            Err(err) => {
                eprintln!("failed to start udevadm monitor: {err}; retrying in 5 seconds");
            }
        }

        thread::sleep(Duration::from_secs(2));
    }
}

