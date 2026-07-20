use std::env;
use std::ffi::OsString;
use std::io;
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use crate::incident::{
    build_event_id, build_evidence_hash, current_timestamp_ms, current_timestamp_rfc3339,
    incident_ecu_id, incident_sensor_id, record_incident, severity_id_for, IncidentRecord,
};

static FS_WATCH: OnceLock<Mutex<Option<FilesystemWatcher>>> = OnceLock::new();
static CLAMAV_PROCESS: OnceLock<Mutex<Option<std::process::Child>>> = OnceLock::new();

struct FilesystemWatcher {
    stop_requested: std::sync::Arc<AtomicBool>,
    handle: thread::JoinHandle<()>,
}

// ── Public API ─────────────────────────────────────────────────────────────────

pub fn start_fs_watch_thread() -> bool {
    let watcher_slot = FS_WATCH.get_or_init(|| Mutex::new(None));
    let mut watcher  = watcher_slot.lock().expect("filesystem watcher mutex poisoned");

    if watcher.is_some() {
        eprintln!("filesystem watcher is already running");
        return false;
    }

    let target          = resolve_fs_watch_target();
    let clamscan_target = target.clone(); // cloned before it is moved into the watcher thread

    eprintln!("starting filesystem watcher");
    let stop_requested        = std::sync::Arc::new(AtomicBool::new(false));
    let thread_stop_requested = std::sync::Arc::clone(&stop_requested);
    let handle = thread::Builder::new()
        .name("fs-monitor".to_owned())
        .spawn(move || watch_fs_target(target, thread_stop_requested))
        .expect("failed to spawn fs monitor thread");

    *watcher = Some(FilesystemWatcher { stop_requested, handle });

    // Start a one-shot ClamAV scan in the background (results go to stdout on FOUND).
    start_clamscan_thread(clamscan_target);

    true
}

pub fn stop_fs_watch_thread() -> bool {
    let Some(watcher_slot) = FS_WATCH.get() else {
        eprintln!("filesystem watcher is not running");
        return false;
    };

    let watcher = {
        let mut watcher = watcher_slot.lock().expect("filesystem watcher mutex poisoned");
        watcher.take()
    };

    let Some(watcher) = watcher else {
        eprintln!("filesystem watcher is not running");
        return false;
    };

    watcher.stop_requested.store(true, Ordering::SeqCst);
    let _ = watcher.handle.join();
    eprintln!("filesystem watcher stopped");

    // Kill clamscan if running
    if let Some(slot) = CLAMAV_PROCESS.get() {
        if let Ok(mut lock) = slot.lock() {
            if let Some(mut child) = lock.take() {
                let _ = child.kill();
                let _ = child.wait();
                eprintln!("clamscan process killed");
            }
        }
    }

    true
}

// ── ClamAV integration (type 17) ───────────────────────────────────────────────

fn start_clamscan_thread(target: PathBuf) {
    thread::Builder::new()
        .name("clamscan".to_owned())
        .spawn(move || run_clamscan(target))
        .expect("failed to spawn clamscan thread");
}

/// Run `clamscan --no-summary --infected -r <target>`.
/// Only files flagged as FOUND produce a JSON incident on stdout.
/// Everything else goes to stderr.
fn run_clamscan(target: PathBuf) {
    let target_str = target.to_string_lossy().into_owned();
    eprintln!("clamscan: starting scan on {target_str}");

    let mut child = match Command::new("clamscan")
        .args(["--no-summary", "--infected", "-r", &target_str])
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("clamscan: failed to execute: {e}");
            return;
        }
    };

    let stdout = child.stdout.take().expect("failed to capture clamscan stdout");
    
    let slot = CLAMAV_PROCESS.get_or_init(|| Mutex::new(None));
    {
        let mut lock = slot.lock().expect("clamscan mutex poisoned");
        *lock = Some(child);
    }

    use std::io::{BufRead, BufReader};
    let reader = BufReader::new(stdout);
    let mut threats = 0u32;

    for raw_line in reader.lines() {
        let Ok(line_str) = raw_line else { break; };
        let line = line_str.trim();
        if line.is_empty() {
            continue;
        }

        // ClamAV per-file format: "/path/to/file: VirusName FOUND"
        if line.ends_with(" FOUND") {
            threats += 1;

            // Split on the first ": " to separate path from virus info.
            let (file_path, virus_info) = match line.find(": ") {
                Some(pos) => (&line[..pos], &line[pos + 2..]),
                None      => (line, line),
            };

            let ts        = current_timestamp_ms();
            let signature = format!("clamscan_threat_found: {virus_info}");
            let incident  = IncidentRecord {
                event_id:         build_event_id("CLAMSCAN_THREAT", file_path, ts),
                incident_type_id: 17,
                sensor_id:        incident_sensor_id(),
                timestamp:        current_timestamp_rfc3339(),
                ecu_id:           incident_ecu_id(),
                bus_type:         "USB".to_owned(),
                source:           file_path.to_owned(),
                can_id:           "n/a".to_owned(),
                direction:        "rx".to_owned(),
                severity:         "critical".to_owned(),
                severity_id:      severity_id_for("critical"),
                confidence:       99,
                signature:        signature.clone(),
                usb_class:        None,
                usb_subclass:     None,
                usb_protocol:     None,
                evidence_hash:    build_evidence_hash(file_path, virus_info, &target_str),
                action_hint:      "quarantine_and_alert".to_owned(),
            };
            record_incident(&incident);
        } else {
            // Clean / error lines → stderr only.
            eprintln!("clamscan: {line}");
        }
    }

    let mut exit_status = None;
    {
        let mut lock = slot.lock().expect("clamscan mutex poisoned");
        if let Some(mut c) = lock.take() {
            exit_status = c.wait().ok();
        }
    }

    if threats == 0 {
        if let Some(status) = exit_status {
            eprintln!("clamscan: scan complete — no threats found (exit code: {status})");
        } else {
            eprintln!("clamscan: scan complete — no threats found");
        }
    } else {
        eprintln!("clamscan: scan complete — {threats} threat(s) found");
    }
}

// ── Filesystem watch loop ──────────────────────────────────────────────────────

fn resolve_fs_watch_target() -> PathBuf {
    if let Some(path) = env::var_os("FS_MONITOR_TARGET") {
        return expand_tilde(PathBuf::from(path));
    }
    expand_tilde(PathBuf::from("~/Projects/rust/sensor"))
}

fn expand_tilde(path: PathBuf) -> PathBuf {
    let path_string = path.to_string_lossy();
    if !path_string.starts_with("~/") {
        return path;
    }
    let Some(home) = env::var_os("HOME") else {
        return path;
    };
    let mut expanded = PathBuf::from(home);
    expanded.push(path_string.trim_start_matches("~/"));
    expanded
}

fn watch_fs_target(target: PathBuf, stop_requested: std::sync::Arc<AtomicBool>) {
    let watch_root = if target.is_dir() {
        target.clone()
    } else {
        target
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or(target.clone())
    };

    let filter_name = if target.is_dir() {
        None
    } else {
        target.file_name().map(OsString::from)
    };

    eprintln!(
        "starting inotify watch on {}{}",
        watch_root.display(),
        filter_name
            .as_ref()
            .and_then(|n| n.to_str())
            .map(|n| format!(" (filtering for {n})"))
            .unwrap_or_default()
    );

    // Upload-burst tracking for type 13. Declared outside unsafe so it lives
    // across the whole loop and can be passed to safe helper functions.
    let mut upload_times: Vec<u128> = Vec::new();

    unsafe {
        let fd = inotify_init1(IN_NONBLOCK);
        if fd < 0 {
            eprintln!("failed to initialize inotify");
            return;
        }

        let watch_path = match std::ffi::CString::new(watch_root.as_os_str().as_bytes()) {
            Ok(v)  => v,
            Err(_) => {
                eprintln!("watch path contains an interior null byte");
                let _ = close(fd);
                return;
            }
        };

        let mask = IN_CREATE
            | IN_MODIFY
            | IN_DELETE
            | IN_MOVED_FROM
            | IN_MOVED_TO
            | IN_ATTRIB
            | IN_CLOSE_WRITE
            | IN_DELETE_SELF
            | IN_MOVE_SELF;

        if inotify_add_watch(fd, watch_path.as_ptr(), mask) < 0 {
            eprintln!("failed to add inotify watch on {}", watch_root.display());
            let _ = close(fd);
            return;
        }

        eprintln!("filesystem watcher is running");

        let mut buffer = [0u8; 8192];
        loop {
            let bytes_read = read(fd, buffer.as_mut_ptr() as *mut c_void, buffer.len());
            if bytes_read < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::WouldBlock {
                    if stop_requested.load(Ordering::SeqCst) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                eprintln!("inotify read stopped for {}: {error}", watch_root.display());
                break;
            }

            if bytes_read == 0 {
                if stop_requested.load(Ordering::SeqCst) {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
                continue;
            }

            let mut offset    = 0usize;
            let bytes_read    = bytes_read as usize;
            while offset + std::mem::size_of::<InotifyEvent>() <= bytes_read {
                let raw_event   = &*(buffer.as_ptr().add(offset) as *const InotifyEvent);
                let name_offset = offset + std::mem::size_of::<InotifyEvent>();
                let name_len    = raw_event.len as usize;
                let name_end    = name_offset.saturating_add(name_len).min(bytes_read);
                let name_bytes  = &buffer[name_offset..name_end];
                let name        = decode_inotify_name(name_bytes);

                if should_report_event(filter_name.as_ref(), name.as_deref()) {
                    // safe function called from within an unsafe block — fine in Rust
                    report_inotify_event(
                        raw_event.mask,
                        &watch_root,
                        name.as_deref(),
                        &mut upload_times,
                    );
                }

                offset = name_offset + name_len;
            }
        }

        let _ = close(fd);
    }
}

fn should_report_event(filter_name: Option<&OsString>, event_name: Option<&str>) -> bool {
    match (filter_name, event_name) {
        (Some(expected), Some(actual)) => expected.to_str() == Some(actual),
        (Some(_), None)                => false,
        (None, _)                      => true,
    }
}

/// Emit typed incident JSON for each inotify event (types 9–13).
/// Also writes a short diagnostic line to stderr.
fn report_inotify_event(
    mask:         u32,
    watch_root:   &Path,
    file_name:    Option<&str>,
    upload_times: &mut Vec<u128>,
) {
    let file_label = file_name
        .map(|n| n.to_owned())
        .unwrap_or_else(|| {
            watch_root
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.to_owned())
                .unwrap_or_else(|| watch_root.display().to_string())
        });

    let source = file_name
        .map(|n| watch_root.join(n).to_string_lossy().into_owned())
        .unwrap_or_else(|| watch_root.to_string_lossy().into_owned());

    // ── Type 13 – Mass File Upload / Possible Exfiltration ─────────────────
    // Track every close-after-write event. Emit at threshold (10) and at each
    // subsequent multiple of 10 to keep reporting an ongoing burst.
    if mask & IN_CLOSE_WRITE != 0 {
        let now = current_timestamp_ms();
        upload_times.push(now);
        // Prune events older than 60 seconds.
        upload_times.retain(|&ts| now.saturating_sub(ts) <= 60_000);

        if upload_times.len() >= 10 && upload_times.len() % 10 == 0 {
            let count  = upload_times.len();
            let reason = format!(
                "{count} file uploads (close-after-write) in 60 seconds — possible exfiltration"
            );
            emit_fs_incident(
                13, "critical",
                "mass_file_upload_detected",
                &reason,
                &source,
                "quarantine_and_alert",
            );
            eprintln!("fs watch type=13 {reason} dir={}", watch_root.display());
        }
    }

    // ── Primary event type selection (highest-severity bit wins) ───────────
    let primary = if mask & (IN_DELETE | IN_DELETE_SELF) != 0 {
        Some((11u8, "high",   "file_deleted",       "investigate_deletion"))
    } else if mask & (IN_MOVED_FROM | IN_MOVED_TO | IN_MOVE_SELF) != 0 {
        Some((12u8, "medium", "file_moved",          "log_event"))
    } else if mask & IN_CREATE != 0 {
        Some((9u8,  "low",    "file_created",        "log_event"))
    } else if mask & (IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE) != 0 {
        Some((10u8, "medium", "file_modified",       "log_event"))
    } else {
        None
    };

    if let Some((type_id, severity, action_label, action_hint)) = primary {
        let description = format!("{action_label}: {file_label}");
        emit_fs_incident(type_id, severity, action_label, &description, &source, action_hint);
        eprintln!(
            "fs watch type={type_id} action={action_label} file={file_label} dir={}",
            watch_root.display()
        );
    }
}

/// Build and emit a typed filesystem incident record to stdout.
fn emit_fs_incident(
    incident_type_id: u8,
    severity:         &str,
    signature:        &str,
    description:      &str,
    source:           &str,
    action_hint:      &str,
) {
    let ts       = current_timestamp_ms();
    let incident = IncidentRecord {
        event_id:         build_event_id("FS_EVENT", source, ts),
        incident_type_id,
        sensor_id:        incident_sensor_id(),
        timestamp:        current_timestamp_rfc3339(),
        ecu_id:           incident_ecu_id(),
        bus_type:         "USB".to_owned(),
        source:           source.to_owned(),
        can_id:           "n/a".to_owned(),
        direction:        "rx".to_owned(),
        severity:         severity.to_owned(),
        severity_id:      severity_id_for(severity),
        confidence:       90,
        signature:        description.to_owned(),
        usb_class:        None,
        usb_subclass:     None,
        usb_protocol:     None,
        evidence_hash:    build_evidence_hash(source, signature, severity),
        action_hint:      action_hint.to_owned(),
    };
    record_incident(&incident);
}

fn decode_inotify_name(bytes: &[u8]) -> Option<String> {
    let end   = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let value = &bytes[..end];
    if value.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(value).to_string())
}

// ── inotify constants and FFI ──────────────────────────────────────────────────

const IN_CREATE:      u32   = 0x0000_0100;
const IN_MODIFY:      u32   = 0x0000_0002;
const IN_DELETE:      u32   = 0x0000_0200;
const IN_MOVED_FROM:  u32   = 0x0000_0040;
const IN_MOVED_TO:    u32   = 0x0000_0080;
const IN_ATTRIB:      u32   = 0x0000_0004;
const IN_CLOSE_WRITE: u32   = 0x0000_0008;
const IN_DELETE_SELF: u32   = 0x0000_0400;
const IN_MOVE_SELF:   u32   = 0x0000_0800;
const IN_NONBLOCK:    c_int = 0x0000_0800;

#[repr(C)]
struct InotifyEvent {
    wd:     c_int,
    mask:   u32,
    cookie: u32,
    len:    u32,
}

unsafe extern "C" {
    fn inotify_init1(flags: c_int) -> c_int;
    fn inotify_add_watch(fd: c_int, pathname: *const c_char, mask: u32) -> c_int;
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    fn close(fd: c_int) -> c_int;
}
