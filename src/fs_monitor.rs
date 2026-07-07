use std::env;
use std::ffi::OsString;
use std::io;
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

static FS_WATCH: OnceLock<Mutex<Option<FilesystemWatcher>>> = OnceLock::new();

struct FilesystemWatcher {
    stop_requested: std::sync::Arc<AtomicBool>,
    handle: thread::JoinHandle<()>,
}

pub fn start_fs_watch_thread() {
    let watcher_slot = FS_WATCH.get_or_init(|| Mutex::new(None));
    let mut watcher = watcher_slot.lock().expect("filesystem watcher mutex poisoned");

    if watcher.is_some() {
        eprintln!("filesystem watcher is already running");
        return;
    }

    let target = resolve_fs_watch_target();
    eprintln!("starting filesystem watcher");
    let stop_requested = std::sync::Arc::new(AtomicBool::new(false));
    let thread_stop_requested = std::sync::Arc::clone(&stop_requested);
    let handle = thread::Builder::new()
        .name("fs-monitor".to_owned())
        .spawn(move || watch_fs_target(target, thread_stop_requested))
        .expect("failed to spawn fs monitor thread");

    *watcher = Some(FilesystemWatcher {
        stop_requested,
        handle,
    });
}

pub fn stop_fs_watch_thread() {
    let Some(watcher_slot) = FS_WATCH.get() else {
        eprintln!("filesystem watcher is not running");
        return;
    };

    let watcher = {
        let mut watcher = watcher_slot.lock().expect("filesystem watcher mutex poisoned");
        watcher.take()
    };

    let Some(watcher) = watcher else {
        eprintln!("filesystem watcher is not running");
        return;
    };

    watcher.stop_requested.store(true, Ordering::SeqCst);
    let _ = watcher.handle.join();
    eprintln!("filesystem watcher stopped");
}

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
            .and_then(|name| name.to_str())
            .map(|name| format!(" (filtering for {name})"))
            .unwrap_or_default()
    );

    unsafe {
        let fd = inotify_init1(IN_NONBLOCK);
        if fd < 0 {
            eprintln!("failed to initialize inotify");
            return;
        }

        let watch_path = match std::ffi::CString::new(watch_root.as_os_str().as_bytes()) {
            Ok(value) => value,
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

            let mut offset = 0usize;
            let bytes_read = bytes_read as usize;
            while offset + std::mem::size_of::<InotifyEvent>() <= bytes_read {
                let raw_event = &*(buffer.as_ptr().add(offset) as *const InotifyEvent);
                let name_offset = offset + std::mem::size_of::<InotifyEvent>();
                let name_len = raw_event.len as usize;
                let name_end = name_offset.saturating_add(name_len).min(bytes_read);
                let name_bytes = &buffer[name_offset..name_end];
                let name = decode_inotify_name(name_bytes);

                if should_report_event(filter_name.as_ref(), name.as_deref()) {
                    report_inotify_event(raw_event.mask, &watch_root, name.as_deref());
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
        (Some(_), None) => false,
        (None, _) => true,
    }
}

fn report_inotify_event(mask: u32, watch_root: &Path, file_name: Option<&str>) {
    let timestamp = super::current_timestamp_ms();
    let path_label = file_name
        .map(|name| watch_root.join(name).display().to_string())
        .unwrap_or_else(|| watch_root.display().to_string());

    let mut labels = Vec::new();
    if mask & IN_CREATE != 0 {
        labels.push("created");
    }
    if mask & IN_MODIFY != 0 {
        labels.push("updated");
    }
    if mask & IN_CLOSE_WRITE != 0 {
        labels.push("uploaded");
    }
    if mask & IN_DELETE != 0 {
        labels.push("deleted");
    }
    if mask & IN_MOVED_TO != 0 {
        labels.push("moved-in");
    }
    if mask & IN_MOVED_FROM != 0 {
        labels.push("moved-out");
    }
    if mask & IN_ATTRIB != 0 {
        labels.push("metadata-changed");
    }

    let labels = if labels.is_empty() {
        "activity".to_owned()
    } else {
        labels.join(",")
    };

    println!("[{timestamp}] fs watch {labels} path={path_label}");
}

fn decode_inotify_name(bytes: &[u8]) -> Option<String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let value = &bytes[..end];

    if value.is_empty() {
        return None;
    }

    Some(String::from_utf8_lossy(value).to_string())
}

const IN_CREATE: u32 = 0x0000_0100;
const IN_MODIFY: u32 = 0x0000_0002;
const IN_DELETE: u32 = 0x0000_0200;
const IN_MOVED_FROM: u32 = 0x0000_0040;
const IN_MOVED_TO: u32 = 0x0000_0080;
const IN_ATTRIB: u32 = 0x0000_0004;
const IN_CLOSE_WRITE: u32 = 0x0000_0008;
const IN_DELETE_SELF: u32 = 0x0000_0400;
const IN_MOVE_SELF: u32 = 0x0000_0800;
const IN_NONBLOCK: c_int = 0x0000_0800;

#[repr(C)]
struct InotifyEvent {
    wd: c_int,
    mask: u32,
    cookie: u32,
    len: u32,
}

unsafe extern "C" {
    fn inotify_init1(flags: c_int) -> c_int;
    fn inotify_add_watch(fd: c_int, pathname: *const c_char, mask: u32) -> c_int;
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    fn close(fd: c_int) -> c_int;
}
