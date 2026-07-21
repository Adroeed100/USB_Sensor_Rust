use std::env;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::net::TcpStream;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// A single structured incident record emitted to stdout as JSON.
#[derive(Debug, Clone)]
pub(crate) struct IncidentRecord {
    pub(crate) event_id: String,
    /// Incident type ID from the taxonomy (1–17).
    pub(crate) incident_type_id: u8,
    pub(crate) sensor_id: String,
    pub(crate) timestamp: String,
    pub(crate) ecu_id: String,
    pub(crate) bus_type: String,
    pub(crate) source: String,
    pub(crate) can_id: String,
    pub(crate) direction: String,
    pub(crate) severity: String,
    /// Numeric severity: 1=low, 2=medium, 3=high, 4=critical.
    pub(crate) severity_id: u8,
    pub(crate) confidence: u8,
    pub(crate) signature: String,
    pub(crate) usb_class: Option<String>,
    pub(crate) usb_subclass: Option<String>,
    pub(crate) usb_protocol: Option<String>,
    pub(crate) evidence_hash: String,
    pub(crate) action_hint: String,
}

/// Map a severity string to its numeric level (1=low, 2=medium, 3=high, 4=critical).
pub(crate) fn severity_id_for(severity: &str) -> u8 {
    match severity {
        "low"      => 1,
        "medium"   => 2,
        "high"     => 3,
        "critical" => 4,
        _          => 0,
    }
}

// ── IDSM TCP delivery ────────────────────────────────────────────────────────

/// Set once from main() after parsing the IDSM address off the command line.
static IDSM_ADDR: OnceLock<String> = OnceLock::new();

/// Persistent connection, shared across all threads that call record_incident.
static IDSM_CONN: Mutex<Option<TcpStream>> = Mutex::new(None);

/// Called once from main() right after parsing argv.
pub(crate) fn set_idsm_addr(addr: String) {
    if IDSM_ADDR.set(addr).is_err() {
        eprintln!("idsm: address already set, ignoring duplicate call");
    }
}

/// Get an existing live connection, or attempt to (re)connect to IDSM.
/// Returns a cloned handle so multiple threads can write concurrently
/// without holding the lock during the actual send.
fn idsm_stream() -> Option<TcpStream> {
    let addr = IDSM_ADDR.get()?; // no address configured → no-op

    let mut guard = IDSM_CONN.lock().unwrap();

    if let Some(stream) = guard.as_ref() {
        if let Ok(cloned) = stream.try_clone() {
            return Some(cloned);
        }
    }

    match TcpStream::connect(addr) {
        Ok(stream) => {
            let _ = stream.set_nodelay(true);
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            let cloned = stream.try_clone().ok();
            *guard = Some(stream);
            eprintln!("idsm: connected to {addr}");
            cloned
        }
        Err(err) => {
            eprintln!("idsm: connect to {addr} failed: {err}");
            None
        }
    }
}

/// Drop the cached connection so the next send re-attempts a fresh connect.
fn idsm_drop_connection() {
    let mut guard = IDSM_CONN.lock().unwrap();
    *guard = None;
}

fn send_to_idsm(incident: &IncidentRecord) {
    let Some(mut stream) = idsm_stream() else {
        return; // not configured, or connect failed — already logged
    };

    let mut payload = format!(
        r#"{{"event_id":{},"source":{},"description":{},"context_data":null}}"#,
        incident.incident_type_id,
        json_string(&incident.source),
        json_string(&incident.signature)
    );
    payload.push('\n'); // newline-delimited so the IDSM side can just read_line

    if let Err(err) = stream.write_all(payload.as_bytes()) {
        eprintln!("idsm: send failed, will reconnect next incident: {err}");
        idsm_drop_connection();
    }
}

pub(crate) fn record_incident(incident: &IncidentRecord) {
    println!("{}", incident_record_to_json(incident));
    send_to_idsm(incident);
}

// ── Shared helpers ──────────────────────────────────────────────────────────

pub(crate) fn incident_sensor_id() -> String {
    env::var("INCIDENT_SENSOR_ID").unwrap_or_else(|_| "sensor-01".to_owned())
}

pub(crate) fn incident_ecu_id() -> String {
    env::var("INCIDENT_ECU_ID").unwrap_or_else(|_| "unknown_ecu".to_owned())
}

pub(crate) fn build_event_id(prefix: &str, source: &str, timestamp_ms: u128) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    prefix.hash(&mut hasher);
    source.hash(&mut hasher);
    timestamp_ms.hash(&mut hasher);
    format!("{prefix}_{timestamp_ms}_{:016x}", hasher.finish())
}

pub(crate) fn build_evidence_hash(primary: &str, secondary: &str, tertiary: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    primary.hash(&mut hasher);
    secondary.hash(&mut hasher);
    tertiary.hash(&mut hasher);
    format!("sha256:{:016x}", hasher.finish())
}

/// Current wall-clock milliseconds since Unix epoch. Shared across all modules.
pub(crate) fn current_timestamp_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default()
}

pub(crate) fn current_timestamp_rfc3339() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = duration.as_secs() as i64;
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn incident_record_to_json(incident: &IncidentRecord) -> String {
    let mut lines = Vec::with_capacity(22);
    lines.push("{".to_owned());
    lines.push(format!("  \"event_id\": {},",           json_string(&incident.event_id)));
    lines.push(format!("  \"incident_type_id\": {},",   incident.incident_type_id));
    lines.push(format!("  \"sensor_id\": {},",          json_string(&incident.sensor_id)));
    lines.push(format!("  \"timestamp\": {},",          json_string(&incident.timestamp)));
    lines.push(format!("  \"ecu_id\": {},",             json_string(&incident.ecu_id)));
    lines.push(format!("  \"bus_type\": {},",           json_string(&incident.bus_type)));
    lines.push(format!("  \"source\": {},",             json_string(&incident.source)));
    lines.push(format!("  \"can_id\": {},",             json_string(&incident.can_id)));
    lines.push(format!("  \"direction\": {},",          json_string(&incident.direction)));
    lines.push(format!("  \"severity\": {},",           json_string(&incident.severity)));
    lines.push(format!("  \"severity_id\": {},",        incident.severity_id));
    lines.push(format!("  \"confidence\": {},",         incident.confidence));
    lines.push(format!("  \"signature\": {},",          json_string(&incident.signature)));
    lines.push(format!("  \"usb_class\": {},",          json_option_string(incident.usb_class.as_deref())));
    lines.push(format!("  \"usb_subclass\": {},",       json_option_string(incident.usb_subclass.as_deref())));
    lines.push(format!("  \"usb_protocol\": {},",       json_option_string(incident.usb_protocol.as_deref())));
    lines.push(format!("  \"evidence_hash\": {},",      json_string(&incident.evidence_hash)));
    lines.push(format!("  \"action_hint\": {}",         json_string(&incident.action_hint)));
    lines.push("}".to_owned());
    lines.join("\n")
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"'       => escaped.push_str("\\\""),
            '\\'      => escaped.push_str("\\\\"),
            '\u{08}'  => escaped.push_str("\\b"),
            '\u{0C}'  => escaped.push_str("\\f"),
            '\n'      => escaped.push_str("\\n"),
            '\r'      => escaped.push_str("\\r"),
            '\t'      => escaped.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{:04x}", c as u32);
            }
            c => escaped.push(c),
        }
    }
    escaped.push('"');
    escaped
}

fn json_option_string(value: Option<&str>) -> String {
    match value {
        Some(v) => json_string(v),
        None    => "null".to_owned(),
    }
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    (year as i32, month as u32, day as u32)
}