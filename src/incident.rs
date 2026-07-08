use std::env;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone)]
pub(crate) struct IncidentRecord {
    pub(crate) event_id: String,
    pub(crate) sensor_id: String,
    pub(crate) timestamp: String,
    pub(crate) ecu_id: String,
    pub(crate) bus_type: String,
    pub(crate) source: String,
    pub(crate) can_id: String,
    pub(crate) direction: String,
    pub(crate) severity: String,
    pub(crate) confidence: u8,
    pub(crate) signature: String,
    pub(crate) usb_class: Option<String>,
    pub(crate) usb_subclass: Option<String>,
    pub(crate) usb_protocol: Option<String>,
    pub(crate) evidence_hash: String,
    pub(crate) action_hint: String,
}

pub(crate) fn record_incident(incident: &IncidentRecord) {
    println!("{}", incident_record_to_json(incident));
}

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
    let mut lines = Vec::with_capacity(18);
    lines.push("{".to_owned());
    lines.push(format!("  \"event_id\": {},", json_string(&incident.event_id)));
    lines.push(format!("  \"sensor_id\": {},", json_string(&incident.sensor_id)));
    lines.push(format!("  \"timestamp\": {},", json_string(&incident.timestamp)));
    lines.push(format!("  \"ecu_id\": {},", json_string(&incident.ecu_id)));
    lines.push(format!("  \"bus_type\": {},", json_string(&incident.bus_type)));
    lines.push(format!("  \"source\": {},", json_string(&incident.source)));
    lines.push(format!("  \"can_id\": {},", json_string(&incident.can_id)));
    lines.push(format!("  \"direction\": {},", json_string(&incident.direction)));
    lines.push(format!("  \"severity\": {},", json_string(&incident.severity)));
    lines.push(format!("  \"confidence\": {},", incident.confidence));
    lines.push(format!("  \"signature\": {},", json_string(&incident.signature)));
    lines.push(format!("  \"usb_class\": {},", json_option_string(incident.usb_class.as_deref())));
    lines.push(format!("  \"usb_subclass\": {},", json_option_string(incident.usb_subclass.as_deref())));
    lines.push(format!("  \"usb_protocol\": {},", json_option_string(incident.usb_protocol.as_deref())));
    lines.push(format!("  \"evidence_hash\": {},", json_string(&incident.evidence_hash)));
    lines.push(format!("  \"action_hint\": {}", json_string(&incident.action_hint)));
    lines.push("}".to_owned());

    lines.join("\n")
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');

    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0C}' => escaped.push_str("\\f"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{:04x}", character as u32);
            }
            character => escaped.push(character),
        }
    }

    escaped.push('"');
    escaped
}

fn json_option_string(value: Option<&str>) -> String {
    match value {
        Some(value) => json_string(value),
        None => "null".to_owned(),
    }
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };

    (year as i32, month as u32, day as u32)
}