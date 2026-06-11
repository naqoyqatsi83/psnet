use std::collections::HashMap;
use std::sync::OnceLock;

static OUI_MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

pub fn lookup(mac: &str) -> Option<&'static str> {
    // Normalize: strip colons/dashes, take first 6 chars, uppercase
    let prefix: String = mac.chars()
        .filter(|c| *c != ':' && *c != '-')
        .take(6)
        .collect::<String>()
        .to_uppercase();

    let map = OUI_MAP.get_or_init(build_map);
    map.get(prefix.as_str()).copied()
}

pub fn warm() {
    OUI_MAP.get_or_init(build_map);
}

fn build_map() -> HashMap<&'static str, &'static str> {
    let mut map = HashMap::new();
    for line in include_str!("../../../data/oui.txt").lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        // Format: "XXXXXX<tab>Vendor Name"
        if let Some((oui, vendor)) = line.split_once('\t') {
            map.insert(oui, vendor);
        }
    }
    map
}
