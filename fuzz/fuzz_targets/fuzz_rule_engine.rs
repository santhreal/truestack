#![no_main]

use libfuzzer_sys::fuzz_target;
use truestack::fingerprints;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    
    let engine = fingerprints::RuleEngine::embedded();

    // Use parts of the data to create headers and body.
    let split_idx = usize::from(data[0]) % data.len();
    if split_idx == 0 || split_idx >= data.len() {
        return;
    }
    
    let header_data = &data[1..split_idx];
    let body_data = &data[split_idx..];
    
    let header_str = String::from_utf8_lossy(header_data);
    let body_str = String::from_utf8_lossy(body_data);
    
    // Create some fake headers based on newlines and colons
    let mut headers = Vec::new();
    for line in header_str.lines() {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.to_string(), v.to_string()));
        } else {
            headers.push((line.to_string(), "true".to_string()));
        }
    }
    
    let _ = fingerprints::detect_with_engine(&headers, &body_str, None, engine);
});
