#![no_main]

use c2pa_text_binding::{manifest::verify_cose, tag, zwbin};
use libfuzzer_sys::fuzz_target;

const DUMMY_KEY: [u8; 32] = [0u8; 32];

fuzz_target!(|data: &[u8]| {
    let _ = verify_cose(data, &DUMMY_KEY);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = tag::extract(text);
        let _ = zwbin::extract(text);
    }
});
