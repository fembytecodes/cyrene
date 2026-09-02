#![no_main]

use cyrene_net::RelayRequest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = serde_json::from_slice::<RelayRequest>(data) {
        let _ = request.verify(1_800_000_000);
    }
});
