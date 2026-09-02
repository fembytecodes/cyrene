#![no_main]

use cyrene_authority::ShareInvitation;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<ShareInvitation>(data);
});
