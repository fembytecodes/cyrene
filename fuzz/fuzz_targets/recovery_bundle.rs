#![no_main]

use cyrene_trust::RecoveryBundle;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = RecoveryBundle::from_bytes(data);
});
