#![no_main]

use libfuzzer_sys::fuzz_target;
use std::hint::black_box;

fuzz_target!(|tree: &[u8]| {
    let _ = black_box(legix_object::TreeRef::from_bytes(tree, legix_hash::Kind::Sha1));
    let _ = black_box(legix_object::TreeRef::from_bytes(tree, legix_hash::Kind::Sha256));
});
