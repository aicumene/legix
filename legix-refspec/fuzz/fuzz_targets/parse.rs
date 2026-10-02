#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    drop(legix_refspec::parse(data.into(), legix_refspec::parse::Operation::Push));
    drop(legix_refspec::parse(data.into(), legix_refspec::parse::Operation::Fetch));
});
