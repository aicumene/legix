#![no_main]

use legix_date;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    legix_date::parse(data, None).ok();
});
