#![no_main]

use libfuzzer_sys::fuzz_target;
use net_compat::dns_parser::parse_packet;

fuzz_target!(|data: &[u8]| {
    let _ = parse_packet(data);
});
