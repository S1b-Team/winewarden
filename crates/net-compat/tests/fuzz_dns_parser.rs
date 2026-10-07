//! Deterministic in-process fuzz harness for the DNS packet parser.
//!
//! Complements `fuzz/fuzz_targets/dns_parser.rs` (cargo-fuzz, nightly) with a
//! seeded pseudo-random corpus that runs as a plain `cargo test` target, so
//! CI and build-from-source users exercise the parser's attack surface
//! without special toolchains.

use net_compat::dns_parser::parse_packet;

struct XorShift64(u64);

impl XorShift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
}

/// Builds a header-only prefix with random-ish section counts so the corpus
/// frequently reaches the question/record parsing loops.
fn mutation_corpus(rng: &mut XorShift64) -> Vec<Vec<u8>> {
    let mut corpus = Vec::new();
    for _ in 0..2000 {
        let len = rng.below(128);
        let mut pkt: Vec<u8> = Vec::with_capacity(len.max(12));
        pkt.push((rng.next_u64() & 0xFF) as u8);
        pkt.push((rng.next_u64() & 0xFF) as u8);
        pkt.push((rng.next_u64() & 0xFF) as u8);
        pkt.push((rng.next_u64() & 0xFF) as u8);
        pkt.push((rng.next_u64() & 0x1F) as u8);
        pkt.push((rng.next_u64() & 0xFF) as u8);
        pkt.push((rng.next_u64() & 0x1F) as u8);
        pkt.push((rng.next_u64() & 0xFF) as u8);
        pkt.push((rng.next_u64() & 0x1F) as u8);
        pkt.push((rng.next_u64() & 0xFF) as u8);
        pkt.push((rng.next_u64() & 0x1F) as u8);
        pkt.push((rng.next_u64() & 0xFF) as u8);
        for _ in 0..len {
            pkt.push((rng.next_u64() & 0xFF) as u8);
        }
        corpus.push(pkt);
    }
    corpus
}

/// Seeds the corpus with structures that stress compression-pointer handling.
fn structured_corpus() -> Vec<Vec<u8>> {
    let mut corpus = Vec::new();
    let header = |qd: u16, an: u16| -> Vec<u8> {
        vec![
            0x00,
            0x01,
            0x01,
            0x00,
            qd.to_be_bytes()[0],
            qd.to_be_bytes()[1],
            an.to_be_bytes()[0],
            an.to_be_bytes()[1],
            0x00,
            0x00,
            0x00,
            0x00,
        ]
    };

    let mut self_loop = header(1, 0);
    self_loop.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
    corpus.push(self_loop);

    let mut mutual = header(1, 0);
    mutual.extend_from_slice(&[0xC0, 0x0E, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
    corpus.push(mutual);

    let mut long_chain = header(1, 0);
    for _ in 0..64 {
        long_chain.extend_from_slice(&[0xC0, 0x0E]);
    }
    long_chain.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    corpus.push(long_chain);

    let mut deep_labels = header(1, 0);
    for _ in 0..300 {
        deep_labels.extend_from_slice(&[0x01, b'a']);
    }
    deep_labels.push(0x00);
    deep_labels.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    corpus.push(deep_labels);

    let mut bad_pointer = header(1, 0);
    bad_pointer.extend_from_slice(&[0xC0, 0xFF, 0x00, 0x01, 0x00, 0x01]);
    corpus.push(bad_pointer);

    corpus
}

#[test]
fn dns_parser_never_panics_or_hangs_on_random_input() {
    let mut rng = XorShift64(0x9E3779B97F4A7C15);
    for pkt in mutation_corpus(&mut rng) {
        let _ = parse_packet(&pkt);
    }
}

#[test]
fn dns_parser_never_panics_or_hangs_on_structured_input() {
    for pkt in structured_corpus() {
        let _ = parse_packet(&pkt);
    }
}
