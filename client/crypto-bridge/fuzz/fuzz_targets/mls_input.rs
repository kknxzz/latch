#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    latch_crypto::fuzz_input(data);
});
