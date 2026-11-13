//! Instrumented native allocation measurements. This allocator is linked only
//! into this standalone development benchmark, never into release libraries.

use latch_crypto::{Identity, Session};
mod support {
    pub mod abi;
}
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
    time::Instant,
};

struct MeasuredAllocator;
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static REQUESTED: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn allocated(bytes: usize) {
    ALLOCATIONS.fetch_add(1, Relaxed);
    REQUESTED.fetch_add(bytes, Relaxed);
    let live = LIVE.fetch_add(bytes, Relaxed) + bytes;
    PEAK.fetch_max(live, Relaxed);
}

// SAFETY: pointers, sizes and alignment are delegated unchanged to System.
unsafe impl GlobalAlloc for MeasuredAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller provides the GlobalAlloc layout contract.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller provides the GlobalAlloc layout contract.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Relaxed);
        // SAFETY: the original pointer and layout are passed to System.
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: the original pointer/layout and requested size are unchanged.
        let result = unsafe { System.realloc(pointer, layout, size) };
        if !result.is_null() {
            ALLOCATIONS.fetch_add(1, Relaxed);
            REQUESTED.fetch_add(size, Relaxed);
            let live = if size >= layout.size() {
                LIVE.fetch_add(size - layout.size(), Relaxed) + size - layout.size()
            } else {
                LIVE.fetch_sub(layout.size() - size, Relaxed) - (layout.size() - size)
            };
            PEAK.fetch_max(live, Relaxed);
        }
        result
    }
}

#[global_allocator]
static ALLOCATOR: MeasuredAllocator = MeasuredAllocator;

fn device(seed: u8, name: &[u8]) -> (Session, Identity) {
    // Synthetic benchmark credentials, with no network enrollment or authority.
    let private = [seed; 32];
    let public = ed25519_dalek::SigningKey::from_bytes(&private)
        .verifying_key()
        .to_bytes()
        .to_vec();
    let identity = Identity {
        credential: name.to_vec(),
        public_key: public,
    };
    (Session::new(identity.clone(), &private).unwrap(), identity)
}

fn measure(iterations: usize, payload_bytes: usize) {
    let (mut sender, host) = device(1, b"benchmark host");
    let (mut receiver, member) = device(2, b"benchmark member");
    sender.create(&[23; 16]).unwrap();
    let package = receiver.key_package().unwrap();
    let change = sender.add(&package, &member).unwrap();
    receiver
        .join(
            &change.welcome,
            &[23; 16],
            &host.public_key,
            &[host.clone(), member],
        )
        .unwrap();
    let payload = vec![b'x'; payload_bytes];
    for _ in 0..100 {
        let cipher = sender.encrypt(&payload).unwrap();
        assert_eq!(receiver.decrypt(&cipher).unwrap().plaintext, payload);
    }
    let baseline = LIVE.load(Relaxed);
    ALLOCATIONS.store(0, Relaxed);
    REQUESTED.store(0, Relaxed);
    PEAK.store(baseline, Relaxed);
    let started = Instant::now();
    for _ in 0..iterations {
        let ciphertext = sender.encrypt(&payload).unwrap();
        let application = receiver.decrypt(&ciphertext).unwrap();
        assert_eq!(application.plaintext, payload);
    }
    let elapsed = started.elapsed().as_nanos() as f64;
    let allocations = ALLOCATIONS.load(Relaxed);
    let requested = REQUESTED.load(Relaxed);
    let live = LIVE.load(Relaxed);
    let peak = PEAK.load(Relaxed);
    println!(
        "{{\"payload_bytes\":{payload_bytes},\"iterations\":{iterations},\"rust_allocations_per_roundtrip\":{},\"rust_requested_bytes_per_roundtrip\":{},\"rust_live_before_bytes\":{baseline},\"rust_live_after_bytes\":{live},\"rust_peak_bytes\":{peak},\"instrumented_ns_per_roundtrip\":{}}}",
        allocations as f64 / iterations as f64,
        requested as f64 / iterations as f64,
        elapsed / iterations as f64
    );
}

fn main() {
    let iterations = std::env::var("LATCH_BENCH_MESSAGES")
        .ok()
        .map(|value| value.parse::<usize>().expect("invalid iteration count"))
        .unwrap_or(10000);
    assert!((1..=1_000_000).contains(&iterations));
    for payload in [128, 4096] {
        measure(iterations, payload);
        measure_abi(iterations, payload);
    }
}

fn measure_abi(iterations: usize, payload_bytes: usize) {
    let mut pair = support::abi::Pair::new();
    let payload = vec![b'x'; payload_bytes];
    for _ in 0..100 {
        pair.roundtrip(&payload);
    }
    let baseline = LIVE.load(Relaxed);
    ALLOCATIONS.store(0, Relaxed);
    REQUESTED.store(0, Relaxed);
    PEAK.store(baseline, Relaxed);
    let started = Instant::now();
    for _ in 0..iterations {
        pair.roundtrip(&payload);
    }
    let elapsed = started.elapsed().as_nanos() as f64;
    let allocations = ALLOCATIONS.load(Relaxed);
    let requested = REQUESTED.load(Relaxed);
    let live = LIVE.load(Relaxed);
    let peak = PEAK.load(Relaxed);
    println!(
        "{{\"path\":\"native_abi\",\"payload_bytes\":{payload_bytes},\"iterations\":{iterations},\"rust_allocations_per_roundtrip\":{},\"rust_requested_bytes_per_roundtrip\":{},\"rust_live_before_bytes\":{baseline},\"rust_live_after_bytes\":{live},\"rust_peak_bytes\":{peak},\"instrumented_ns_per_roundtrip\":{}}}",
        allocations as f64 / iterations as f64,
        requested as f64 / iterations as f64,
        elapsed / iterations as f64
    );
}
