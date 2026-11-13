//! Exercise the same exported ABI as Go. The scratch copy stands in for Go's
//! heap copy so native allocation counts do not include a second Rust copy.

#[repr(C)]
struct RawBuffer {
    data: *mut u8,
    len: usize,
}
unsafe extern "C" {
    fn latch_session_new(
        id: *const u8,
        id_len: usize,
        seed: *const u8,
        seed_len: usize,
        key: *const u8,
        key_len: usize,
        out: *mut u64,
    ) -> i32;
    fn latch_execute(handle: u64, op: u32, data: *const u8, len: usize, out: *mut RawBuffer)
    -> i32;
    fn latch_session_free(handle: u64) -> i32;
    fn latch_buffer_free(buffer: RawBuffer);
}
struct Output(RawBuffer);
impl Output {
    fn bytes(&self) -> &[u8] {
        if self.0.len == 0 {
            return &[];
        }
        // SAFETY: a successful ABI output owns this live allocation until Drop.
        unsafe { std::slice::from_raw_parts(self.0.data, self.0.len) }
    }
}
impl Drop for Output {
    fn drop(&mut self) {
        let owned = RawBuffer {
            data: self.0.data,
            len: self.0.len,
        };
        // SAFETY: this output is passed back exactly once, unmodified.
        unsafe { latch_buffer_free(owned) };
    }
}
struct Member(u64);
impl Member {
    fn new(seed: u8, id: &[u8]) -> Self {
        let private = [seed; 32];
        let public = ed25519_dalek::SigningKey::from_bytes(&private)
            .verifying_key()
            .to_bytes();
        let mut handle = 0;
        // SAFETY: input slices and the output handle remain live for the call.
        let result = unsafe {
            latch_session_new(
                id.as_ptr(),
                id.len(),
                private.as_ptr(),
                private.len(),
                public.as_ptr(),
                public.len(),
                &mut handle,
            )
        };
        assert_eq!(result, 0);
        assert_ne!(handle, 0);
        Self(handle)
    }
    fn call(&self, op: u32, data: &[u8]) -> Output {
        let mut out = RawBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
        // SAFETY: the live handle, input slice and output object meet the ABI.
        let result = unsafe { latch_execute(self.0, op, data.as_ptr(), data.len(), &mut out) };
        assert_eq!(result, 0);
        assert!(out.len <= 65536);
        Output(out)
    }
}
impl Drop for Member {
    fn drop(&mut self) {
        // SAFETY: this is an owned integer handle, removed exactly once.
        assert_eq!(unsafe { latch_session_free(self.0) }, 0);
    }
}
fn pack(fields: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::new();
    for field in fields {
        output.extend_from_slice(&(field.len() as u32).to_be_bytes());
        output.extend_from_slice(field);
    }
    output
}
fn field(mut bytes: &[u8], index: usize) -> &[u8] {
    for i in 0..=index {
        let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        bytes = &bytes[4..];
        if i == index {
            return &bytes[..length];
        };
        bytes = &bytes[length..];
    }
    unreachable!()
}
pub struct Pair {
    sender: Member,
    receiver: Member,
    scratch: [u8; 65536],
}
impl Pair {
    pub fn new() -> Self {
        let sender = Member::new(1, b"benchmark host");
        let receiver = Member::new(2, b"benchmark member");
        let host_key = ed25519_dalek::SigningKey::from_bytes(&[1; 32])
            .verifying_key()
            .to_bytes();
        let member_key = ed25519_dalek::SigningKey::from_bytes(&[2; 32])
            .verifying_key()
            .to_bytes();
        sender.call(2, &[23; 16]);
        let package = receiver.call(1, &[]);
        let change = sender.call(
            4,
            &pack(&[package.bytes(), b"benchmark member", &member_key]),
        );
        let roster = pack(&[
            b"benchmark host",
            &host_key,
            b"benchmark member",
            &member_key,
        ]);
        receiver.call(
            3,
            &pack(&[field(change.bytes(), 1), &[23; 16], &host_key, &roster]),
        );
        Self {
            sender,
            receiver,
            scratch: [0; 65536],
        }
    }
    pub fn roundtrip(&mut self, payload: &[u8]) {
        let ciphertext = self.sender.call(8, payload);
        let length = ciphertext.bytes().len();
        self.scratch[..length].copy_from_slice(ciphertext.bytes());
        drop(ciphertext);
        let application = self.receiver.call(9, &self.scratch[..length]);
        assert_eq!(field(application.bytes(), 2), payload);
    }
}
