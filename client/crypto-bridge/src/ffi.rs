//! The ABI owns its allocations and exposes integer handles rather than Rust
//! pointers. Callers must pass live buffers for the indicated lengths and free
//! successful output once with latch_buffer_free. No Rust pointer retains Go data.

use crate::{Change, Error, Identity, Result, Session};
use std::{
    collections::HashMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Mutex, Once, OnceLock},
};

const MAX_SESSIONS: usize = 16;
const MAX_PACKET: usize = 65536;

#[repr(C)]
pub struct Buffer {
    pub data: *mut u8,
    pub len: usize,
}

struct Registry {
    next: u64,
    sessions: HashMap<u64, Session>,
}
static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
static PANIC_HOOK: Once = Once::new();

fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(|| {
        Mutex::new(Registry {
            next: 1,
            sessions: HashMap::new(),
        })
    })
}

fn boundary(f: impl FnOnce() -> Result<()>) -> i32 {
    // Never emit panic payloads, backtraces or source input from native crypto.
    PANIC_HOOK.call_once(|| std::panic::set_hook(Box::new(|_| {})));
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => 0,
        Ok(Err(Error::Invalid)) => 1,
        Ok(Err(Error::State)) => 2,
        Ok(Err(Error::Membership)) => 3,
        Ok(Err(Error::Crypto)) => 4,
        Err(_) => {
            // A panic may interrupt an MLS mutation while the registry lock is
            // held. Do not leave poisoned, still-referenced room secrets behind
            // or permit any partially mutated session to be used again.
            let mut r = registry()
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            r.sessions.clear();
            registry().clear_poison();
            5
        }
    }
}

unsafe fn input<'a>(data: *const u8, len: usize) -> Result<&'a [u8]> {
    if len > MAX_PACKET || (len > 0 && data.is_null()) {
        return Err(Error::Invalid);
    }
    if len == 0 {
        return Ok(&[]);
    }
    // SAFETY: caller promises a readable buffer of len bytes for this call.
    Ok(unsafe { std::slice::from_raw_parts(data, len) })
}

unsafe fn output(out: *mut Buffer, bytes: Vec<u8>) -> Result<()> {
    if out.is_null() || bytes.len() > MAX_PACKET {
        return Err(Error::Invalid);
    }
    let mut bytes = bytes.into_boxed_slice();
    let value = Buffer {
        data: bytes.as_mut_ptr(),
        len: bytes.len(),
    };
    std::mem::forget(bytes);
    // SAFETY: caller supplies a valid, uniquely writable output object.
    unsafe { out.write(value) };
    Ok(())
}

fn fields(mut bytes: &[u8]) -> Result<Vec<&[u8]>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 || out.len() >= 64 {
            return Err(Error::Invalid);
        }
        let n = u32::from_be_bytes(bytes[..4].try_into().map_err(|_| Error::Invalid)?) as usize;
        bytes = &bytes[4..];
        if n > bytes.len() {
            return Err(Error::Invalid);
        }
        out.push(&bytes[..n]);
        bytes = &bytes[n..];
    }
    Ok(out)
}

fn pack(fields: &[&[u8]]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for f in fields {
        if out.len() + 4 + f.len() > MAX_PACKET {
            return Err(Error::Invalid);
        }
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f);
    }
    Ok(out)
}

fn identities(data: &[u8]) -> Result<Vec<Identity>> {
    let f = fields(data)?;
    if f.is_empty() || f.len() % 2 != 0 || f.len() > crate::MAX_MEMBERS * 2 {
        return Err(Error::Invalid);
    }
    Ok(f.as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Identity {
            credential: pair[0].to_vec(),
            public_key: pair[1].to_vec(),
        })
        .collect())
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_fields(data: &[u8]) {
    if let Ok(decoded) = fields(data) {
        let encoded = pack(&decoded).expect("bounded parsed fields must re-encode");
        assert_eq!(encoded, data);
    }
    let _ = identities(data);
}

fn change(c: Change) -> Result<Vec<u8>> {
    pack(&[&c.commit, &c.welcome, &c.epoch.to_be_bytes()])
}

/// # Safety
/// Input buffers must be live for this call; handle_out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn latch_session_new(
    identity: *const u8,
    identity_len: usize,
    seed: *const u8,
    seed_len: usize,
    key: *const u8,
    key_len: usize,
    handle_out: *mut u64,
) -> i32 {
    boundary(|| {
        if handle_out.is_null() {
            return Err(Error::Invalid);
        }
        unsafe { handle_out.write(0) };
        let id = Identity {
            credential: unsafe { input(identity, identity_len)? }.to_vec(),
            public_key: unsafe { input(key, key_len)? }.to_vec(),
        };
        let session = Session::new(id, unsafe { input(seed, seed_len)? })?;
        let mut r = registry().lock().map_err(|_| Error::State)?;
        if r.sessions.len() >= MAX_SESSIONS {
            return Err(Error::State);
        }
        let handle = r.next;
        r.next = r.next.checked_add(1).ok_or(Error::State)?;
        r.sessions.insert(handle, session);
        unsafe { handle_out.write(handle) };
        Ok(())
    })
}

/// # Safety
/// data must remain readable, and out writable, throughout this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn latch_execute(
    handle: u64,
    op: u32,
    data: *const u8,
    len: usize,
    out: *mut Buffer,
) -> i32 {
    boundary(|| {
        if out.is_null() {
            return Err(Error::Invalid);
        }
        unsafe {
            out.write(Buffer {
                data: std::ptr::null_mut(),
                len: 0,
            })
        };
        let bytes = unsafe { input(data, len)? };
        let mut r = registry().lock().map_err(|_| Error::State)?;
        let session = r.sessions.get_mut(&handle).ok_or(Error::State)?;
        let result = execute(session, op, bytes);
        // A membership operation that fails may already have consumed MLS state.
        // Remove the entire session rather than permitting inconsistent reuse.
        if result.is_err() && matches!(op, 2..=7) {
            r.sessions.remove(&handle);
        }
        unsafe { output(out, result?) }
    })
}

fn execute(s: &mut Session, op: u32, data: &[u8]) -> Result<Vec<u8>> {
    match op {
        1 if data.is_empty() => s.key_package(),
        2 => {
            s.create(data)?;
            Ok(Vec::new())
        }
        3 => {
            let f = fields(data)?;
            if f.len() != 4 {
                return Err(Error::Invalid);
            }
            s.join(f[0], f[1], f[2], &identities(f[3])?)?;
            Ok(Vec::new())
        }
        4 => {
            let f = fields(data)?;
            if f.len() != 3 {
                return Err(Error::Invalid);
            }
            change(s.add(
                f[0],
                &Identity {
                    credential: f[1].to_vec(),
                    public_key: f[2].to_vec(),
                },
            )?)
        }
        5 => change(s.remove(data)?),
        6 if data.is_empty() => change(s.update()?),
        7 => {
            let f = fields(data)?;
            if f.len() != 2 {
                return Err(Error::Invalid);
            }
            s.process_commit(f[0], &identities(f[1])?)?;
            Ok(s.epoch()?.to_be_bytes().to_vec())
        }
        8 => s.encrypt(data),
        9 => {
            let a = s.decrypt(data)?;
            pack(&[&a.sender.credential, &a.sender.public_key, &a.plaintext])
        }
        10 if data.is_empty() => {
            let members = s.members()?;
            let mut f = Vec::new();
            for m in &members {
                f.push(m.credential.as_slice());
                f.push(m.public_key.as_slice());
            }
            pack(&f)
        }
        11 if data.is_empty() => Ok(s.epoch()?.to_be_bytes().to_vec()),
        _ => Err(Error::Invalid),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn latch_session_free(handle: u64) -> i32 {
    boundary(|| {
        registry()
            .lock()
            .map_err(|_| Error::State)?
            .sessions
            .remove(&handle);
        Ok(())
    })
}

/// # Safety
/// buffer must be an unmodified result of latch_execute and freed exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn latch_buffer_free(buffer: Buffer) {
    if buffer.data.is_null() {
        return;
    }
    // SAFETY: matched allocation from output() above, owned by this function.
    let mut bytes =
        unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(buffer.data, buffer.len)) };
    bytes.fill(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    #[test]
    fn invalid_buffers_and_stale_handles() {
        let _guard = TEST_LOCK.lock().unwrap();
        assert_eq!(
            unsafe {
                latch_session_new(
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                )
            },
            1
        );
        let mut out = Buffer {
            data: std::ptr::null_mut(),
            len: 0,
        };
        assert_eq!(
            unsafe { latch_execute(999, 1, std::ptr::null(), 0, &mut out) },
            2
        );
        assert_eq!(
            unsafe { latch_execute(999, 1, std::ptr::null(), MAX_PACKET + 1, &mut out) },
            1
        );
        assert_eq!(latch_session_free(999), 0);
    }
    #[test]
    fn packet_bounds() {
        let _guard = TEST_LOCK.lock().unwrap();
        assert!(fields(&[0, 0, 0, 2, 1]).is_err());
        assert!(fields(&[0]).is_err());
        assert!(identities(&[]).is_err());
        let p = pack(&[b"a", b"bc"]).unwrap();
        assert_eq!(fields(&p).unwrap(), vec![b"a".as_slice(), b"bc".as_slice()]);
    }

    #[test]
    fn panic_discards_sessions_and_recovers_registry() {
        let _guard = TEST_LOCK.lock().unwrap();
        let seed = [17; 32];
        let key = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
            .to_vec();
        let session = Session::new(
            Identity {
                credential: b"panic test".to_vec(),
                public_key: key,
            },
            &seed,
        )
        .unwrap();
        registry()
            .lock()
            .unwrap()
            .sessions
            .insert(u64::MAX, session);
        let status = boundary(|| {
            let _guard = registry().lock().unwrap();
            panic!("synthetic native failure");
        });
        assert_eq!(status, 5);
        assert!(!registry().is_poisoned());
        assert!(registry().lock().unwrap().sessions.is_empty());
    }
}
