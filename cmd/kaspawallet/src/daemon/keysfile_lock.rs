//! Exclusive keyfile lock. Acquires `<keysfile>.lock` via the
//! cross-platform [`fd_lock`] crate for the daemon's lifetime.
//! On POSIX the underlying primitive is `flock(2)`; on Windows
//! it is `LockFileEx`.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use fd_lock::{RwLock, RwLockWriteGuard};

use super::error::DaemonError;

/// Held for the daemon's lifetime; releases the OS-level lock on
/// drop. The contained `RwLock` owns the lock file's handle; the
/// guard borrows from it, so the lock and guard share this owner.
pub struct KeysfileGuard {
    // `_guard` must be dropped before `_lock`; Rust's default
    // field-drop order (declaration order) yields the right
    // sequence. Storing the lock keeps the underlying `File`
    // alive for the guard's lifetime.
    _guard: RwLockWriteGuard<'static, File>,
    _lock: Box<RwLock<File>>,
}

/// Acquire an exclusive lock on `<keysfile>.lock`. Returns
/// [`DaemonError::Runtime`] when the lock is already held by
/// another process or the lock file cannot be created.
pub fn acquire(keysfile_path: &Path) -> Result<KeysfileGuard, DaemonError> {
    let lock_path = lock_path_for(keysfile_path);
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|source| DaemonError::Runtime(format!("failed to open keyfile lock '{}': {source}", lock_path.display())))?;

    // Box the lock so its address is stable and the
    // `'static`-extended guard reference below stays valid for the
    // lifetime of the returned `KeysfileGuard` (the box outlives
    // the guard via struct field-drop order).
    let mut boxed = Box::new(RwLock::new(file));
    let lock_ptr: *mut RwLock<File> = &mut *boxed;
    // SAFETY: `boxed` is heap-allocated and stored alongside the
    // guard in `KeysfileGuard`; the box is dropped strictly after
    // the guard (field declaration order in `KeysfileGuard`), so
    // the dereferenced reference remains valid for the entire
    // life of `_guard`.
    let lock_ref: &'static mut RwLock<File> = unsafe { &mut *lock_ptr };
    match lock_ref.try_write() {
        Ok(guard) => Ok(KeysfileGuard { _guard: guard, _lock: boxed }),
        Err(err) => match err.kind() {
            io::ErrorKind::WouldBlock => Err(DaemonError::Runtime(format!(
                "keyfile '{}' is already in use by another wallet daemon (lock '{}'); refusing to start",
                keysfile_path.display(),
                lock_path.display(),
            ))),
            _ => Err(DaemonError::Runtime(format!("failed to acquire keyfile lock '{}': {err}", lock_path.display(),))),
        },
    }
}

/// Compose `<keysfile>.lock` from the keyfile path, preserving the
/// parent directory and the full basename (e.g.
/// `/var/.../keys.json` -> `/var/.../keys.json.lock`).
fn lock_path_for(keysfile_path: &Path) -> PathBuf {
    let mut name: OsString = keysfile_path.file_name().map(OsString::from).unwrap_or_else(|| OsString::from("keysfile"));
    name.push(".lock");
    keysfile_path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn second_acquire_against_same_keyfile_fails() {
        let tmp = TempDir::new().expect("tempdir");
        let keys_path = tmp.path().join("keys.json");
        std::fs::write(&keys_path, b"{}").expect("write keyfile");
        let _first = acquire(&keys_path).expect("first acquire succeeds");
        let err = match acquire(&keys_path) {
            Ok(_) => panic!("second acquire must fail"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(msg.contains("already in use"), "unexpected error: {msg}");
    }

    #[test]
    fn release_on_drop_permits_re_acquire() {
        let tmp = TempDir::new().expect("tempdir");
        let keys_path = tmp.path().join("keys.json");
        std::fs::write(&keys_path, b"{}").expect("write keyfile");
        {
            let _first = acquire(&keys_path).expect("first acquire succeeds");
        }
        let _second = acquire(&keys_path).expect("re-acquire succeeds after drop");
    }

    #[test]
    fn lock_path_appends_dot_lock() {
        let p = lock_path_for(Path::new("/tmp/x/keys.json"));
        assert_eq!(p, PathBuf::from("/tmp/x/keys.json.lock"));
    }
}
