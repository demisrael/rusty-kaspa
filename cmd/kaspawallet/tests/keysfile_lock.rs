//! Integration test for the exclusive keyfile lock the daemon
//! acquires in `start_daemon`. Two acquisitions against the same
//! keyfile path must fail the second one.
//!
//! This integration test exists alongside the in-crate unit tests
//! in `daemon::keysfile_lock::tests` so the public guarantee
//! (`fd-lock` integration through `acquire` works at the
//! crate-boundary) is exercised through the same surface a future
//! standalone CLI invocation of `start-daemon` would.

use std::thread;

use tempfile::TempDir;

use kaspawallet::daemon::keysfile_lock;

#[test]
fn two_daemons_one_keyfile_second_acquire_fails() {
    let tmp = TempDir::new().expect("tempdir");
    let keys_path = tmp.path().join("keys.json");
    std::fs::write(&keys_path, b"{}").expect("write keyfile");

    let first = keysfile_lock::acquire(&keys_path).expect("first daemon acquires lock");

    let err = match keysfile_lock::acquire(&keys_path) {
        Ok(_) => panic!("second daemon must fail to acquire the same keyfile lock"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(msg.contains("already in use"), "second-acquire error must name the conflict: {msg}");

    // Releasing the first guard MUST allow re-acquisition; this
    // proves the lock is held for the daemon's lifetime and
    // releases cleanly on shutdown (drop-equivalent semantics in
    // the `start_daemon` early-return paths).
    drop(first);
    let _second = keysfile_lock::acquire(&keys_path).expect("re-acquire after release succeeds");
}

#[test]
fn cross_thread_second_acquire_fails() {
    let tmp = TempDir::new().expect("tempdir");
    let keys_path = tmp.path().join("keys.json");
    std::fs::write(&keys_path, b"{}").expect("write keyfile");
    let _first = keysfile_lock::acquire(&keys_path).expect("primary thread acquires");

    let path_clone = keys_path.clone();
    let handle = thread::spawn(move || keysfile_lock::acquire(&path_clone));
    let result = handle.join().expect("worker thread did not panic");
    let err = match result {
        Ok(_) => panic!("second-thread acquire must fail while primary thread holds the lock"),
        Err(e) => e,
    };
    assert!(format!("{err}").contains("already in use"));
}
