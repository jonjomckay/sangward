//! Process and socket hardening for the agent.
#![allow(unsafe_code)]

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;

/// Disable core dumps and ptrace-attach by non-root same-UID processes.
pub fn harden_process() {
    // SAFETY: plain syscalls with constant, valid arguments.
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            tracing::warn!(
                "prctl(PR_SET_DUMPABLE, 0) failed: {}",
                io::Error::last_os_error()
            );
        }
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &zero) != 0 {
            tracing::warn!(
                "setrlimit(RLIMIT_CORE, 0) failed: {}",
                io::Error::last_os_error()
            );
        }
    }
}

pub fn current_uid() -> u32 {
    // SAFETY: getuid cannot fail.
    unsafe { libc::getuid() }
}

pub fn is_dumpable() -> bool {
    // SAFETY: PR_GET_DUMPABLE takes no pointer arguments.
    unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) == 1 }
}

/// Peer-credential policy: only the agent's own UID may talk to it.
pub fn peer_allowed(peer_uid: u32, our_uid: u32) -> bool {
    peer_uid == our_uid
}

/// Create the socket directory with 0700 and verify we own it.
pub fn prepare_socket_dir(dir: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(io::Error::other(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    if meta.uid() != current_uid() {
        return Err(io::Error::other(format!(
            "{} is owned by another user",
            dir.display()
        )));
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_uid_policy() {
        assert!(peer_allowed(1000, 1000));
        assert!(!peer_allowed(0, 1000));
        assert!(!peer_allowed(1001, 1000));
    }

    #[test]
    fn socket_dir_is_0700() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("keyward");
        fs::create_dir(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        prepare_socket_dir(&d).unwrap();
        assert_eq!(
            fs::metadata(&d).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}
