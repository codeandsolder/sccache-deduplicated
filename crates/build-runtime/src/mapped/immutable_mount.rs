//! Recognize immutable ZFS snapshot files through the kernel, not path names,
//! mountinfo supplied by an executor, or a read-only bind mount.
use std::{fs::File, os::fd::AsRawFd};

use linux_raw_sys::general::{
    __NR_statmount, STATMOUNT_MNT_BASIC, STATMOUNT_SB_BASIC, STATMOUNT_SB_SOURCE, mnt_id_req,
    statmount,
};

const ZFS_MAGIC: u64 = 0x2fc1_2fc1;
const SB_RDONLY: u32 = 1;
// Linux added descriptor-based statmount after the initial UAPI release.
// Old kernels return EINVAL/ENOSYS and simply use ordinary byte hashing.
const STATMOUNT_BY_FD: u32 = 1;
const REQUEST: u64 = (STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC | STATMOUNT_SB_SOURCE) as u64;

#[repr(C)]
struct MountInfo {
    header: statmount,
    strings: [u8; 4096],
}

impl MountInfo {
    fn snapshot_mount(&self) -> Option<u64> {
        let header = &self.header;
        if header.mask & REQUEST != REQUEST
            || header.sb_magic != ZFS_MAGIC
            || header.sb_flags & SB_RDONLY == 0
            || header.mnt_id == 0
        {
            return None;
        }
        let length = usize::try_from(header.size)
            .ok()?
            .checked_sub(size_of::<statmount>())?;
        let strings = self.strings.get(..length)?;
        let source = strings.get(usize::try_from(header.sb_source).ok()?..)?;
        let source = source.get(..source.iter().position(|&b| b == 0)?)?;
        // A ZFS mount's kernel-reported source is dataset@snapshot.
        // An ordinary ZFS dataset cannot have '@' in its name. Requiring
        // superblock read-only also rejects mutable bind/remount views.
        let separator = source.iter().position(|&b| b == b'@')?;
        if separator == 0
            || separator + 1 == source.len()
            || source[separator + 1..].contains(&b'@')
        {
            return None;
        }
        Some(header.mnt_id)
    }
}

pub(super) fn zfs_snapshot_mount(file: &File) -> Option<u64> {
    let fs = rustix::fs::fstatfs(file).ok()?;
    if fs.f_type as u64 != ZFS_MAGIC {
        return None;
    }
    let request = mnt_id_req {
        size: u32::try_from(size_of::<mnt_id_req>()).ok()?,
        spare: u32::try_from(file.as_raw_fd()).ok()?,
        mnt_id: 0,
        param: REQUEST,
        mnt_ns_id: 0,
    };
    // SAFETY: all fields of statmount and its trailing byte array accept
    // zero; the UAPI writes at most the explicitly supplied buffer length.
    let mut info: MountInfo = unsafe { std::mem::zeroed() };
    // SAFETY: the live fd is in request, and the pointers refer to correctly
    // aligned, initialized UAPI structures for the duration of this syscall.
    let status = unsafe {
        libc::syscall(
            libc::c_long::from(__NR_statmount),
            &raw const request,
            &raw mut info,
            size_of::<MountInfo>(),
            STATMOUNT_BY_FD,
        )
    };
    if status != 0 {
        return None;
    }
    info.snapshot_mount()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(source: &[u8]) -> MountInfo {
        // SAFETY: integer fields and bytes accept zero.
        let mut info: MountInfo = unsafe { std::mem::zeroed() };
        info.header.size = u32::try_from(size_of::<statmount>() + source.len() + 1).unwrap();
        info.header.mask = REQUEST;
        info.header.sb_magic = ZFS_MAGIC;
        info.header.sb_flags = SB_RDONLY;
        info.header.mnt_id = 123456;
        info.strings[..source.len()].copy_from_slice(source);
        info
    }

    #[test]
    fn only_read_only_zfs_snapshot_superblocks_qualify() {
        let mut info = response(b"pool/dataset@snapshot");
        assert_eq!(info.snapshot_mount(), Some(123456));
        info.header.sb_flags = 0;
        assert_eq!(info.snapshot_mount(), None);
        assert_eq!(response(b"pool/dataset").snapshot_mount(), None);
        assert_eq!(response(b"pool/dataset@").snapshot_mount(), None);
        assert_eq!(response(b"@snapshot").snapshot_mount(), None);
        let mut info = response(b"pool/dataset@snapshot");
        info.header.mask &= !u64::from(STATMOUNT_SB_SOURCE);
        assert_eq!(info.snapshot_mount(), None);
        let mut info = response(b"pool/dataset@snapshot");
        info.header.sb_source = 4096;
        assert_eq!(info.snapshot_mount(), None);
    }
}
