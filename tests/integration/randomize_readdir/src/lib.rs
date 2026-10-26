// Copyright 2024 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This library implements a shim that randomizes the results of `readdir`
//! and `readdir64` for testing purposes. This is done by overriding the
//! POSIX calls associated with reading directories: `opendir`, `fdopendir`,
//! `readdir`, `readdir64`, and `closedir`.
//!
//! When `readdir` or `readdir64` is first invoked, the shim will read the
//! entire directory into a vector, shuffle it, and store iteration
//! state inside a custom `DirentIterator` structure. Note that we
//! assume that no new entries will be added to the directory while
//! iterating, to keep things simple. Also keep in mind that calls to
//! any of the directory reading operations can come from different
//! threads, so the library state has to be kept in thread safe types
//! where appropriate.
//!
//! Calls are dispatched to the "real" implementation in `libc` by using
//! `dlsym` with `RTLD_NEXT`. Unfortunately it seems that the usual libraries
//! for this like `libloading` do not support `RTLD_NEXT`, so these
//! functions are just invoked using unsafe calls.
//!
//! To use this library, set `LD_PRELOAD=path/to/librandomize_readdir.so`.
//! You can verify that the output is random by running for example
//! `LD_PRELOAD=path/to/librandomize_readdir.so ls -U`.
//!
//! To test `sccache` with `librandomize_readdir`, export `LD_PRELOAD` in
//! the integration test and then check that the second invocation
//! hits the cache. If not, something inside `sccache` relies implicitly
//! on the order that files are returned from the filesystem, which is
//! not defined, which is not ideal.

use ctor::ctor;
#[cfg(target_vendor = "apple")]
use libc::dirent as dirent64;
#[cfg(not(target_vendor = "apple"))]
use libc::dirent64;
use libc::{c_char, c_int, c_void, dirent, dlsym, DIR, RTLD_NEXT};
use log::{error, info};
use rand::seq::SliceRandom;
use rand::thread_rng;
use simplelog::{Config, LevelFilter, WriteLogger};
use std::collections::HashMap;
use std::env;
use std::ffi::CStr;
use std::fs::File;
use std::process;
use std::sync::{OnceLock, PoisonError, RwLock, RwLockWriteGuard};

type Opendir = unsafe extern "C" fn(dirname: *const c_char) -> *mut DIR;
type Fdopendir = unsafe extern "C" fn(fd: c_int) -> *mut DIR;
type Readdir = unsafe extern "C" fn(dirp: *mut DIR) -> *mut dirent;
type Readdir64 = unsafe extern "C" fn(dirp: *mut DIR) -> *mut dirent64;
type Closedir = unsafe extern "C" fn(dirp: *mut DIR) -> c_int;

struct DirentIterator<Dirent> {
    entries: Vec<Dirent>,
    index: usize,
}

impl<Dirent> Iterator for DirentIterator<Dirent> {
    type Item = *mut Dirent;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.entries.len() {
            return None;
        }

        let ptr = &mut self.entries[self.index];
        self.index += 1;
        Some(ptr)
    }
}

struct ReaddirState {
    iter: Option<DirentIterator<dirent>>,
    iter64: Option<DirentIterator<dirent64>>,
}

struct State {
    opendir: Opendir,
    fdopendir: Fdopendir,
    readdir: Readdir,
    readdir64: Readdir64,
    closedir: Closedir,

    dirs: RwLock<HashMap<usize, ReaddirState>>,
}

impl State {
    fn dirs_mut(&self) -> RwLockWriteGuard<'_, HashMap<usize, ReaddirState>> {
        self.dirs.write().unwrap_or_else(PoisonError::into_inner)
    }

    fn new_opendir(&self, dirp: *mut DIR) {
        self.dirs_mut().insert(
            dirp as usize,
            ReaddirState {
                iter: None,
                iter64: None,
            },
        );
    }

    unsafe fn wrapped_readdir_inner<Dirent, GetIter, Readdir>(
        &self,
        dirp: *mut DIR,
        get_iter: GetIter,
        readdir: Readdir,
    ) -> *mut Dirent
    where
        Dirent: Copy,
        GetIter: FnOnce(&mut ReaddirState) -> &mut Option<DirentIterator<Dirent>>,
        Readdir: Fn() -> *mut Dirent,
    {
        self.dirs_mut()
            .get_mut(&(dirp as usize))
            .and_then(|dirstate| {
                let iter = get_iter(dirstate);
                if iter.is_none() {
                    let mut entries = Vec::new();

                    loop {
                        let entry = readdir();
                        if entry.is_null() {
                            break;
                        }

                        // SAFETY: `readdir` returned a non-null pointer to a live dirent.
                        entries.push(unsafe { *entry });
                    }

                    entries.shuffle(&mut thread_rng());

                    *iter = Some(DirentIterator { entries, index: 0 });
                }

                let iter = iter.as_mut()?;
                info!(
                    "{dirp:p}: reading entry {}/{}",
                    iter.index,
                    iter.entries.len()
                );
                iter.next()
            })
            .unwrap_or(std::ptr::null_mut())
    }

    unsafe fn wrapped_readdir(&self, dirp: *mut DIR) -> *mut dirent {
        // SAFETY: this method inherits the caller guarantee that `dirp` is a live DIR*.
        unsafe {
            self.wrapped_readdir_inner(
                dirp,
                |dirstate| &mut dirstate.iter,
                || {
                    // SAFETY: `dirp` is the live directory handle supplied by the caller.
                    (self.readdir)(dirp)
                },
            )
        }
    }

    unsafe fn wrapped_readdir64(&self, dirp: *mut DIR) -> *mut dirent64 {
        // SAFETY: this method inherits the caller guarantee that `dirp` is a live DIR*.
        unsafe {
            self.wrapped_readdir_inner(
                dirp,
                |dirstate| &mut dirstate.iter64,
                || {
                    // SAFETY: `dirp` is the live directory handle supplied by the caller.
                    (self.readdir64)(dirp)
                },
            )
        }
    }
}

static STATE: OnceLock<State> = OnceLock::new();

unsafe fn load_next<Prototype: Copy>(name: &'static [u8]) -> Prototype {
    let name = match CStr::from_bytes_with_nul(name) {
        Ok(name) => name,
        Err(error) => {
            error!("invalid C string literal for libc symbol: {error}");
            process::abort();
        }
    };

    // SAFETY: `name` is a valid NUL-terminated symbol name and `RTLD_NEXT`
    // requests the next implementation in the dynamic linker search order.
    let sym = unsafe { dlsym(RTLD_NEXT, name.as_ptr()) };
    if sym.is_null() {
        error!("failed to load libc function {:?}", name.to_string_lossy());
        process::abort();
    }
    if std::mem::size_of::<Prototype>() != std::mem::size_of::<*mut c_void>() {
        error!("resolved libc symbol has an incompatible pointer size");
        process::abort();
    }

    // SAFETY: every call site supplies the exact function-pointer prototype
    // for the named libc symbol, and the size check above guarantees the
    // representation returned by `dlsym` fits in `Prototype`.
    unsafe { std::ptr::read((&raw const sym).cast::<Prototype>()) }
}

#[ctor]
fn init() {
    if let Ok(path) = env::var("RANDOMIZE_READDIR_LOG") {
        let pid = process::id();
        let path = format!("{path}.{pid}");
        match File::create(&path) {
            Ok(file) => {
                if let Err(error) = WriteLogger::init(LevelFilter::Info, Config::default(), file) {
                    eprintln!("failed to initialize randomize_readdir logger: {error}");
                }
            }
            Err(error) => eprintln!("failed to create randomize_readdir log {path}: {error}"),
        }
    }

    // Force loading on module init.
    // SAFETY: each symbol name is paired with its exact libc function-pointer ABI.
    let opendir = unsafe { load_next::<Opendir>(b"opendir\0") };
    // SAFETY: exact libc function-pointer ABI for fdopendir.
    let fdopendir = unsafe { load_next::<Fdopendir>(b"fdopendir\0") };
    // SAFETY: exact libc function-pointer ABI for readdir.
    let readdir = unsafe { load_next::<Readdir>(b"readdir\0") };
    // SAFETY: exact libc function-pointer ABI for readdir64.
    let readdir64 = unsafe { load_next::<Readdir64>(b"readdir64\0") };
    // SAFETY: exact libc function-pointer ABI for closedir.
    let closedir = unsafe { load_next::<Closedir>(b"closedir\0") };

    _ = STATE.get_or_init(|| State {
        opendir,
        fdopendir,
        readdir,
        readdir64,
        closedir,
        dirs: RwLock::new(HashMap::new()),
    });
}

/// Opens a directory stream for reading.
///
/// # Safety
///
/// This function is unsafe because:
/// - `dirname` must be a valid pointer to a null-terminated C string
/// - The caller is responsible for eventually closing the returned directory stream with `closedir`
#[no_mangle]
pub unsafe extern "C" fn opendir(dirname: *const c_char) -> *mut DIR {
    let state = STATE.wait();
    // SAFETY: callers must provide the same valid C string pointer required by libc's `opendir`.
    let dirp = unsafe { (state.opendir)(dirname) };

    info!(
        "{dirp:p}: opening directory '{}'",
        // SAFETY: this function's contract requires `dirname` to remain a valid NUL-terminated C string.
        unsafe { CStr::from_ptr(dirname) }.to_string_lossy()
    );

    if !dirp.is_null() {
        state.new_opendir(dirp);
    }

    dirp
}

/// Converts an open directory file descriptor into a directory stream.
///
/// # Safety
///
/// `dirfd` must be an open directory descriptor whose ownership may be
/// transferred to the returned stream; after success the caller must not close
/// or otherwise treat the original descriptor as independently owned.
#[no_mangle]
pub unsafe extern "C" fn fdopendir(dirfd: c_int) -> *mut DIR {
    let state = STATE.wait();
    // SAFETY: guaranteed by this exported function's descriptor-ownership contract.
    let dirp = unsafe { (state.fdopendir)(dirfd) };

    info!("{dirp:p}: opening directory fd {dirfd}");

    if !dirp.is_null() {
        state.new_opendir(dirp);
    }

    dirp
}

/// Reads the next directory entry.
///
/// # Safety
///
/// `dirp` must point to a live directory stream and must not be concurrently
/// closed while this call is in progress.
#[no_mangle]
pub unsafe extern "C" fn readdir(dirp: *mut DIR) -> *mut dirent {
    // SAFETY: guaranteed by this exported function's contract.
    unsafe { STATE.wait().wrapped_readdir(dirp) }
}

/// Reads the next directory entry using the 64-bit dirent ABI.
///
/// # Safety
///
/// `dirp` must point to a live directory stream and must not be concurrently
/// closed while this call is in progress.
#[no_mangle]
pub unsafe extern "C" fn readdir64(dirp: *mut DIR) -> *mut dirent64 {
    // SAFETY: guaranteed by this exported function's contract.
    unsafe { STATE.wait().wrapped_readdir64(dirp) }
}

/// Closes a directory stream.
///
/// # Safety
///
/// This function is unsafe because:
/// - `dirp` must be a valid pointer to a directory stream previously opened by `opendir`
/// - The directory stream must not be used after calling this function
#[no_mangle]
pub unsafe extern "C" fn closedir(dirp: *mut DIR) -> c_int {
    info!("{dirp:p}: closing handle");

    let state = STATE.wait();
    state.dirs_mut().remove(&(dirp as usize));

    // SAFETY: callers must provide the same live directory pointer required
    // by libc's `closedir`.
    unsafe { (state.closedir)(dirp) }
}
