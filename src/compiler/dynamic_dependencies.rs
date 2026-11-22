//! Discover ELF runtime libraries using the actual dynamic loader.
use crate::errors::{Context, Result, bail};
use fs_err as fs;
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process, str,
};

// The dynamic linker is the only thing that truly knows how dynamic libraries will be
// searched for, so we need to ask it directly.
//
// This function will extract any absolute paths from output like the following:
// $ ldd /bin/ls
//         linux-vdso.so.1 =>  (0x00007ffeb41f6000)
//         libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f6877f4f000)
//         libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f6877b85000)
//         libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f6877915000)
//         libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f6877711000)
//         /lib64/ld-linux-x86-64.so.2 (0x00007f6878171000)
//         libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f68774f4000)
//
// Elf executables can be statically or dynamically linked, and position independent (PIE) or not:
// - dynamic + PIE = ET_DYN, ldd stdouts something like the list above and exits with code 0
// - dynamic + non-PIE = ET_EXEC, ldd stdouts something like the list above and exits with code 0
// - static + PIE = ET_DYN, ldd stdouts something like "\tstatically linked" or
//   "\tldd (0x7f79ef662000)" and exits with code 0
// - static + non-PIE = ET_EXEC, ldd stderrs something like "\tnot a dynamic executable" or
//   "ldd: a.out: Not a valid dynamic program" and exits with code 1
//
pub(crate) fn find_ldd_libraries(
    executable: &Path,
    environment: Option<&[(OsString, OsString)]>,
) -> Result<Vec<PathBuf>> {
    let mut command = process::Command::new(which::which("ldd")?);
    if let Some(environment) = environment {
        command.env_clear().envs(environment.iter().cloned());
    }
    let process::Output {
        status,
        stdout,
        stderr,
    } = command
        .arg(executable)
        // The probe requires EOF, not a device node. A namespace may
        // have a restricted /dev even when compiler execution works.
        .stdin(process::Stdio::piped())
        .output()
        .context("could not execute dynamic dependency probe")?;

    let stdout = str::from_utf8(&stdout).context("ldd output not utf8")?;
    if stdout
        .lines()
        .any(|line| line.trim_end().ends_with("=> not found"))
    {
        bail!("unresolved dynamic dependency for {}", executable.display());
    }
    if !status.success() {
        // Only accept a genuine static executable, not a dynamic ET_EXEC
        // whose interpreter or libraries could not be loaded.
        use object::{Object, ObjectKind};
        let bytes = fs::read(executable)?;
        let elf = object::File::parse(bytes.as_slice())?;
        if elf.format() != object::BinaryFormat::Elf
            || elf.kind() != ObjectKind::Executable
            || elf.imports()?.next().is_some()
        {
            bail!(
                "dynamic dependency discovery failed for {}",
                executable.display()
            );
        }
        // An executable without imported symbols can still have PT_INTERP.
        // Check the actual ELF program headers rather than section names.
        use object::read::elf::ProgramHeader;
        let has_interpreter = match elf {
            object::File::Elf32(file) => file
                .elf_program_headers()
                .iter()
                .any(|header| header.p_type(file.endian()) == object::elf::PT_INTERP),
            object::File::Elf64(file) => file
                .elf_program_headers()
                .iter()
                .any(|header| header.p_type(file.endian()) == object::elf::PT_INTERP),
            _ => true,
        };
        if has_interpreter {
            bail!(
                "dynamic interpreter discovery failed for {}",
                executable.display()
            );
        }
        return Ok(Vec::new());
    }

    if !stderr.is_empty() {
        trace!(
            "ldd stderr non-empty: {:?}",
            String::from_utf8_lossy(&stderr)
        );
    }

    Ok(parse_ldd_output(stdout))
}

// If it's a static PIE the output will be a line like "\tstatically linked", so be forgiving
// in the parsing here and treat parsing oddities as an empty list.
fn parse_ldd_output(stdout: &str) -> Vec<PathBuf> {
    let mut libs = vec![];
    for line in stdout.lines() {
        let Some((entry, address)) = line.trim().rsplit_once(" (") else {
            continue;
        };
        if !address.ends_with(')') {
            continue;
        }
        let path = if let Some((name, resolved)) = entry.split_once(" =>") {
            let original = PathBuf::from(name.trim());
            if original.is_absolute() {
                libs.push(original);
            }
            PathBuf::from(resolved.trim())
        } else {
            PathBuf::from(entry.trim())
        };
        if path.is_absolute() {
            libs.push(path);
        }
    }

    libs
}

#[test]
fn test_ldd_parse() {
    let ubuntu_ls_output = "\tlinux-vdso.so.1 =>  (0x00007fffcfffe000)
\tlibselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f69caa6b000)
\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f69ca6a1000)
\tlibpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f69ca431000)
\tlibdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f69ca22d000)
\t/lib64/ld-linux-x86-64.so.2 (0x00007f69cac8d000)
\tlibpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f69ca010000)
";
    assert_eq!(
        parse_ldd_output(ubuntu_ls_output),
        vec![
            PathBuf::from("/lib/x86_64-linux-gnu/libselinux.so.1"),
            PathBuf::from("/lib/x86_64-linux-gnu/libc.so.6"),
            PathBuf::from("/lib/x86_64-linux-gnu/libpcre.so.3"),
            PathBuf::from("/lib/x86_64-linux-gnu/libdl.so.2"),
            PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
            PathBuf::from("/lib/x86_64-linux-gnu/libpthread.so.0"),
        ]
    );
}

#[test]
fn test_ldd_parse_static() {
    let static_outputs = &[
        "\tstatically linked",    // glibc ldd output
        "\tldd (0x7f79ef662000)", // musl ldd output
    ];
    for static_output in static_outputs {
        assert_eq!(parse_ldd_output(static_output).len(), 0);
    }
}

#[test]
fn test_ldd_parse_v2_30() {
    let archlinux_ls_output = "\tlinux-vdso.so.1 (0x00007ffddc1f6000)
\tlibcap.so.2 => /usr/lib/libcap.so.2 (0x00007f4980989000)
\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f69ca6a1000)
\tlibc.so.6 => /usr/lib/libc.so.6 (0x00007f49807c2000)
\t/lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007f49809e9000)
";
    assert_eq!(
        parse_ldd_output(archlinux_ls_output),
        vec![
            PathBuf::from("/usr/lib/libcap.so.2"),
            PathBuf::from("/lib/x86_64-linux-gnu/libc.so.6"),
            PathBuf::from("/usr/lib/libc.so.6"),
            PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
            PathBuf::from("/usr/lib64/ld-linux-x86-64.so.2"),
        ]
    );
}

#[test]
fn test_ldd_paths_with_spaces() {
    assert_eq!(
        parse_ldd_output("libexample.so => /private tool/libexample.so (0x123)\n"),
        vec![PathBuf::from("/private tool/libexample.so")]
    );
}
