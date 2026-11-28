//! Resolve named GNU/LLVM linker inputs in search order. This is discovery:
//! it never launches the linker or recursively inventories a library directory.
//! The caller supplies the path mapping and any already-declared virtual files.
use std::{
    collections::{BTreeSet, VecDeque},
    ffi::{OsStr, OsString},
    fs,
    io::Read,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum LibraryMode {
    #[default]
    Dynamic,
    Static,
}

#[derive(Debug, PartialEq, Eq)]
enum Operand {
    File(PathBuf),
    Library(OsString, LibraryMode),
    Script(PathBuf),
    OpaqueFile(PathBuf),
    SymbolsOrDirectory(PathBuf),
}

#[derive(Debug, Default)]
struct CommandInputs {
    search: Vec<PathBuf>,
    sysroot: Option<PathBuf>,
    operands: Vec<Operand>,
}

// GNU response files support backslash quoting and either quote style.
// Unlike a shell, '#' is not a comment delimiter and there is no expansion.
pub(super) fn response_words(bytes: &[u8]) -> Result<Vec<OsString>> {
    let mut result = Vec::new();
    let mut word = Vec::new();
    let mut started = false;
    let mut quote = None;
    let mut escaped = false;
    for &byte in bytes {
        if escaped {
            word.push(byte);
            escaped = false;
            started = true;
        } else if byte == b'\\' {
            escaped = true;
            started = true;
        } else if let Some(delimiter) = quote {
            if byte == delimiter {
                quote = None;
            } else {
                word.push(byte);
            }
        } else if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
            started = true;
        } else if byte.is_ascii_whitespace() {
            if started {
                result.push(OsString::from_vec(std::mem::take(&mut word)));
                started = false;
            }
        } else {
            word.push(byte);
            started = true;
        }
    }
    ensure!(
        !escaped && quote.is_none(),
        "unterminated linker response-file quoting"
    );
    if started {
        result.push(OsString::from_vec(word));
    }
    Ok(result)
}

pub(super) fn expand_response(
    words: impl IntoIterator<Item = OsString>,
    read: &mut impl FnMut(&Path) -> Result<Vec<u8>>,
    active: &mut BTreeSet<PathBuf>,
    files: &mut BTreeSet<PathBuf>,
    output: &mut Vec<OsString>,
) -> Result<()> {
    for word in words {
        if let Some(response) = word.as_bytes().strip_prefix(b"@").filter(|p| !p.is_empty()) {
            let path = PathBuf::from(OsString::from_vec(response.to_vec()));
            ensure!(
                active.insert(path.clone()),
                "recursive linker response file: {}",
                path.display()
            );
            files.insert(path.clone());
            let bytes =
                read(&path).with_context(|| format!("read linker response {}", path.display()))?;
            expand_response(response_words(&bytes)?, read, active, files, output)?;
            active.remove(&path);
        } else {
            output.push(word);
        }
    }
    Ok(())
}

fn value(
    arg: &[u8],
    long: &[u8],
    short: Option<&[u8]>,
    pending: &mut VecDeque<OsString>,
) -> Result<Option<OsString>> {
    if arg == long || short == Some(arg) {
        return pending
            .pop_front()
            .context("missing linker option operand")
            .map(Some);
    }
    if let Some(rest) = arg
        .strip_prefix(long)
        .and_then(|rest| rest.strip_prefix(b"="))
    {
        return Ok(Some(OsString::from_vec(rest.to_vec())));
    }
    Ok(short
        .and_then(|short| arg.strip_prefix(short))
        .filter(|rest| !rest.is_empty())
        .map(|rest| OsString::from_vec(rest.to_vec())))
}

impl CommandInputs {
    fn parse(words: Vec<OsString>) -> Result<Self> {
        let mut pending = VecDeque::from(words);
        let mut result = Self::default();
        let mut mode = LibraryMode::Dynamic;
        let mut states = Vec::new();
        let mut end_options = false;
        while let Some(word) = pending.pop_front() {
            let arg = word.as_bytes();
            if end_options || !arg.starts_with(b"-") || arg == b"-" {
                result.operands.push(Operand::File(PathBuf::from(word)));
            } else if arg == b"--" {
                end_options = true;
            } else if matches!(
                arg,
                b"-Bstatic" | b"-static" | b"--static" | b"-dn" | b"-non_shared"
            ) {
                mode = LibraryMode::Static;
            } else if matches!(arg, b"-Bdynamic" | b"-dy" | b"-call_shared") {
                mode = LibraryMode::Dynamic;
            } else if arg == b"--push-state" {
                states.push(mode);
            } else if arg == b"--pop-state" {
                mode = states.pop().context("unmatched linker --pop-state")?;
            } else if let Some(path) = value(arg, b"--library-path", Some(b"-L"), &mut pending)? {
                result.search.push(PathBuf::from(path));
            } else if let Some(path) = value(arg, b"--sysroot", None, &mut pending)? {
                result.sysroot = Some(PathBuf::from(path));
            } else if let Some(name) = value(arg, b"--library", Some(b"-l"), &mut pending)? {
                result.operands.push(Operand::Library(name, mode));
            } else if [
                b"-Ttext".as_slice(),
                b"-Ttext-segment",
                b"-Tdata",
                b"-Tbss",
                b"-Trodata-segment",
                b"-Tldata-segment",
            ]
            .iter()
            .any(|option| {
                arg == *option
                    || arg
                        .strip_prefix(*option)
                        .is_some_and(|rest| rest.starts_with(b"="))
            }) {
                if !arg.contains(&b'=') {
                    pending
                        .pop_front()
                        .context("missing linker segment address")?;
                }
            } else if let Some(path) = value(arg, b"--script", Some(b"-T"), &mut pending)? {
                result.operands.push(Operand::Script(PathBuf::from(path)));
            } else if let Some(path) = value(arg, b"--default-script", None, &mut pending)? {
                result.operands.push(Operand::Script(PathBuf::from(path)));
            } else if let Some(path) = value(arg, b"--just-symbols", Some(b"-R"), &mut pending)? {
                // GNU -R accepts either a file (symbols) or a directory (rpath).
                result
                    .operands
                    .push(Operand::SymbolsOrDirectory(PathBuf::from(path)));
            } else if let Some(option) = value(arg, b"--plugin-opt", None, &mut pending)?.or(value(
                arg,
                b"-plugin-opt",
                None,
                &mut pending,
            )?) {
                // A standalone absolute plugin argument is an executable
                // helper (e.g. GCC lto-wrapper), not a generated output.
                // Plugin-specific options require their own contract.
                if Path::new(&option).is_absolute() {
                    result
                        .operands
                        .push(Operand::OpaqueFile(PathBuf::from(option)));
                }
            } else {
                let mut consumed = false;
                for option in [
                    b"--version-script".as_slice(),
                    b"--dynamic-list",
                    b"--retain-symbols-file",
                    b"--symbol-ordering-file",
                    b"--section-ordering-file",
                    b"--call-graph-ordering-file",
                    b"--plugin",
                    b"-plugin",
                    b"--export-dynamic-symbol-list",
                ] {
                    if let Some(path) = value(arg, option, None, &mut pending)? {
                        result
                            .operands
                            .push(Operand::OpaqueFile(PathBuf::from(path)));
                        consumed = true;
                        break;
                    }
                }
                if consumed {
                    continue;
                }
                // Value-taking options that are not input files. Keep this
                // distinct from positional paths; an output might already exist.
                for (long, short) in [
                    (b"--output".as_slice(), Some(b"-o".as_slice())),
                    (b"--entry", Some(b"-e")),
                    (b"--undefined", Some(b"-u")),
                    (b"--emulation", Some(b"-m")),
                    (b"--oformat", None),
                    (b"--format", Some(b"-b")),
                    (b"--defsym", None),
                    (b"--dynamic-linker", Some(b"-I")),
                    (b"-dynamic-linker", None),
                    (b"--soname", Some(b"-h")),
                    (b"-soname", None),
                    (b"--rpath", None),
                    (b"-rpath", None),
                    (b"--rpath-link", None),
                    (b"-rpath-link", None),
                    (b"--Map", None),
                    (b"-Map", None),
                    (b"--dependency-file", None),
                    (b"--why-extract", None),
                    (b"--reproduce", None),
                    (b"--wrap", None),
                    (b"--hash-style", None),
                    (b"--exclude-libs", None),
                    (b"--orphan-handling", None),
                    (b"--compress-debug-sections", None),
                    (b"--sort-section", None),
                    (b"--unresolved-symbols", None),
                    (b"--error-limit", None),
                    (b"--threads", None),
                    (b"--image-base", None),
                    (b"--section-start", None),
                    (b"--fuse-ld", None),
                    (b"-fuse-ld", None),
                    (b"-z", None),
                ] {
                    if value(arg, long, short, &mut pending)?.is_some() {
                        break;
                    }
                }
            }
        }
        ensure!(states.is_empty(), "unbalanced linker state stack");
        Ok(result)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ScriptToken {
    Word(OsString),
    Open,
    Close,
    Separator,
}

// Input-list syntax is not shell syntax: punctuation and C-style comments
// delimit tokens. Quoted names can contain whitespace, commas and parentheses.
fn script_tokens(bytes: &[u8]) -> Result<VecDeque<ScriptToken>> {
    let mut tokens = VecDeque::new();
    let mut rest = bytes;
    while let Some((&first, tail)) = rest.split_first() {
        if first.is_ascii_whitespace() {
            rest = tail;
        } else if rest.starts_with(b"/*") {
            let end = rest[2..]
                .windows(2)
                .position(|pair| pair == b"*/")
                .context("unterminated linker script comment")?;
            rest = &rest[end + 4..];
        } else if matches!(first, b'(' | b')' | b',' | b';') {
            tokens.push_back(match first {
                b'(' => ScriptToken::Open,
                b')' => ScriptToken::Close,
                _ => ScriptToken::Separator,
            });
            rest = tail;
        } else if first == b'"' {
            let end = tail
                .iter()
                .position(|byte| *byte == b'"')
                .context("unterminated linker script string")?;
            tokens.push_back(ScriptToken::Word(OsString::from_vec(tail[..end].to_vec())));
            rest = &tail[end + 1..];
        } else {
            let end = rest
                .iter()
                .enumerate()
                .find_map(|(index, byte)| {
                    (byte.is_ascii_whitespace()
                        || matches!(*byte, b'(' | b')' | b',' | b';' | b'"')
                        || rest[index..].starts_with(b"/*"))
                    .then_some(index)
                })
                .unwrap_or(rest.len());
            ensure!(end > 0, "invalid linker script token");
            tokens.push_back(ScriptToken::Word(OsString::from_vec(rest[..end].to_vec())));
            rest = &rest[end..];
        }
    }
    Ok(tokens)
}

#[derive(Debug, PartialEq, Eq)]
enum ScriptInput {
    File(PathBuf),
    Library(OsString),
    Include(PathBuf),
    Search(PathBuf),
}

fn input_list(tokens: &mut VecDeque<ScriptToken>, output: &mut Vec<ScriptInput>) -> Result<()> {
    ensure!(
        tokens.pop_front() == Some(ScriptToken::Open),
        "missing linker script input list"
    );
    loop {
        match tokens
            .pop_front()
            .context("unterminated linker script input list")?
        {
            ScriptToken::Close => return Ok(()),
            ScriptToken::Separator => {}
            ScriptToken::Word(word) if word == "AS_NEEDED" => input_list(tokens, output)?,
            ScriptToken::Word(word) => {
                if let Some(name) = word.as_bytes().strip_prefix(b"-l") {
                    ensure!(!name.is_empty(), "empty linker script library");
                    output.push(ScriptInput::Library(OsString::from_vec(name.to_vec())));
                } else {
                    output.push(ScriptInput::File(PathBuf::from(word)));
                }
            }
            ScriptToken::Open => bail!("unexpected nested linker script input list"),
        }
    }
}

fn script_inputs(bytes: &[u8]) -> Result<Vec<ScriptInput>> {
    let mut tokens = script_tokens(bytes)?;
    let mut result = Vec::new();
    while let Some(token) = tokens.pop_front() {
        let ScriptToken::Word(word) = token else {
            continue;
        };
        match word.as_bytes() {
            b"INPUT" | b"GROUP" | b"STARTUP" if tokens.front() == Some(&ScriptToken::Open) => {
                input_list(&mut tokens, &mut result)?;
            }
            b"INCLUDE" => {
                let Some(ScriptToken::Word(path)) = tokens.pop_front() else {
                    bail!("missing linker script INCLUDE path");
                };
                result.push(ScriptInput::Include(PathBuf::from(path)));
            }
            b"SEARCH_DIR" if tokens.front() == Some(&ScriptToken::Open) => {
                tokens.pop_front();
                let Some(ScriptToken::Word(path)) = tokens.pop_front() else {
                    bail!("missing linker script SEARCH_DIR path");
                };
                ensure!(
                    tokens.pop_front() == Some(ScriptToken::Close),
                    "malformed SEARCH_DIR"
                );
                result.push(ScriptInput::Search(PathBuf::from(path)));
            }
            _ => {}
        }
    }
    Ok(result)
}

pub(super) fn default_search_paths(script: &[u8]) -> Result<Vec<PathBuf>> {
    Ok(script_inputs(script)?
        .into_iter()
        .filter_map(|input| match input {
            ScriptInput::Search(path) => Some(path),
            _ => None,
        })
        .collect())
}

/// Resolve a GNU-compatible link command in a caller-supplied logical
/// filesystem. Absent candidate paths are never captured. A subsequently
/// created higher-priority candidate changes the resolved path on the next
/// discovery; it does not depend on hashing the directory's contents.
pub(super) struct LinkClosure {
    pub files: BTreeSet<PathBuf>,
    pub directories: BTreeSet<PathBuf>,
}

struct Resolver<'a> {
    cwd: &'a Path,
    physical: &'a dyn Fn(&Path) -> Result<PathBuf>,
    virtual_file: &'a dyn Fn(&Path) -> bool,
    search: Vec<PathBuf>,
    sysroot: Option<PathBuf>,
    closure: LinkClosure,
    visited: BTreeSet<PathBuf>,
}

impl LinkClosure {
    pub(super) fn discover(
        words: Vec<OsString>,
        cwd: &Path,
        default_search: Vec<PathBuf>,
        physical: &dyn Fn(&Path) -> Result<PathBuf>,
        virtual_file: &dyn Fn(&Path) -> bool,
    ) -> Result<Self> {
        ensure!(cwd.is_absolute(), "linker cwd must be absolute");
        let mut response_files = BTreeSet::new();
        let mut expanded = Vec::new();
        expand_response(
            words,
            &mut |path| Ok(fs::read(physical(&cwd.join(path))?)?),
            &mut BTreeSet::new(),
            &mut response_files,
            &mut expanded,
        )?;
        let CommandInputs {
            search,
            sysroot,
            operands,
        } = CommandInputs::parse(expanded)?;
        let mut resolver = Resolver {
            cwd,
            physical,
            virtual_file,
            search: Vec::new(),
            sysroot,
            closure: Self {
                files: BTreeSet::new(),
                directories: BTreeSet::new(),
            },
            visited: BTreeSet::new(),
        };
        for directory in search.into_iter().chain(default_search) {
            resolver.add_search(directory)?;
        }
        for response in response_files {
            resolver.record(&cwd.join(response))?;
        }
        for operand in operands {
            match operand {
                Operand::File(path) => resolver.file(&path, None, LibraryMode::Dynamic, false)?,
                Operand::Script(path) => resolver.file(&path, None, LibraryMode::Dynamic, true)?,
                Operand::OpaqueFile(path) => {
                    let path = resolver.find(&path, None)?;
                    resolver.record(&path)?;
                }
                Operand::SymbolsOrDirectory(path) => {
                    if !(resolver.physical)(&resolver.cwd.join(&path))?.is_dir() {
                        resolver.file(&path, None, LibraryMode::Dynamic, false)?;
                    }
                }
                Operand::Library(name, mode) => resolver.library(&name, mode)?,
            }
        }
        Ok(resolver.closure)
    }
}

impl Resolver<'_> {
    fn add_search(&mut self, path: PathBuf) -> Result<()> {
        let bytes = path.as_os_str().as_bytes();
        let resolved = if let Some(rest) = bytes
            .strip_prefix(b"=")
            .or_else(|| bytes.strip_prefix(b"$SYSROOT"))
        {
            self.sysroot
                .as_deref()
                .unwrap_or(Path::new("/"))
                .join(OsStr::from_bytes(rest.strip_prefix(b"/").unwrap_or(rest)))
        } else {
            self.cwd.join(path)
        };
        if !self.search.contains(&resolved) {
            if (self.physical)(&resolved)?.is_dir() {
                self.closure.directories.insert(resolved.clone());
            }
            self.search.push(resolved);
        }
        Ok(())
    }

    fn exists(&self, path: &Path) -> Result<bool> {
        if (self.virtual_file)(path) {
            return Ok(true);
        }
        match fs::metadata((self.physical)(path)?) {
            Ok(metadata) => Ok(metadata.is_file()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn find(&self, path: &Path, script: Option<&Path>) -> Result<PathBuf> {
        if path.is_absolute() {
            if let (Some(script), Some(root)) = (script, &self.sysroot)
                && script.starts_with(root)
            {
                return Ok(root.join(path.strip_prefix("/")?));
            }
            return Ok(path.to_owned());
        }
        // GNU ld resolves INPUT and INCLUDE relative to cwd, then search
        // directories; the path of a thin archive member is handled separately.
        let local = self.cwd.join(path);
        if self.exists(&local)? {
            return Ok(local);
        }
        for directory in &self.search {
            let candidate = directory.join(path);
            if self.exists(&candidate)? {
                return Ok(candidate);
            }
        }
        bail!("linker input {} not found", path.display())
    }

    fn library(&mut self, name: &OsStr, mode: LibraryMode) -> Result<()> {
        let bytes = name.as_bytes();
        ensure!(!bytes.is_empty(), "empty linker library name");
        let names = if let Some(exact) = bytes.strip_prefix(b":") {
            vec![OsString::from_vec(exact.to_vec())]
        } else {
            let make =
                |suffix: &[u8]| OsString::from_vec([b"lib".as_slice(), bytes, suffix].concat());
            match mode {
                LibraryMode::Static => vec![make(b".a")],
                LibraryMode::Dynamic => vec![make(b".so"), make(b".a")],
            }
        };
        for directory in &self.search {
            for name in &names {
                let candidate = directory.join(name);
                if self.exists(&candidate)? {
                    return self.file(&candidate, None, mode, false);
                }
            }
        }
        bail!("linker library {} not found", name.to_string_lossy())
    }

    fn record(&mut self, path: &Path) -> Result<()> {
        if !(self.virtual_file)(path) {
            ensure!(
                self.exists(path)?,
                "missing linker input {}",
                path.display()
            );
            self.closure.files.insert(path.to_owned());
        }
        Ok(())
    }

    fn file(
        &mut self,
        path: &Path,
        script: Option<&Path>,
        mode: LibraryMode,
        force_script: bool,
    ) -> Result<()> {
        let path = self.find(path, script)?;
        if (self.virtual_file)(&path) {
            return Ok(());
        }
        let physical = (self.physical)(&path)?;
        if physical.is_dir() {
            // -R can specify a runtime directory rather than an input file.
            return Ok(());
        }
        self.record(&path)?;
        if !self.visited.insert(path.clone()) {
            return Ok(());
        }
        let mut prefix = Vec::new();
        fs::File::open(&physical)?
            .take(64)
            .read_to_end(&mut prefix)?;
        if !force_script {
            if prefix.starts_with(b"!<thin>\n") {
                let bytes = fs::read(&physical)?;
                let archive = object::read::archive::ArchiveFile::parse(bytes.as_slice())?;
                for member in archive.members() {
                    let member = member?;
                    ensure!(
                        member.is_thin(),
                        "unexpected embedded member in thin archive"
                    );
                    let target = path
                        .parent()
                        .context("thin archive has no parent")?
                        .join(OsStr::from_bytes(member.name()));
                    self.file(&target, None, mode, false)?;
                }
                return Ok(());
            }
            if prefix.starts_with(b"\x7fELF")
                || prefix.starts_with(b"!<arch>\n")
                || prefix.starts_with(b"BC\xc0\xde")
                || prefix.starts_with(b"\xde\xc0\x17\x0b")
                || prefix.starts_with(b"\0asm")
                || object::FileKind::parse(prefix.as_slice()).is_ok()
            {
                return Ok(());
            }
        }
        let bytes = fs::read(&physical)?;
        for input in script_inputs(&bytes)? {
            match input {
                ScriptInput::File(input) => self.file(&input, Some(&path), mode, false)?,
                ScriptInput::Include(input) => self.file(&input, Some(&path), mode, true)?,
                ScriptInput::Library(name) => self.library(&name, mode)?,
                ScriptInput::Search(directory) => self.add_search(directory)?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn response_syntax_preserves_bytes_and_literal_hash() -> Result<()> {
        assert_eq!(
            response_words(b"one 'two three' \"four five\" six\\ seven #hash '' \xff")?,
            [
                b"one".as_slice(),
                b"two three",
                b"four five",
                b"six seven",
                b"#hash",
                b"",
                b"\xff"
            ]
            .map(|v| OsString::from_vec(v.to_vec()))
        );
        assert!(response_words(b"unterminated'").is_err());
        Ok(())
    }

    #[test]
    fn selected_libraries_only_and_recursive_scripts() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        for name in ["first", "second", "script"] {
            fs::create_dir(root.join(name))?;
        }
        let elf = b"\x7fELF\0\0\0\0";
        let archive = b"!<arch>\n";
        fs::write(root.join("first/libwanted.a"), archive)?;
        fs::write(root.join("second/libwanted.so"), elf)?;
        fs::write(root.join("second/libunrelated.a"), archive)?;
        fs::write(root.join("script/real.so"), elf)?;
        fs::write(root.join("script/other.a"), archive)?;
        fs::write(root.join("script/with space.a"), archive)?;
        fs::write(root.join("first/libscript.so"), b"/* GROUP ( ignored ) */ GROUP ( script/real.so AS_NEEDED ( script/other.a ) ) INCLUDE script/more.ld")?;
        fs::write(
            root.join("script/more.ld"),
            b"INPUT ( \"script/with space.a\" )",
        )?;
        fs::write(
            root.join("args.rsp"),
            b"-Lfirst -Lsecond -lwanted -lscript -o existing",
        )?;
        fs::write(root.join("existing"), b"old output")?;
        let discover = || {
            LinkClosure::discover(
                words(&["@args.rsp"]),
                root,
                Vec::new(),
                &|p| Ok(p.to_owned()),
                &|_| false,
            )
        };
        let first = discover()?;
        let expected = [
            "args.rsp",
            "first/libwanted.a",
            "first/libscript.so",
            "script/real.so",
            "script/other.a",
            "script/more.ld",
            "script/with space.a",
        ]
        .map(|name| root.join(name))
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(first.files, expected);
        fs::write(root.join("second/libunrelated.a"), b"changed")?;
        assert_eq!(discover()?.files, expected);
        fs::write(root.join("first/libwanted.so"), elf)?;
        let changed = discover()?;
        assert!(changed.files.contains(&root.join("first/libwanted.so")));
        assert!(!changed.files.contains(&root.join("first/libwanted.a")));
        Ok(())
    }

    #[test]
    fn static_state_and_exact_library_name() -> Result<()> {
        let inputs = CommandInputs::parse(words(&[
            "-L",
            "a",
            "--push-state",
            "-Bstatic",
            "-lfoo",
            "--pop-state",
            "-l:bar.so",
            "-z",
            "now",
            "-o",
            "ignored",
            "object.o",
        ]))?;
        assert_eq!(inputs.search, [PathBuf::from("a")]);
        assert_eq!(
            inputs.operands,
            [
                Operand::Library("foo".into(), LibraryMode::Static),
                Operand::Library(":bar.so".into(), LibraryMode::Dynamic),
                Operand::File("object.o".into())
            ]
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires installed GNU/LLVM linker and a C runtime startup object"]
    fn dependency_closure_matches_real_linker() -> Result<()> {
        use std::process::Command;
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        for name in ["first", "second", "script"] {
            fs::create_dir(root.join(name))?;
        }
        let crt = Command::new("cc").arg("-print-file-name=crti.o").output()?;
        ensure!(crt.status.success(), "C runtime discovery failed");
        fs::copy(
            Path::new(std::str::from_utf8(&crt.stdout)?.trim()),
            root.join("probe.o"),
        )?;
        for name in ["first/libfoo.a", "second/libfoo.a", "script/nested.a"] {
            fs::write(root.join(name), b"!<arch>\n")?;
        }
        fs::write(root.join("script/outer.ld"), b"GROUP ( script/nested.a )")?;
        let mut args = words(&[
            "-r",
            "-Lfirst",
            "-Lsecond",
            "-lfoo",
            "-T",
            "script/outer.ld",
            "-o",
            "result.o",
            "probe.o",
        ]);
        args.push("--dependency-file=dependencies".into());
        let closure = LinkClosure::discover(
            args.clone(),
            root,
            Vec::new(),
            &|path| Ok(path.to_owned()),
            &|_| false,
        )?;
        assert_eq!(
            closure.directories,
            [root.join("first"), root.join("second")]
                .into_iter()
                .collect()
        );
        for linker in ["/usr/bin/ld", "/usr/bin/ld.lld"] {
            if !Path::new(linker).exists() {
                continue;
            }
            let output = Command::new(linker)
                .current_dir(root)
                .args(&args)
                .output()?;
            ensure!(
                output.status.success(),
                "{linker}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let dependencies = fs::read_to_string(root.join("dependencies"))?;
            let first_rule = dependencies
                .split("\n\n")
                .next()
                .context("missing dependency rule")?;
            let (_, dependencies) = first_rule
                .split_once(':')
                .context("missing dependency separator")?;
            let observed = dependencies
                .split_whitespace()
                .filter(|word| *word != "\\")
                .map(|word| root.join(word))
                .collect::<BTreeSet<_>>();
            assert_eq!(closure.files, observed, "{linker}");
        }
        Ok(())
    }

    #[test]
    #[ignore = "requires ar and C runtime startup object"]
    fn thin_archive_references_are_part_of_the_closure() -> Result<()> {
        use std::process::Command;
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        fs::create_dir(root.join("objects"))?;
        let crt = Command::new("cc").arg("-print-file-name=crti.o").output()?;
        ensure!(crt.status.success(), "C runtime discovery failed");
        fs::copy(
            Path::new(std::str::from_utf8(&crt.stdout)?.trim()),
            root.join("objects/member.o"),
        )?;
        let archive = Command::new("ar")
            .current_dir(root)
            .args(["crsT", "libthin.a", "objects/member.o"])
            .output()?;
        ensure!(archive.status.success(), "create thin archive");
        let closure = LinkClosure::discover(
            words(&["libthin.a"]),
            root,
            Vec::new(),
            &|p| Ok(p.to_owned()),
            &|_| false,
        )?;
        assert_eq!(
            closure.files,
            [root.join("libthin.a"), root.join("objects/member.o")]
                .into_iter()
                .collect()
        );
        Ok(())
    }

    #[test]
    fn nested_response_cycles_are_rejected() -> Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("a"), b"@b")?;
        fs::write(dir.path().join("b"), b"@a")?;
        assert!(
            LinkClosure::discover(
                words(&["@a"]),
                dir.path(),
                Vec::new(),
                &|p| Ok(p.to_owned()),
                &|_| false
            )
            .is_err()
        );
        Ok(())
    }
}
