//! Native-CAS end-to-end compilation benchmark with a real installed Clang.
//!
//! Run on a Linux host with ZFS, Bubblewrap, Clang and an available /dev/shm:
//! ```sh
//! cargo +stable run -p sccache-build --example native_realbuild_arc --release -- \
//!   /zfs/benchmark-parent /dev/shm /usr/bin/clang /usr/bin/bwrap
//! ```
//!
//! The generated translation unit uses hundreds of separately imported C
//! headers; the compiler and actual dynamic loader/library closure are copied
//! into a CAS root. Results are compared byte-for-byte with host compilation.
//! Numbers are warm observations, not a controlled ARC-cold experiment.

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fmt::Write as _,
        fs,
        io::Read,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::Command,
        time::{Duration, Instant},
    };

    use anyhow::{Context, Result, ensure};
    use sccache_build::{
        BuildPath, CommandSpec, ContentId, ExecutionPolicy, ExecutionRoot, ExecutionSpec,
        NativeStore, OutputSpec, TreeEntry, TreeManifest, TreeMetadata, TreePath, TreeRecipe,
        TreeTimestamp, execute,
    };

    const HEADER_COUNT: usize = 384;
    const REPETITIONS: usize = 7;

    fn make_input(root: &Path, compiler: &Path) -> Result<()> {
        for name in ["bin", "dev", "proc", "tmp", "src", "out"] {
            fs::create_dir_all(root.join(name))?;
        }

        ensure!(compiler.is_file(), "selected Clang binary not found");
        fs::copy(compiler, root.join("bin/clang"))?;
        fs::set_permissions(root.join("bin/clang"), fs::Permissions::from_mode(0o755))?;

        let result = Command::new("ldd").arg(compiler).output()?;
        ensure!(result.status.success(), "ldd failed for installed Clang");
        let output = String::from_utf8(result.stdout)?;
        let mut library_paths = BTreeSet::new();
        for line in output.lines() {
            if let Some(name) = line.split_whitespace().find(|item| item.starts_with('/')) {
                library_paths.insert(PathBuf::from(name));
            }
        }
        ensure!(
            library_paths.len() >= 5,
            "Clang's ELF dependency closure was incomplete"
        );
        for library in &library_paths {
            let relative = library.strip_prefix("/")?;
            let dest = root.join(relative);
            fs::create_dir_all(dest.parent().context("library parent")?)?;
            fs::copy(library, dest)?;
        }

        let mut source = String::new();
        for index in 0..HEADER_COUNT {
            let name = format!("header_{index:04}.h");
            writeln!(source, "#include \"{name}\"")?;
            fs::write(
                root.join("src").join(name),
                format!(
                    "static inline unsigned mix_{index}(unsigned v) {{ v ^= v >> 7; return (v * 1664525u + {index}u + 1013904223u) ^ (v << 5); }}\n"
                ),
            )?;
        }
        // A stable generated include is also used in the structural-delta
        // benchmark below. Replacing it with a symlink to byte-identical
        // generated headers must leave the compiled object unchanged.
        fs::create_dir_all(root.join("src/aux"))?;
        fs::write(
            root.join("src/aux/selected.h"),
            b"/* generated stable header */\n",
        )?;
        source.push_str("#include \"aux/selected.h\"\n");
        source.push_str("unsigned compiled_kernel(unsigned seed) { unsigned v = seed;\n");
        for index in 0..HEADER_COUNT {
            writeln!(source, "v = mix_{index}(v);")?;
        }
        source.push_str("return v; }\n");
        fs::write(root.join("src/input.c"), source)?;
        println!(
            "corpus=clang-cc1-c-headers headers={HEADER_COUNT} dynamic_libs={} code={}",
            library_paths.len(),
            fs::metadata(root.join("src/input.c"))?.len()
        );
        Ok(())
    }

    #[derive(Clone, Copy)]
    struct ArcCounters {
        hits: u64,
        misses: u64,
        size: u64,
        compressed: u64,
    }

    fn arc() -> Result<ArcCounters> {
        let text = fs::read_to_string("/proc/spl/kstat/zfs/arcstats")?;
        let metric = |name: &str| -> Result<u64> {
            let line = text
                .lines()
                .find(|line| line.split_whitespace().next() == Some(name))
                .context("ZFS ARC metric missing")?;
            line.split_whitespace()
                .nth(2)
                .context("ZFS ARC metric missing value")?
                .parse()
                .map_err(Into::into)
        };
        Ok(ArcCounters {
            hits: metric("hits")?,
            misses: metric("misses")?,
            size: metric("size")?,
            compressed: metric("compressed_size")?,
        })
    }

    fn emit(
        backend: &str,
        iteration: usize,
        duration: Duration,
        before: ArcCounters,
        after: ArcCounters,
    ) {
        println!(
            "RUN backend={backend} iteration={iteration} wall_us={} arc_hits={} arc_misses={} arc_size={} arc_compressed_size={}",
            duration.as_micros(),
            after.hits.saturating_sub(before.hits),
            after.misses.saturating_sub(before.misses),
            after.size,
            after.compressed
        );
    }

    fn run_host(root: &Path, compiler: &Path) -> Result<Vec<u8>> {
        let src = root.join("src/input.c");
        let output = root.join("out/host.o");
        let mut reference = None;
        for index in 0..REPETITIONS {
            let before = arc()?;
            let started = Instant::now();
            let status = Command::new(compiler)
                .args(["-cc1", "-emit-obj", "-O2", "-x", "c", "-o"])
                .arg(&output)
                .arg(&src)
                .status()?;
            let elapsed = started.elapsed();
            ensure!(status.success(), "host compiler failed");
            let bytes = fs::read(&output)?;
            if let Some(first) = &reference {
                ensure!(
                    first == &bytes,
                    "host compiler produced inconsistent outputs"
                );
            } else {
                reference = Some(bytes);
            }
            emit("host", index, elapsed, before, arc()?);
        }
        reference.context("missing host compilation")
    }

    fn compile_spec(
        root: sccache_build::TreeId,
        recipe: TreeRecipe,
        platform: ContentId,
    ) -> Result<ExecutionSpec> {
        Ok(ExecutionSpec {
            platform,
            root: ExecutionRoot { id: root, recipe },
            mounts: BTreeMap::new(),
            command: CommandSpec {
                executable: BuildPath::new(b"/bin/clang".to_vec())?,
                arguments: [
                    b"-cc1".as_slice(),
                    b"-emit-obj",
                    b"-O2",
                    b"-x",
                    b"c",
                    b"-o",
                    b"/out/result.o",
                    b"/src/input.c",
                ]
                .iter()
                .map(|arg| arg.to_vec())
                .collect(),
                cwd: BuildPath::new(b"/src".to_vec())?,
                environment: BTreeMap::new(),
            },
            outputs: BTreeMap::from([(
                "obj".into(),
                OutputSpec {
                    path: BuildPath::new(b"/out/result.o".to_vec())?,
                    required: true,
                },
            )]),
        })
    }

    fn run_cas(
        backend: &str,
        root: &Path,
        temp_root: &Path,
        compiler_sandbox: &Path,
        reference: &[u8],
    ) -> Result<()> {
        let store_directory = temp_root.join("store");
        let started = Instant::now();
        let store = NativeStore::open(&store_directory)?;
        let tree = store.capture_tree(root)?;
        ensure!(
            match backend {
                "zfs" => store.physical_encoding() == sccache_build::BlobEncoding::Raw,
                "nonzfs" => store.physical_encoding() == sccache_build::BlobEncoding::ZstdChunks,
                _ => anyhow::bail!("unrecognized benchmark filesystem backend"),
            },
            "benchmark parent has the wrong filesystem backend"
        );
        let captured = started.elapsed();
        println!(
            "IMPORT backend={backend} wall_us={} files={} logical_bytes={} stored_as={:?}",
            captured.as_micros(),
            tree.manifest().entries.len(),
            store.stats()?.logical_bytes,
            store.physical_encoding(),
        );

        let platform = ContentId::of(b"native-cas-clang-cc1-benchmark");
        let recipe = TreeRecipe::union(
            TreeMetadata {
                mode: 0o755,
                modified: TreeTimestamp {
                    seconds: 1,
                    nanoseconds: 0,
                },
            },
            [tree.id()],
        );
        let composed = store.lease_recipe(&recipe)?.id();
        let spec = compile_spec(composed, recipe, platform)?;
        let policy = ExecutionPolicy {
            platform,
            bubblewrap: compiler_sandbox.to_owned(),
            scratch: temp_root.to_owned(),
            timeout: Duration::from_secs(90),
            max_result_bytes: 64 * 1024 * 1024,
        };
        for index in 0..REPETITIONS {
            run_once(backend, index, &spec, &store, &policy, reference)?;
        }

        run_variants(&store, &tree, root, &spec, &policy, reference)?;
        run_structural_variants(&store, &tree, &spec, &policy, reference)?;
        Ok(())
    }

    struct Variants {
        original: TreeManifest,
        source: Vec<u8>,
        source_path: TreePath,
        source_meta: TreeMetadata,
        source_manifest: TreeManifest,
        single_source: TreeManifest,
        stable_recipe: TreeRecipe,
        stable_composed_id: sccache_build::TreeId,
        shared_headers_recipe: TreeRecipe,
        shared_headers_composed: sccache_build::TreeId,
    }

    impl Variants {
        fn prepare(
            store: &NativeStore,
            tree: &sccache_build::TreeLease,
            root: &Path,
            directory_meta: TreeMetadata,
        ) -> Result<Self> {
            let original = tree.manifest().clone();
            let source = fs::read(root.join("src/input.c"))?;
            let source_path = TreePath::new(b"src/input.c".to_vec())?;
            let source_meta = match original.entries.get(&source_path) {
                Some(TreeEntry::File { metadata, .. }) => *metadata,
                _ => anyhow::bail!("captured C translation unit missing"),
            };
            let source_directory = TreePath::new(b"src".to_vec())?;
            let source_directory_meta = match original.entries.get(&source_directory) {
                Some(TreeEntry::Directory(metadata)) => *metadata,
                _ => anyhow::bail!("captured source directory missing"),
            };

            let mut toolchain = original.clone();
            toolchain
                .entries
                .retain(|path, _| !path.as_bytes().starts_with(b"src/"));
            let toolchain_id = store.publish_tree(&toolchain, vec![])?;
            let source_manifest = TreeManifest {
                root: source_directory_meta,
                entries: original
                    .entries
                    .iter()
                    .filter(|(path, _)| path.as_bytes().starts_with(b"src/"))
                    .map(|(path, entry)| {
                        Ok((TreePath::new(path.as_bytes()[4..].to_vec())?, entry.clone()))
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?,
            };
            let stable_recipe = TreeRecipe::union(directory_meta, [toolchain_id]);
            let stable_composed_id = store.lease_recipe(&stable_recipe)?.id();

            let mut with_headers = original.clone();
            with_headers.entries.remove(&source_path);
            with_headers.entries.insert(
                TreePath::new(b"src/current".to_vec())?,
                TreeEntry::Directory(source_directory_meta),
            );
            let shared_headers_id = store.publish_tree(&with_headers, vec![])?;
            let shared_headers_recipe = TreeRecipe::union(directory_meta, [shared_headers_id]);
            let shared_headers_composed = store.lease_recipe(&shared_headers_recipe)?.id();

            Ok(Self {
                original,
                source,
                source_path,
                source_meta,
                source_manifest,
                single_source: TreeManifest {
                    root: source_directory_meta,
                    entries: BTreeMap::new(),
                },
                stable_recipe,
                stable_composed_id,
                shared_headers_recipe,
                shared_headers_composed,
            })
        }
    }

    fn run_variants(
        store: &NativeStore,
        tree: &sccache_build::TreeLease,
        root: &Path,
        spec: &ExecutionSpec,
        policy: &ExecutionPolicy,
        reference: &[u8],
    ) -> Result<()> {
        let mut layouts = Variants::prepare(store, tree, root, spec.root.recipe.directories)?;
        for index in 0..REPETITIONS {
            let mut updated = layouts.source.clone();
            updated
                .extend_from_slice(format!("\n/* distinct action source {index} */\n").as_bytes());
            let staged = store.stage(updated.as_slice())?;
            let file = TreeEntry::File {
                blob: staged.reference(),
                metadata: layouts.source_meta,
            };
            let mut changed_root = layouts.original.clone();
            changed_root
                .entries
                .insert(layouts.source_path.clone(), file.clone());
            let changed_root_id = store.publish_tree(&changed_root, vec![staged])?;
            layouts
                .source_manifest
                .entries
                .insert(TreePath::new(b"input.c".to_vec())?, file.clone());
            let source_id = store.publish_tree(&layouts.source_manifest, vec![])?;
            layouts
                .single_source
                .entries
                .insert(TreePath::new(b"input.c".to_vec())?, file);
            let single_source_id = store.publish_tree(&layouts.single_source, vec![])?;

            let recipe = TreeRecipe::union(spec.root.recipe.directories, [changed_root_id]);
            let composed = store.lease_recipe(&recipe)?.id();
            let combined = compile_spec(composed, recipe, policy.platform)?;
            let mut separate = compile_spec(
                layouts.stable_composed_id,
                layouts.stable_recipe.clone(),
                policy.platform,
            )?;
            separate
                .mounts
                .insert(BuildPath::new(b"/src".to_vec())?, source_id);
            let mut isolated_source = compile_spec(
                layouts.shared_headers_composed,
                layouts.shared_headers_recipe.clone(),
                policy.platform,
            )?;
            isolated_source
                .mounts
                .insert(BuildPath::new(b"/src/current".to_vec())?, single_source_id);
            isolated_source.command.arguments[7] = b"/src/current/input.c".to_vec();
            isolated_source
                .command
                .arguments
                .insert(7, b"/src".to_vec());
            isolated_source.command.arguments.insert(7, b"-I".to_vec());

            let runs = [
                ("unique-root", &combined),
                ("stable-toolchain-mount", &separate),
                ("stable-headers-source-mount", &isolated_source),
            ];
            for offset in 0..runs.len() {
                let (label, command) = runs[(offset + index) % runs.len()];
                run_once(label, index, command, store, policy, reference)?;
            }
        }
        Ok(())
    }

    /// Exercise the normal whole-root action planner with changes to the
    /// contents *and topology* of a small generated-header directory. Clang
    /// actually reads the symlinked header, and every resulting object must
    /// be byte-identical to direct host Clang.
    fn run_structural_variants(
        store: &NativeStore,
        tree: &sccache_build::TreeLease,
        spec: &ExecutionSpec,
        policy: &ExecutionPolicy,
        reference: &[u8],
    ) -> Result<()> {
        let selected = TreePath::new(b"src/aux/selected.h".to_vec())?;
        let TreeEntry::File { metadata, .. } = tree
            .manifest()
            .entries
            .get(&selected)
            .context("generated header missing")?
        else {
            anyhow::bail!("expected a regular generated benchmark header");
        };
        let original = tree
            .manifest()
            .entries
            .get(&selected)
            .context("original header unavailable")?
            .clone();
        // Refresh this base view so structural variants do not inherit
        // eviction state from the earlier source-only benchmark.
        run_once("structural-baseline", 0, spec, store, policy, reference)?;
        for iteration in 0..REPETITIONS {
            let mut variant = tree.manifest().clone();
            let filename = format!("candidate-{iteration}.h");
            let extra_path = TreePath::new([b"src/aux/".as_slice(), filename.as_bytes()].concat())?;
            variant.entries.insert(extra_path, original.clone());
            variant.entries.insert(
                selected.clone(),
                TreeEntry::Symlink {
                    target: filename.into_bytes(),
                    modified: metadata.modified,
                },
            );
            let id = store.publish_tree(&variant, vec![])?;
            let recipe = TreeRecipe::union(spec.root.recipe.directories, [id]);
            let composed = store.lease_recipe(&recipe)?.id();
            let command = compile_spec(composed, recipe, policy.platform)?;
            run_once(
                "unique-root-structural",
                iteration,
                &command,
                store,
                policy,
                reference,
            )?;
        }
        Ok(())
    }

    fn run_once(
        backend: &str,
        index: usize,
        spec: &ExecutionSpec,
        store: &NativeStore,
        policy: &ExecutionPolicy,
        reference: &[u8],
    ) -> Result<()> {
        let before = arc()?;
        let started = Instant::now();
        let execution = execute(spec, store, policy, || Ok(()))?;
        let elapsed = started.elapsed();
        if !execution.status().success() {
            let mut diagnostic = String::new();
            if let Some(stderr) = execution.diagnostics().1 {
                execution
                    .open_blob(stderr.id)?
                    .read_to_string(&mut diagnostic)?;
            }
            anyhow::bail!(
                "native {backend} compiler exited {}: {diagnostic}",
                execution.status()
            );
        }
        let blob = execution
            .successful_result()
            .context("successful result missing")?
            .outputs
            .get("obj")
            .context("output object missing")?
            .blob;
        let mut compiled = Vec::new();
        execution.open_blob(blob.id)?.read_to_end(&mut compiled)?;
        ensure!(
            compiled == reference,
            "{backend} output differs from host Clang"
        );
        emit(backend, index, elapsed, before, arc()?);
        Ok(())
    }

    pub fn run() -> Result<()> {
        let usage =
            "usage: native_realbuild_arc ZFS_PARENT NONZFS_PARENT CLANG_BINARY BWRAP_BINARY";
        let mut arguments = std::env::args_os().skip(1);
        let zfs_parent = PathBuf::from(arguments.next().context(usage)?);
        let non_zfs_parent = PathBuf::from(arguments.next().context(usage)?);
        let compiler = PathBuf::from(arguments.next().context(usage)?);
        let bubblewrap = PathBuf::from(arguments.next().context(usage)?);
        ensure!(arguments.next().is_none(), "{usage}");
        ensure!(
            zfs_parent.is_absolute()
                && non_zfs_parent.is_absolute()
                && compiler.is_absolute()
                && bubblewrap.is_absolute(),
            "benchmark paths must be absolute"
        );
        ensure!(bubblewrap.is_file(), "Bubblewrap not found");
        fs::create_dir_all(&zfs_parent)?;
        fs::create_dir_all(&non_zfs_parent)?;
        let zfs = tempfile::Builder::new()
            .prefix("bench-zfs-")
            .tempdir_in(&zfs_parent)?;
        let non_zfs = tempfile::Builder::new()
            .prefix("bench-nonzfs-")
            .tempdir_in(&non_zfs_parent)?;
        let root = zfs.path().join("input");
        make_input(&root, &compiler)?;
        let expected = run_host(&root, &compiler)?;
        println!(
            "REFERENCE object_bytes={} blake3={}",
            expected.len(),
            blake3::hash(&expected).to_hex(),
        );
        run_cas("zfs", &root, zfs.path(), &bubblewrap, &expected)?;
        run_cas("nonzfs", &root, non_zfs.path(), &bubblewrap, &expected)?;
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::run()
    }
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("native CAS benchmark requires Linux")
    }
}
