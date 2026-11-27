#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use sccache_build::{ContentId, DescriptorMemo, hash_descriptor};
    use std::{fs::File, path::PathBuf, time::Instant};

    let mut args = std::env::args_os().skip(1);
    let snapshot = PathBuf::from(args.next().context("expected immutable snapshot file")?);
    let mutable = PathBuf::from(args.next().context("expected mutable file")?);
    ensure!(args.next().is_none(), "unexpected arguments");
    let memo = DescriptorMemo::default();
    let scope = ContentId::of(b"immutable-digest-probe");
    for (path, immutable) in [(snapshot, true), (mutable, false)] {
        let start = Instant::now();
        let file = File::open(&path)?;
        let (probe, old) = memo.probe(scope, &file)?;
        ensure!(old.is_none(), "unexpected initial memo hit");
        let blob = hash_descriptor(&file)?;
        memo.remember(&probe, &file, blob)?;
        let elapsed = start.elapsed();
        drop(file);
        let file = File::open(&path)?;
        let start = Instant::now();
        let (_, value) = memo.probe(scope, &file)?;
        ensure!(
            value == immutable.then_some(blob),
            "unexpected memo eligibility"
        );
        println!(
            "{}: {} bytes, first={elapsed:?}, lookup={:?}, reused={immutable}",
            path.display(),
            blob.size,
            start.elapsed()
        );
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("requires Linux")
}
