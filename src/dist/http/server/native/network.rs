//! Native-service transport telemetry lives independently of CAS maintenance.

use std::{
    fs::File,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::build_runtime::{NetworkCheckpoint, NetworkMeter};

const CHECKPOINT_LIMIT: u64 = 4 << 20;
const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Serialize, Deserialize)]
struct SavedNetwork {
    listener: SocketAddr,
    model: NetworkCheckpoint,
}

fn restore(path: &Path, listener: SocketAddr, meter: &NetworkMeter) -> Result<()> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        file.metadata()?.len() <= CHECKPOINT_LIMIT,
        "native network checkpoint exceeds limit"
    );
    let saved: SavedNetwork = serde_json::from_reader(file.take(CHECKPOINT_LIMIT))?;
    if saved.listener == listener {
        meter.restore(saved.model);
    }
    Ok(())
}

fn save(path: &Path, listener: SocketAddr, meter: &NetworkMeter) -> Result<()> {
    let Some(model) = meter.checkpoint() else {
        return Ok(());
    };
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(&mut file, &SavedNetwork { listener, model })?;
    anyhow::ensure!(
        file.as_file().metadata()?.len() <= CHECKPOINT_LIMIT,
        "native network checkpoint exceeds limit"
    );
    file.as_file().sync_all()?;
    file.persist(path)?;
    Ok(())
}

pub(super) fn start(meter: &Arc<NetworkMeter>, path: PathBuf, listener: SocketAddr) -> Result<()> {
    if let Err(error) = restore(&path, listener, meter) {
        warn!("Ignoring native network timing checkpoint: {error:#}");
    }
    let meter = Arc::downgrade(meter);
    thread::Builder::new()
        .name("native-network-meter".into())
        .spawn(move || {
            let mut checkpoint = Instant::now();
            loop {
                thread::sleep(Duration::from_millis(250));
                let Some(meter) = meter.upgrade() else {
                    break;
                };
                meter.sample();
                if checkpoint.elapsed() >= CHECKPOINT_INTERVAL {
                    checkpoint = Instant::now();
                    if let Err(error) = save(&path, listener, &meter) {
                        warn!("Native network timing checkpoint failed: {error:#}");
                    }
                }
            }
        })?;
    Ok(())
}
