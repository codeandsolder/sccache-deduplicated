use std::io;
use std::process::Command;
use std::sync::Arc;

use futures::StreamExt;
use futures::channel::mpsc;
use futures::channel::oneshot;

use crate::errors::{Context, Result, anyhow};

// The execution model of sccache is that on the first run it spawns a server
// in the background and detaches it.
// When normally executing the rust compiler from either cargo or make, it
// will use cargo/make's jobserver and limit its resource usage accordingly.
// When executing the rust compiler through the sccache server, that jobserver
// is not available, and spawning as many rustc as there are CPUs can lead to
// a quadratic use of the CPU resources (each rustc spawning as many threads
// as there are CPUs).
// One way around this issue is to inherit the jobserver from cargo or make
// when the sccache server is spawned, but that means that in some cases, the
// cargo or make process can't terminate until the sccache server terminates
// after its idle timeout (which also never happens if SCCACHE_IDLE_TIMEOUT=0).
// Also, if the sccache server ends up shared between multiple runs of
// cargo/make, then which jobserver is used doesn't make sense anymore.
// Ideally, the sccache client would give a handle to the jobserver it has
// access to, so that the rust compiler would "just" use the jobserver it
// would have used if it had run without sccache, but that adds some extra
// complexity, and requires to use Unix domain sockets.
// What we do instead is to arbitrary use our own jobserver.
// Unfortunately, that doesn't absolve us from having to deal with the original
// jobserver, because make may give us file descriptors to its pipes, and the
// simple fact of keeping them open can block it. That is handled by closing
// every inherited descriptor when the server detaches; see
// `util::close_inherited_fds`.

#[derive(Clone)]
enum ClientState {
    Ready {
        helper: Arc<jobserver::HelperThread>,
        tx: mpsc::UnboundedSender<oneshot::Sender<io::Result<jobserver::Acquired>>>,
        inner: jobserver::Client,
    },
    Failed(Arc<str>),
}

#[derive(Clone)]
pub struct Client {
    state: ClientState,
    #[cfg(target_os = "linux")]
    capacity: usize,
    #[cfg(target_os = "linux")]
    remote: Option<remote::RemoteClient>,
}

pub struct Acquired {
    #[cfg(target_os = "linux")]
    _remote: Option<remote::RemotePermit>,
    _token: Option<jobserver::Acquired>,
}

const DEFAULT_MIN_JOBS: u32 = 12;

fn effective_jobs(cpus: usize, minimum: Option<&str>) -> Result<usize> {
    let minimum = minimum
        .map(str::parse::<u32>)
        .transpose()
        .context("SCCACHE_MIN_JOBS must be a non-negative integer")?
        .unwrap_or(DEFAULT_MIN_JOBS);
    Ok(cpus.max(minimum as usize))
}

impl Client {
    pub fn new() -> Self {
        let jobs = match std::env::var("SCCACHE_MIN_JOBS") {
            Ok(value) => effective_jobs(crate::util::num_cpus(), Some(&value)),
            Err(std::env::VarError::NotPresent) => effective_jobs(crate::util::num_cpus(), None),
            Err(error) => Err(error).context("invalid SCCACHE_MIN_JOBS"),
        };
        match jobs {
            Ok(jobs) => Self::new_num(jobs),
            Err(error) => Self {
                state: ClientState::Failed(Arc::from(format!("{error:#}"))),
                #[cfg(target_os = "linux")]
                capacity: 1,
                #[cfg(target_os = "linux")]
                remote: None,
            },
        }
    }

    pub fn new_num(num: usize) -> Self {
        let inner = match jobserver::Client::new(num) {
            Ok(inner) => inner,
            Err(error) => {
                return Self {
                    state: ClientState::Failed(Arc::from(format!(
                        "failed to create jobserver: {error}"
                    ))),
                    #[cfg(target_os = "linux")]
                    capacity: num,
                    #[cfg(target_os = "linux")]
                    remote: None,
                };
            }
        };

        let (tx, mut rx) = mpsc::unbounded::<oneshot::Sender<_>>();
        let helper = inner.clone().into_helper_thread(move |token| {
            futures::executor::block_on(async {
                if let Some(sender) = rx.next().await {
                    let _ = sender.send(token);
                }
            });
        });

        let state = match helper {
            Ok(helper) => ClientState::Ready {
                helper: Arc::new(helper),
                tx,
                inner,
            },
            Err(error) => ClientState::Failed(Arc::from(format!(
                "failed to spawn jobserver helper thread: {error}"
            ))),
        };

        Self {
            state,
            #[cfg(target_os = "linux")]
            capacity: num,
            #[cfg(target_os = "linux")]
            remote: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn capacity(&self) -> usize {
        self.capacity
    }

    /// The private executor owns a one-slot local jobserver for compiler
    /// subprocesses, but obtains physical execution permits from its daemon.
    #[cfg(target_os = "linux")]
    pub(crate) fn with_remote(stream: std::os::unix::net::UnixStream) -> Result<Self> {
        let mut client = Self::new_num(1);
        client.remote = Some(remote::RemoteClient::new(stream)?);
        Ok(client)
    }

    /// Configures this jobserver to be inherited by the specified command.
    pub fn configure(&self, cmd: &mut Command) {
        if let ClientState::Ready { inner, .. } = &self.state {
            inner.configure(cmd);
        }
    }

    /// Returns a future that represents an acquired jobserver token.
    ///
    /// This should be invoked before any "work" is spawned (for whatever the
    /// definition of "work" is) to ensure that the system is properly
    /// rate-limiting itself.
    ///
    /// # Errors
    ///
    /// Returns an error if the jobserver failed to initialize, the helper
    /// request channel is closed, or token acquisition fails.
    pub async fn acquire(&self) -> Result<Acquired> {
        let (helper, tx) = match &self.state {
            ClientState::Ready { helper, tx, .. } => (helper, tx),
            ClientState::Failed(error) => return Err(anyhow!("{error}")),
        };

        let (mytx, myrx) = oneshot::channel();
        helper.request_token();
        tx.unbounded_send(mytx)
            .map_err(|_| anyhow!("jobserver helper request channel closed"))?;

        let acquired = myrx
            .await
            .context("jobserver helper panicked")?
            .context("failed to acquire jobserver token")?;

        #[cfg(target_os = "linux")]
        let remote = match &self.remote {
            Some(client) => Some(client.acquire().await?),
            None => None,
        };
        Ok(Acquired {
            #[cfg(target_os = "linux")]
            _remote: remote,
            _token: Some(acquired),
        })
    }
}

#[cfg(target_os = "linux")]
pub mod remote;

#[cfg(test)]
mod tests {
    use super::effective_jobs;

    #[test]
    fn minimum_job_capacity() -> crate::errors::Result<()> {
        assert_eq!(effective_jobs(4, None)?, 12);
        assert_eq!(effective_jobs(24, None)?, 24);
        assert_eq!(effective_jobs(8, Some("16"))?, 16);
        assert_eq!(effective_jobs(8, Some("0"))?, 8);
        assert!(effective_jobs(8, Some("-1")).is_err());
        assert!(effective_jobs(8, Some("bad")).is_err());
        Ok(())
    }
}
