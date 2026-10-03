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
}

pub struct Acquired {
    _token: Option<jobserver::Acquired>,
}

impl Client {
    pub fn new() -> Self {
        Self::new_num(crate::util::num_cpus())
    }

    pub fn new_num(num: usize) -> Self {
        let inner = match jobserver::Client::new(num) {
            Ok(inner) => inner,
            Err(error) => {
                return Self {
                    state: ClientState::Failed(Arc::from(format!(
                        "failed to create jobserver: {error}"
                    ))),
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

        Self { state }
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

        Ok(Acquired {
            _token: Some(acquired),
        })
    }
}
