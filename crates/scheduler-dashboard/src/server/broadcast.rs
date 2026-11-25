//! Shared revisioned SSE transport. State publication and subscription are
//! serialized together; a lagged receiver starts again from a current reset.
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use axum::response::sse::Event;
use futures::{Stream, stream};
use serde::Serialize;
use tokio::sync::broadcast;

struct Published<T> {
    data: T,
    reset: Option<Arc<str>>,
}

pub(super) struct Feed<T> {
    state: Mutex<Published<T>>,
    changes: broadcast::Sender<Arc<str>>,
}

#[derive(Serialize)]
enum Reset<'a, T> {
    Reset(&'a T),
}

impl<T: Serialize> Feed<T> {
    pub(super) fn new(data: T, capacity: usize) -> Self {
        let (changes, _) = broadcast::channel(capacity);
        Self {
            state: Mutex::new(Published { data, reset: None }),
            changes,
        }
    }

    pub(super) fn inspect<R>(&self, read: impl FnOnce(&T) -> R) -> R {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        read(&state.data)
    }

    /// The producer prepares its payload before committing the mutation.
    /// A suppressed update keeps the previously serialized reset reusable.
    pub(super) fn publish(
        &self,
        update: impl FnOnce(&mut T) -> Result<Option<Arc<str>>>,
    ) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(payload) = update(&mut state.data)? {
            state.reset = None;
            let _ = self.changes.send(payload);
        }
        drop(state);
        Ok(())
    }

    pub(super) fn subscribe(&self) -> Result<(Arc<str>, broadcast::Receiver<Arc<str>>)> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let receiver = self.changes.subscribe();
        let reset = if let Some(reset) = &state.reset {
            Arc::clone(reset)
        } else {
            let reset: Arc<str> = serde_json::to_string(&Reset::Reset(&state.data))?.into();
            state.reset = Some(Arc::clone(&reset));
            reset
        };
        drop(state);
        Ok((reset, receiver))
    }
}

pub(super) fn event(data: impl AsRef<str>) -> Event {
    Event::default().data(data.as_ref())
}

/// The arbitrary lease stays alive for the entire HTTP response, including
/// time spent blocked by a slow consumer. Native status uses a unit lease.
pub(super) fn events<T: Serialize + Send + 'static>(
    feed: Arc<Feed<T>>,
    lease: impl Send + 'static,
) -> impl Stream<Item = Result<Event, Infallible>> {
    stream::unfold(
        (feed, lease, None),
        |(feed, lease, receiver): (_, _, Option<broadcast::Receiver<Arc<str>>>)| async move {
            let next = match receiver {
                Some(mut receiver) => match receiver.recv().await {
                    Ok(payload) => Some((payload, receiver)),
                    Err(broadcast::error::RecvError::Lagged(_)) => feed.subscribe().ok(),
                    Err(broadcast::error::RecvError::Closed) => None,
                },
                None => feed.subscribe().ok(),
            };
            next.map(|(payload, receiver)| (Ok(event(payload)), (feed, lease, Some(receiver))))
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_is_shared_per_revision_and_invalidated_on_publish() -> Result<()> {
        let feed = Feed::new(1_u64, 4);
        let (first, _) = feed.subscribe()?;
        let (second, _) = feed.subscribe()?;
        assert!(Arc::ptr_eq(&first, &second));
        feed.publish(|_| Ok(None))?;
        assert!(Arc::ptr_eq(&first, &feed.subscribe()?.0));
        feed.publish(|value| {
            *value = 2;
            Ok(Some("patch".into()))
        })?;
        let (third, _) = feed.subscribe()?;
        assert_eq!(&*third, r#"{"Reset":2}"#);
        assert!(!Arc::ptr_eq(&first, &third));
        Ok(())
    }
}
