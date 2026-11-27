//! Content-addressed durable publication notifications. Unlike a global
//! generation counter, unrelated commits never wake waiting acquisitions.
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, PoisonError},
};

use anyhow::{Context, Result};
use tokio::sync::Notify;

use crate::ContentId;

#[derive(Default)]
pub(super) struct PublicationWaits {
    registry: Mutex<Registry>,
}

#[derive(Default)]
struct Registry {
    next_id: u64,
    by_content: BTreeMap<ContentId, BTreeMap<u64, Arc<Waiter>>>,
}

#[derive(Default)]
struct Waiter {
    changed: Mutex<BTreeSet<ContentId>>,
    wake: Notify,
}

pub(super) struct Subscription<'a> {
    owner: &'a PublicationWaits,
    id: u64,
    contents: Vec<ContentId>,
    waiter: Arc<Waiter>,
}

impl PublicationWaits {
    pub(super) fn register(
        &self,
        contents: impl IntoIterator<Item = ContentId>,
    ) -> Result<Subscription<'_>> {
        let contents: Vec<_> = contents.into_iter().collect();
        let waiter = Arc::new(Waiter::default());
        let mut registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
        let id = registry.next_id;
        registry.next_id = id
            .checked_add(1)
            .context("publication subscriber ID exhausted")?;
        for &content in &contents {
            registry
                .by_content
                .entry(content)
                .or_default()
                .insert(id, Arc::clone(&waiter));
        }
        drop(registry);
        Ok(Subscription {
            owner: self,
            id,
            contents,
            waiter,
        })
    }

    pub(super) fn notify(&self, changed: &[ContentId]) {
        if changed.is_empty() {
            return;
        }
        let registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
        let mut recipients = BTreeMap::<u64, (Arc<Waiter>, Vec<ContentId>)>::new();
        for content in changed {
            if let Some(waiters) = registry.by_content.get(content) {
                for (&id, waiter) in waiters {
                    recipients
                        .entry(id)
                        .or_insert_with(|| (Arc::clone(waiter), Vec::new()))
                        .1
                        .push(*content);
                }
            }
        }
        drop(registry);
        // Keep the registry lock independent of the consumer's event lock.
        // Cancellation after snapshotting a recipient is harmless.
        for (_, (waiter, contents)) in recipients {
            waiter
                .changed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend(contents);
            waiter.wake.notify_one();
        }
    }
}

impl Subscription<'_> {
    pub(super) async fn next(&self) -> BTreeSet<ContentId> {
        loop {
            let changed = {
                let mut pending = self
                    .waiter
                    .changed
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                std::mem::take(&mut *pending)
            };
            if !changed.is_empty() {
                return changed;
            }
            // notify_one retains a permit if publication occurs between the
            // empty check and polling the future. At most one consumer waits.
            self.waiter.wake.notified().await;
        }
    }
}

impl Drop for Subscription<'_> {
    fn drop(&mut self) {
        let mut registry = self
            .owner
            .registry
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for content in &self.contents {
            if let std::collections::btree_map::Entry::Occupied(mut entry) =
                registry.by_content.entry(*content)
            {
                entry.get_mut().remove(&self.id);
                if entry.get().is_empty() {
                    entry.remove_entry();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::{Future, poll_fn},
        task::Poll,
    };

    #[tokio::test]
    async fn notifications_are_targeted_coalesced_and_retained_until_consumed() -> Result<()> {
        let waits = PublicationWaits::default();
        let a = ContentId::of(b"a");
        let b = ContentId::of(b"b");
        let c = ContentId::of(b"c");
        let d = ContentId::of(b"d");
        let first = waits.register([a, b])?;
        let second = waits.register([b, c])?;
        let unrelated = waits.register([d])?;
        // Simulate commits before a consumer has started polling.
        waits.notify(&[a, b]);
        waits.notify(&[a, c]);
        assert_eq!(first.next().await, BTreeSet::from([a, b]));
        assert_eq!(second.next().await, BTreeSet::from([b, c]));
        let mut next = Box::pin(unrelated.next());
        poll_fn(|cx| {
            assert!(next.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        waits.notify(&[d]);
        assert_eq!(next.await, BTreeSet::from([d]));
        drop((first, second, unrelated));
        assert!(
            waits
                .registry
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .by_content
                .is_empty()
        );
        Ok(())
    }
}
