//! `EventSource` lifecycle is owned by the reactive component. The browser
//! reconnects transport failures; every new connection starts with a reset.
use std::{cell::RefCell, rc::Rc, time::Duration};

use gloo_events::EventListener;
use leptos::{
    leptos_dom::helpers::{TimeoutHandle, set_timeout_with_handle},
    prelude::*,
};
use send_wrapper::SendWrapper;
use serde::de::DeserializeOwned;
use wasm_bindgen::JsCast;
use web_sys::{EventSource, MessageEvent};

use super::ConnectionStatus;

type RetryTimer = Rc<RefCell<Option<TimeoutHandle>>>;

struct Connection {
    source: EventSource,
    _message: EventListener,
    _error: EventListener,
    timer: RetryTimer,
    watchdog: RetryTimer,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.source.close();
        clear_timer(&self.timer);
        clear_timer(&self.watchdog);
    }
}

fn clear_timer(timer: &RetryTimer) {
    if let Some(handle) = timer.borrow_mut().take() {
        handle.clear();
    }
}

fn arm_watchdog(timer: &RetryTimer, status: RwSignal<ConnectionStatus>, timeout: Option<Duration>) {
    clear_timer(timer);
    if let Some(timeout) = timeout {
        *timer.borrow_mut() = set_timeout_with_handle(
            move || {
                let _ = status.try_set(ConnectionStatus::Stalled);
            },
            timeout,
        )
        .ok();
    }
}

fn schedule_retry(timer: &RetryTimer, retry: RwSignal<u64>) {
    let mut pending = timer.borrow_mut();
    if pending.is_some() {
        return;
    }
    *pending = set_timeout_with_handle(
        move || {
            let _ = retry.try_update(|value| *value = value.wrapping_add(1));
        },
        Duration::from_secs(2),
    )
    .ok();
}

/// Attach to the current effect's owner; changing a metrics view or
/// unmounting the page closes the previous connection synchronously.
pub(super) fn connect<T: DeserializeOwned + 'static>(
    url: &str,
    status: RwSignal<ConnectionStatus>,
    retry: RwSignal<u64>,
    stale_after: Option<Duration>,
    apply: impl Fn(T) -> bool + 'static,
) {
    status.set(ConnectionStatus::Connecting);
    let Ok(source) = EventSource::new(url) else {
        status.set(ConnectionStatus::Unavailable);
        return;
    };
    let timer = RetryTimer::default();
    let watchdog = RetryTimer::default();
    arm_watchdog(&watchdog, status, stale_after);
    let error_watchdog = Rc::clone(&watchdog);
    let error_timer = Rc::clone(&timer);
    let error_source = source.clone();
    let error = EventListener::new(&source, "error", move |_| {
        clear_timer(&error_watchdog);
        status.set(ConnectionStatus::Reconnecting);
        // EventSource automatically retries transient network failures, but
        // some HTTP failures permanently close it (e.g. a full view registry).
        if error_source.ready_state() == EventSource::CLOSED {
            schedule_retry(&error_timer, retry);
        }
    });
    let close = source.clone();
    let message_watchdog = Rc::clone(&watchdog);
    let message_timer = Rc::clone(&timer);
    let message = EventListener::new(&source, "message", move |event| {
        let parsed = event
            .dyn_ref::<MessageEvent>()
            .and_then(|message| message.data().as_string())
            .and_then(|data| serde_json::from_str::<T>(&data).ok());
        if parsed.is_some_and(&apply) {
            status.set(ConnectionStatus::Connected);
            arm_watchdog(&message_watchdog, status, stale_after);
        } else {
            clear_timer(&message_watchdog);
            close.close();
            status.set(ConnectionStatus::ProtocolError);
            schedule_retry(&message_timer, retry);
        }
    });
    let connection = SendWrapper::new(Connection {
        source,
        _message: message,
        _error: error,
        timer,
        watchdog,
    });
    on_cleanup(move || drop(connection));
}
