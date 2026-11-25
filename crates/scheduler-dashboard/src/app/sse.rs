//! EventSource lifecycle is owned by the reactive component. The browser
//! reconnects transport failures; every new connection starts with a reset.
use gloo_events::EventListener;
use leptos::prelude::*;
use send_wrapper::SendWrapper;
use serde::de::DeserializeOwned;
use wasm_bindgen::JsCast;
use web_sys::{EventSource, MessageEvent};

use super::ConnectionStatus;

struct Connection {
    source: EventSource,
    _message: EventListener,
    _error: EventListener,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.source.close();
    }
}

/// Attach to the current effect's owner; changing a metrics view or
/// unmounting the page closes the previous connection synchronously.
pub(super) fn connect<T: DeserializeOwned + 'static>(
    url: &str,
    status: RwSignal<ConnectionStatus>,
    retry: RwSignal<u64>,
    apply: impl Fn(T) -> bool + 'static,
) {
    status.set(ConnectionStatus::Connecting);
    let Ok(source) = EventSource::new(url) else {
        status.set(ConnectionStatus::Unavailable);
        return;
    };
    let error = EventListener::new(&source, "error", move |_| {
        status.set(ConnectionStatus::Reconnecting);
    });
    let close = source.clone();
    let message = EventListener::new(&source, "message", move |event| {
        let parsed = event
            .dyn_ref::<MessageEvent>()
            .and_then(|message| message.data().as_string())
            .and_then(|data| serde_json::from_str::<T>(&data).ok());
        if parsed.is_some_and(&apply) {
            status.set(ConnectionStatus::Connected);
        } else {
            // A reset is guaranteed on every connection. Never apply a patch
            // to a stale base, and back off rather than spin on bad payloads.
            close.close();
            status.set(ConnectionStatus::ProtocolError);
            leptos::leptos_dom::helpers::set_timeout(
                move || {
                    let _ = retry.try_update(|value| *value = value.wrapping_add(1));
                },
                std::time::Duration::from_secs(2),
            );
        }
    });
    let connection = SendWrapper::new(Connection {
        source,
        _message: message,
        _error: error,
    });
    on_cleanup(move || drop(connection));
}
