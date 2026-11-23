# Local patch

This vendored `tiny_http` 0.12.0 carries one correctness fix needed by sccache's Rouille dist HTTP server: a peer can disconnect before `peer_addr()` succeeds. Upstream stores that `io::Result` and later unwraps it while constructing the request, which panics a connection worker on `ENOTCONN`. Remote-address metadata is optional, so this copy converts lookup failure to `None` and has a regression test for the failure path.

## 2026-11-23: TLS handshake accept-loop stall

The original tiny_http HTTPS listener ran a blocking OpenSSL handshake inside
its single TCP accept thread, without a timeout. One peer that did not finish
its ClientHello prevented the listener from accepting all subsequent connections.
On Asus this manifested as a saturated worker accept backlog, numerous CLOSE-WAIT
sockets, and repeated sccache distributed assign_job timeouts.

The listener now dispatches sockets into the existing connection task pool
before negotiating TLS. In-flight handshakes have CPU-scaled bounded admission;
both OpenSSL and rustls negotiation use a 10-second per-I/O timeout, cleared
after successful negotiation so legitimate request bodies are unaffected.
The TLS integration test keeps one handshake unfinished and verifies that a
second HTTPS client is served. The cause of the specific stalled live thread
remains unverified until stack capture, but this closes the concrete transport
path that can produce the observed symptom.

## 2026-11-23: bound post-handshake idle connections and request headers

TLS handshake isolation alone leaves connection task threads exposed to incomplete
HTTP headers and abandoned request-body uploads. After negotiation the former
socket timeouts were removed, so those connections could occupy a worker
indefinitely; the connection task pool could grow without a bound. Set a
60-second *idle I/O* timeout throughout the connection lifecycle (normal
streaming uploads may continue as long as data arrives), a 60-second absolute
HTTP-header phase deadline, and a 64 KiB cumulative request-header budget.
Admission permits cap concurrent connection tasks at a CPU-scaled 128–512,
independently of the tighter 32–256 TLS-handshake cap. Oversized requests get
HTTP 431; idle request headers get HTTP 408 where feasible.

The separate HTTP header regression test covers a single oversized header,
excessive aggregate header size, and a large valid header section.

Plaintext HTTP request pipelining now uses the same response notification and
per-connection backpressure as TLS: it cannot push unbounded requests into the
shared messages queue or Rouille executor. Notification sends tolerate a peer
connection that has already vanished rather than panicking during response
completion or cleanup.

An unrelated but adjacent timeout bug in the internal message queue passed the
full original timeout to each condvar wait even after a spurious wakeup,
allowing recv_timeout to run beyond its requested deadline. Subsequent waits
now use the remaining duration.
