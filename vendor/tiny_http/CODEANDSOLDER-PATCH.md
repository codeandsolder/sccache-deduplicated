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
