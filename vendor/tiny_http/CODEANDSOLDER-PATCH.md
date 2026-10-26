# Local patch

This vendored `tiny_http` 0.12.0 carries one correctness fix needed by sccache's Rouille dist HTTP server: a peer can disconnect before `peer_addr()` succeeds. Upstream stores that `io::Result` and later unwraps it while constructing the request, which panics a connection worker on `ENOTCONN`. Remote-address metadata is optional, so this copy converts lookup failure to `None` and has a regression test for the failure path.
