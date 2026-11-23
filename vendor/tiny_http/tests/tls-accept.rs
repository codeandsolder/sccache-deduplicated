#![cfg(feature = "ssl-openssl")]

use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use tiny_http::{Response, Server, SslConfig};

#[test]
fn silent_tls_peer_does_not_block_other_connections() {
    let server = Server::https(
        "127.0.0.1:0",
        SslConfig {
            certificate: include_bytes!("../examples/ssl-cert.pem").to_vec(),
            private_key: include_bytes!("../examples/ssl-key.pem").to_vec(),
        },
    )
    .expect("create HTTPS server");
    let addr = server.server_addr().to_ip().expect("TCP address");

    // The incomplete record ensures OpenSSL is waiting for the remainder of
    // the TLS ClientHello. Before the fix this blocks the *only* acceptor.
    let mut incomplete = TcpStream::connect(addr).expect("first socket");
    incomplete
        .write_all(&[0x16, 0x03, 0x03, 0, 16])
        .expect("partial client hello");
    thread::sleep(Duration::from_millis(100));

    let responder = thread::spawn(move || {
        let request = server
            .recv_timeout(Duration::from_secs(3))
            .expect("receive request without a blocked accept loop")
            .expect("second client must reach the server");
        request
            .respond(Response::from_string("ok"))
            .expect("respond");
    });

    let mut tls = SslConnector::builder(SslMethod::tls()).expect("connector");
    tls.set_verify(SslVerifyMode::NONE);
    let tls = tls.build();
    let socket = TcpStream::connect(addr).expect("second socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read timeout");
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .expect("write timeout");
    let mut client = tls.connect("localhost", socket).expect("TLS handshake");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("send HTTP request");
    // The server may close TCP without a TLS close_notify. Validate the
    // complete HTTP response, not the cleanliness of the TLS shutdown.
    let mut response = Vec::new();
    let mut buffer = [0; 1024];
    while !response.ends_with(b"ok") {
        let n = client.read(&mut buffer).expect("read HTTP response");
        assert_ne!(n, 0, "HTTP response ended before its body");
        response.extend_from_slice(&buffer[..n]);
    }
    let response = String::from_utf8(response).expect("UTF-8 response");
    assert!(
        response.contains("200 OK"),
        "unexpected response: {}",
        response
    );
    assert!(response.ends_with("ok"), "unexpected body: {}", response);

    drop(incomplete);
    responder.join().expect("server thread");
}
