use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tiny_http::{Response, Server};

fn request_with_headers(headers: &str, expected_status: &str) {
    let server = Server::http("127.0.0.1:0").expect("HTTP listener");
    let addr = server.server_addr().to_ip().expect("TCP listener");
    let responder = std::thread::spawn(move || {
        if let Some(req) = server
            .recv_timeout(Duration::from_millis(500))
            .expect("server receive")
        {
            req.respond(Response::from_string("ok")).expect("respond");
        }
    });

    let mut socket = TcpStream::connect(addr).expect("connect");
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set timeout");
    socket
        .write_all(format!("GET / HTTP/1.1\r\n{headers}\r\n").as_bytes())
        .expect("send headers");
    let mut response = [0; 1024];
    let n = socket.read(&mut response).expect("receive status");
    let response = String::from_utf8_lossy(&response[..n]);
    assert!(
        response.contains(expected_status),
        "expected {}; response was {:?}",
        expected_status,
        response
    );
    responder.join().expect("join responder");
}

#[test]
fn rejects_oversized_header_line_before_allocating_unbounded_memory() {
    request_with_headers(&format!("X-Long: {}\r\n", "a".repeat(70_000)), "431");
}

#[test]
fn rejects_oversized_aggregate_header_section() {
    let mut headers = String::new();
    for i in 0..90 {
        headers.push_str(&format!("X-Custom-{i}: {}\r\n", "b".repeat(1000)));
    }
    request_with_headers(&headers, "431");
}

#[test]
fn accepts_large_but_bounded_header_section() {
    request_with_headers(&format!("X-Valid: {}\r\n", "v".repeat(60_000)), "200");
}
