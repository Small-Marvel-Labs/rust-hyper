#![deny(warnings)]

use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::header::{self, HeaderMap, HeaderName};
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response};

use tokio::net::{TcpListener, TcpStream};

#[path = "../benches/support/mod.rs"]
mod support;
use support::TokioIo;

type ClientBuilder = hyper::client::conn::http1::Builder;
type ServerBuilder = hyper::server::conn::http1::Builder;

// To try this example:
// 1. cargo run --example http_proxy
// 2. config http_proxy in command line
//    $ export http_proxy=http://127.0.0.1:8100
//    $ export https_proxy=http://127.0.0.1:8100
// 3. send requests
//    $ curl -i https://www.some_domain.com/
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8100));

    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            if let Err(err) = ServerBuilder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, service_fn(proxy))
                .with_upgrades()
                .await
            {
                println!("Failed to serve connection: {:?}", err);
            }
        });
    }
}

async fn proxy(
    mut req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    println!("req: {:?}", req);

    if Method::CONNECT == req.method() {
        // Received an HTTP request like:
        // ```
        // CONNECT www.domain.com:443 HTTP/1.1
        // Host: www.domain.com:443
        // Proxy-Connection: Keep-Alive
        // ```
        //
        // When HTTP method is CONNECT we should return an empty body
        // then we can eventually upgrade the connection and talk a new protocol.
        //
        // Note: only after client received an empty body with STATUS_OK can the
        // connection be upgraded, so we can't return a response inside
        // `on_upgrade` future.
        if let Some(addr) = host_addr(req.uri()) {
            let server = match TcpStream::connect(addr.as_str()).await {
                Ok(server) => server,
                Err(e) => {
                    eprintln!("CONNECT to {} failed: {}", addr, e);
                    let mut resp = Response::new(full("CONNECT target is unreachable"));
                    *resp.status_mut() = http::StatusCode::BAD_GATEWAY;

                    return Ok(resp);
                }
            };

            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, server).await {
                            eprintln!("server io error: {}", e);
                        };
                    }
                    Err(e) => eprintln!("upgrade error: {}", e),
                }
            });

            Ok(Response::new(empty()))
        } else {
            eprintln!("CONNECT host is not socket addr: {:?}", req.uri());
            let mut resp = Response::new(full("CONNECT must be to a socket address"));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;

            Ok(resp)
        }
    } else {
        // Removes the fields that only apply to one connection (RFC 9110, Section 7.6.1):
        // those its Connection field names, and those known to be connection-specific.
        fn remove_hop_by_hop_headers(headers: &mut HeaderMap) {
            let named: Vec<HeaderName> = headers
                .get_all(header::CONNECTION)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|value| value.split(','))
                .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
                .collect();
            for name in named {
                headers.remove(name);
            }
            for name in [
                header::CONNECTION,
                HeaderName::from_static("proxy-connection"),
                HeaderName::from_static("keep-alive"),
                header::TE,
                header::TRANSFER_ENCODING,
                header::UPGRADE,
            ] {
                headers.remove(name);
            }
        }

        remove_hop_by_hop_headers(req.headers_mut());
        // Credentials for this proxy, not for the origin.
        req.headers_mut().remove(header::PROXY_AUTHORIZATION);

        let host = req.uri().host().expect("uri has no host");
        let port = req.uri().port_u16().unwrap_or(80);

        let stream = TcpStream::connect((host, port)).await.unwrap();
        let io = TokioIo::new(stream);

        let (mut sender, conn) = ClientBuilder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(io)
            .await?;
        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                println!("Connection failed: {:?}", err);
            }
        });

        let mut resp = sender.send_request(req).await?;
        remove_hop_by_hop_headers(resp.headers_mut());
        Ok(resp.map(|b| b.boxed()))
    }
}

fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().map(|auth| auth.to_string())
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

// Build a tunnel between the upgraded connection and the connection to host:port
async fn tunnel(upgraded: Upgraded, mut server: TcpStream) -> std::io::Result<()> {
    let mut upgraded = TokioIo::new(upgraded);

    // Proxying data
    let (from_client, from_server) =
        tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;

    // Print message when done
    println!(
        "client wrote {} bytes and received {} bytes",
        from_client, from_server
    );

    Ok(())
}
