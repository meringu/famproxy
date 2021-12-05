use nix::{
    self,
    sys::socket::{getsockopt, sockopt::OriginalDst},
};
use rustls::internal::msgs::{
    deframer::MessageDeframer,
    handshake::{HandshakePayload, ServerNamePayload},
    message::MessagePayload,
};
use std::{
    io::{Error, ErrorKind},
    net::SocketAddrV4,
    os::unix::io::AsRawFd,
};
use tokio::{
    io,
    net::{TcpListener, TcpStream},
};
use tracing::{error, info};
use tracing_subscriber;

const HTTPS_BIND_ADDRESS: &str = "0.0.0.0:6443";

const BLOCKED_HOSTS: &[&str] = &["youtube.com"];

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt().init();

    info!("Starting listener on: {}", HTTPS_BIND_ADDRESS);

    let mut tcp_listener = TcpListener::bind(HTTPS_BIND_ADDRESS).await.map_err(|e| {
        error!("Error binding address {}: {}", HTTPS_BIND_ADDRESS, e);
        e
    })?;

    serve_tls(&mut tcp_listener).await?;

    Ok(())
}

async fn serve_tls(listener: &mut TcpListener) -> io::Result<()> {
    info!("Serving requests on: {}", HTTPS_BIND_ADDRESS);
    loop {
        // Asynchronously wait for an inbound socket.
        let socket = listener.accept().await;

        match socket {
            Ok((stream, _)) => {
                stream.nodelay().unwrap_or_default();
                // handle accepted connections asynchronously
                tokio::spawn(async move {
                    match handle_client_tls_connection(stream).await {
                        Ok(()) => {}
                        Err(e) => error!("{}", e),
                    }
                });
            }
            Err(e) => error!("Failed TCP handshake {}", e),
        }
    }
}

async fn handle_client_tls_connection(client_stream: TcpStream) -> io::Result<()> {
    let mut deframer = MessageDeframer::new();

    let mut buf = [0; 10_000];
    let length = client_stream.peek(&mut buf).await?;

    deframer.read(&mut Box::new(&buf[..length]))?;
    let opaque_message = deframer
        .frames
        .iter()
        .next()
        .ok_or(Error::new(ErrorKind::Other, "no TLS opaque_message"))?;

    let message = MessagePayload::new(
        opaque_message.typ,
        opaque_message.version,
        opaque_message.payload.clone(),
    )
    .map_err(|e| Error::new(ErrorKind::Other, e))?;

    let handshake = match message {
        MessagePayload::Handshake(h) => h,
        _ => return Err(Error::new(ErrorKind::Other, "expected TLS handshake")),
    };

    let client_hello = match handshake.payload {
        HandshakePayload::ClientHello(h) => h,
        _ => return Err(Error::new(ErrorKind::Other, "expected TLS client hello")),
    };

    let sni = client_hello.get_sni_extension().ok_or(Error::new(
        ErrorKind::Other,
        "dropping packet as SNI is enforced",
    ))?;

    let server_name = sni.iter().next().ok_or(Error::new(
        ErrorKind::Other,
        "dropping packet as not exactly on server names found for SNI",
    ))?;

    match &server_name.payload {
        ServerNamePayload::HostName((_, dnsname)) => {
            // TODO: use a HashSet or trie to match prefixes
            for host in BLOCKED_HOSTS.iter() {
                if host.eq(&(dnsname as &dyn AsRef<str>).as_ref()) {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("blocking: {:?}", dnsname.as_ref()),
                    ));
                }
            }
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Other,
                "dropping packet as unknown SNI format",
            ));
        }
    }

    // Get the intended destination
    let dest = getsockopt(client_stream.as_raw_fd(), OriginalDst)
        .map(|addr| SocketAddrV4::new(u32::from_be(addr.sin_addr.s_addr).into(), 443))?;

    // connect to upstream
    let dest_stream = TcpStream::connect(dest).await?;

    let (mut uread, mut uwrite) = client_stream.into_split();
    let (mut dread, mut dwrite) = dest_stream.into_split();

    // Join the streams and let the traffic flow
    tokio::spawn(async move { io::copy(&mut dread, &mut uwrite).await });
    tokio::spawn(async move { io::copy(&mut uread, &mut dwrite).await });

    Ok(())
}
