use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use bytes::{Bytes, BytesMut};
use http::{Request, StatusCode};
use quinn::Endpoint;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use structopt::StructOpt;
use tokio::{fs::File, io::AsyncReadExt};
use tracing::{error, info, trace_span, warn};

use h3::{error::ErrorLevel, quic::BidiStream, server::RequestStream};
use h3_quinn::quinn::{self, crypto::rustls::QuicServerConfig};

#[derive(StructOpt, Debug)]
#[structopt(name = "server")]
struct Opt {
    #[structopt(
        name = "dir",
        short,
        long,
        help = "Root directory of the files to serve. \
                If omitted, server will respond OK."
    )]
    pub root: Option<PathBuf>,

    #[structopt(
        short,
        long,
        default_value = "[::1]:4433",
        help = "What address:port to listen for new connections"
    )]
    pub listen: SocketAddr,

    #[structopt(flatten)]
    pub certs: Certs,
}

#[derive(StructOpt, Debug)]
pub struct Certs {
    #[structopt(
        long,
        short,
        default_value = "examples/server.cert",
        help = "Certificate for TLS. If present, `--key` is mandatory."
    )]
    pub cert: PathBuf,

    #[structopt(
        long,
        short,
        default_value = "examples/server.key",
        help = "Private key for the certificate."
    )]
    pub key: PathBuf,
}

static ALPN: &[u8] = b"h3";

async fn create_connection(uri: &str) -> Result<
  (
    Endpoint,
    h3::client::Connection<h3_quinn::Connection, bytes::Bytes>,
    h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>
  ),
  Box<dyn std::error::Error>>
{
  let base_uri = uri.parse::<http::Uri>()?;

  if base_uri.scheme() != Some(&http::uri::Scheme::HTTPS) {
    return Err("uri scheme must be 'https'".into());
  }

  let auth = base_uri.authority().ok_or("uri must have a host")?.clone();
  let port = auth.port_u16().unwrap_or(443);

  let addr = tokio::net::lookup_host((auth.host(), port))
    .await?
    .next()
    .ok_or("dns found no addresses")?;

  info!("DNS lookup for {:?}: {:?}", base_uri, addr);

  // create quinn client endpoint
  // load CA certificates stored in the system
  let mut roots = rustls::RootCertStore::empty();
  match rustls_native_certs::load_native_certs() {
    Err(e) => error!("couldn't load any default trust roots: {}", e),
    Ok(certs) => {
      for cert in certs {
        if let Err(e) = roots.add(cert) {
          error!("failed to parse trust anchor: {}", e);
        }
      }
    }
  };

  let mut tls_config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();

  tls_config.enable_early_data = true;
  tls_config.alpn_protocols = vec![ALPN.into()];
  tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

  let mut client_endpoint = h3_quinn::quinn::Endpoint::client("[::]:0".parse().unwrap())?;
  let client_config = quinn::ClientConfig::new(Arc::new(
    quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
  ));
  client_endpoint.set_default_client_config(client_config);
  let conn = client_endpoint.connect(addr, auth.host())?.await?;
  info!("QUIC connection established");

  // create h3 client
  let quinn_conn = h3_quinn::Connection::new(conn);

  #[allow(clippy::type_complexity)]
  let part_h3_client : Result<(
    h3::client::Connection<h3_quinn::Connection, bytes::Bytes>,
    h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>
  ), h3::Error> = h3::client::builder()
    .send_grease(false)
    .build(quinn_conn).await;

  match part_h3_client {
    Ok((x, y)) => Ok((client_endpoint, x, y)),
    Err(error) => Err(Box::new(error)),
  }
}

async fn test_request(
  send_request: &mut h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
) -> Result<(), Box<dyn std::error::Error>>
{
  let new_http_request = http::request::Request::builder()
    .uri("https://workers.dev")
    .header("Worker-Mirror-Host", "example.com")
    .body(())
    .unwrap();

  let mut _send_request = match send_request.send_request(new_http_request).await {
    Ok(value) => value,
    Err(error) => {
      warn!("CLC: {:?}", error);
      return Err(Box::new(error))
    },
  };

  match _send_request.finish().await {
    Ok(value) => value,
    Err(error) => {
      warn!("CLA: {:?}", error);
      return Err(Box::new(error))
    },
  };

  if let Ok(response) = _send_request.recv_response().await {
    println!("{:?}, {:?}", response.headers(), response.status())
  };

  Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::TRACE)
        .init();

    // process cli arguments

    let opt = Opt::from_args();

    let root = if let Some(root) = opt.root {
        if !root.is_dir() {
            return Err(format!("{}: is not a readable directory", root.display()).into());
        } else {
            info!("serving {}", root.display());
            Arc::new(Some(root))
        }
    } else {
        Arc::new(None)
    };

    let Certs { cert, key } = opt.certs;

    // create quinn server endpoint and bind UDP socket

    // both cert and key must be DER-encoded
    let cert = CertificateDer::from(std::fs::read(cert)?);
    let key = PrivateKeyDer::try_from(std::fs::read(key)?)?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;

    tls_config.max_early_data_size = u32::MAX;
    tls_config.alpn_protocols = vec![ALPN.into()];

    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config)?));
    let endpoint = quinn::Endpoint::server(server_config, opt.listen)?;

    info!("listening on {}", opt.listen);

    // handle incoming connections and requests

    while let Some(new_conn) = endpoint.accept().await {
        trace_span!("New connection being attempted");

        let root = root.clone();

        tokio::spawn(async move {
            match new_conn.await {
                Ok(conn) => {
                    info!("new connection established");

                    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn))
                        .await
                        .unwrap();

                    warn!("CREATE_CONNECTION");
                    let (client_endpoint, mut driver, send_request) = match create_connection("https://workers.dev").await {
                        Ok((client_endpoint, x, y)) => (client_endpoint, x, y),
                        Err(error) => {
                            error!("{:?}", &error);
                            return
                        }
                    };
                    warn!("GOT_CREATE_CONNECTION");

                    loop {
                        let mut cloned_send_request = send_request.clone();

                        match h3_conn.accept().await {
                            Ok(Some((req, stream))) => {
                                info!("new request: {:#?}", req);

                                let root = root.clone();

                                tokio::spawn(async move {
                                    // tokio::task::yield_now().await;

                                    warn!("KAKAC: Requesting");
                                    let _ = test_request(&mut cloned_send_request).await;
                                    warn!("KAKAD: Requesting End");

                                    if let Err(e) = handle_request(req, stream, root).await {
                                        error!("handling request failed: {}", e);
                                    }
                                });
                            }

                            // indicating no more streams to be received
                            Ok(None) => {
                                break;
                            }

                            Err(err) => {
                                error!("error on accept {}", err);
                                match err.get_error_level() {
                                    ErrorLevel::ConnectionError => break,
                                    ErrorLevel::StreamError => continue,
                                }
                            }
                        }
                    }

                    let _ = driver.wait_idle().await;
                    let _ = client_endpoint.wait_idle().await;
                }
                Err(err) => {
                    error!("accepting connection failed: {:?}", err);
                }
            }
        });
    }

    // shut down gracefully
    // wait for connections to be closed before exiting
    endpoint.wait_idle().await;

    Ok(())
}

async fn handle_request<T>(
    req: Request<()>,
    mut stream: RequestStream<T, Bytes>,
    serve_root: Arc<Option<PathBuf>>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: BidiStream<Bytes>,
{
    let (status, to_serve) = match serve_root.as_deref() {
        None => (StatusCode::OK, None),
        Some(_) if req.uri().path().contains("..") => (StatusCode::NOT_FOUND, None),
        Some(root) => {
            let to_serve = root.join(req.uri().path().strip_prefix('/').unwrap_or(""));
            match File::open(&to_serve).await {
                Ok(file) => (StatusCode::OK, Some(file)),
                Err(e) => {
                    error!("failed to open: \"{}\": {}", to_serve.to_string_lossy(), e);
                    (StatusCode::NOT_FOUND, None)
                }
            }
        }
    };

    let resp = http::Response::builder().status(status).body(()).unwrap();

    match stream.send_response(resp).await {
        Ok(_) => {
            info!("successfully respond to connection");
        }
        Err(err) => {
            error!("unable to send response to connection peer: {:?}", err);
        }
    }

    if let Some(mut file) = to_serve {
        loop {
            let mut buf = BytesMut::with_capacity(4096 * 10);
            if file.read_buf(&mut buf).await? == 0 {
                break;
            }
            stream.send_data(buf.freeze()).await?;
        }
    }

    Ok(stream.finish().await?)
}
