use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use eyre::Result;
use fibi_proxy::{
    cli::{DataModificationType, Relay, WhiteList},
    srv::server::Server,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    spawn,
    task::JoinHandle,
};
use tracing::{warn_span, Instrument as _, Level};
use tracing_error::ErrorLayer;
use tracing_subscriber::layer::SubscriberExt;

use pretty_assertions::assert_eq;

use pretty_hex::pretty_hex;

const LOCALHOST_ANYPORT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

#[tokio::test]
async fn test_is_wl_allowed_when_no_localhost_only() {
    let lh_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
    let some_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)), 1234);

    let srv_no_wl = Server::new(LOCALHOST_ANYPORT, None, WhiteList::Localhost)
        .await
        .unwrap();
    assert!(srv_no_wl.is_wl_allowed(&lh_addr));
    assert!(!srv_no_wl.is_wl_allowed(&some_addr));
}

#[tokio::test]
async fn test_is_wl_allowed_when_explicit_wl() {
    let lh_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
    let allowed_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 1234);
    let some_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)), 1234);

    let wl: HashSet<Ipv4Addr> = vec!["192.168.0.1".parse().unwrap()].into_iter().collect();
    let srv_wl = Server::new(LOCALHOST_ANYPORT, None, WhiteList::Ips(wl))
        .await
        .unwrap();

    assert!(srv_wl.is_wl_allowed(&lh_addr)); //localhost always allowed implicitly
    assert!(!srv_wl.is_wl_allowed(&some_addr));
    assert!(srv_wl.is_wl_allowed(&allowed_addr));
}

/**
 * General scenario: proxy https query based on CONNECT header
 */
#[tokio::test]
async fn test_server_proxy_to_https() {
    let (proxy_port, _) = start_proxy().await;

    //TODO: mb wrapper to obtain listened port after bind stage?
    let https_srv_port = 50000;
    let jh_ssl_srv = spawn(hyper_ssl_srv_example::run_for_one_request(https_srv_port));

    let jh_client = spawn(
        reqwest::Client::builder()
            .proxy(reqwest::Proxy::https(format!("http://localhost:{proxy_port}")).unwrap())
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
            .get(format!("https://localhost:{https_srv_port}"))
            .send()
            .await
            .unwrap()
            .bytes(),
    );

    jh_ssl_srv.await.unwrap().unwrap();

    let srv_answer = jh_client.await.unwrap().unwrap();
    assert_eq!(srv_answer, "stub answer from ssl serv\n".to_owned());
}

/**
 * inplace-add scenario from point of view of general proxy
 *
 * imitating incoming relayed data
 * test:
 * - rollback of modification to upstream, so the servers sees unmodified traffic
 * - back modification of server response, so data to relay proxy will return modified the same way as
 * specified in meta
 **/
#[tokio::test]
async fn test_server_proxy_inplace_add_handle() {
    let (upstream_port, up_jh) = start_upstream(vec![0x01, 0xff]).await;

    let (proxy_port, _) = start_proxy().await;

    // let all start ...
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut cl = NaiveProxyClient::connect(proxy_port).await;

    let mod_delta = 0x20;
    cl.handshake(&format!(
        "CONNECT localhost:{upstream_port}\r\n\
                    Fp-Conversion-Type: inplace-add\r\n\
                    Fp-Inplace-Mod: {}\r\n\r\n",
        mod_delta
    ))
    .await;

    let proxied_answ = cl.write_read1_into_vec([0x11, 0xef].as_slice()).await;
    let proxied_req = up_jh.await.unwrap();

    //server side sees data 'decoded':
    //with unset modfication according to specified mod_delta at proxy
    assert_eq!(pretty_hex(&proxied_req), pretty_hex(&vec![0xf1, 0xcf]));

    //client side sees data 'encoded':
    //modified the same way as it transfered - with mod_delta addition to server answer
    assert_eq!(pretty_hex(&proxied_answ), pretty_hex(&vec![0x21, 0x1f]));
}

/**
 * inplace-add scenario from point of view of relay proxy
 *
 * test:
 * - modification of data to upstream, so the servers sees modified data
 * - back modification of the relay response, so data to client will return unmodified
 **/
#[tokio::test]
async fn test_relay_proxy_inplace_add_apply() {
    let server_answer_payload = "mnno";

    let (upstream_port, up_jh) =
        start_upstream(format!("HTTP/1.1 200 OK\r\n\r\n{}", server_answer_payload).into()).await;

    let relay = Relay {
        mode: Some(DataModificationType::InplaceAdd),
        relay_to_addr: Some(format!("127.0.0.1:{upstream_port}").parse().unwrap()),
    };
    let (relay_proxy_port, _) = start_proxy_relay(Some(relay)).await;

    let mut cl = NaiveProxyClient::connect(relay_proxy_port).await;

    cl.handshake_minimal().await;

    let proxied_answ = cl.write_read1_into_vec([0, 0x64, 0xc8].as_slice()).await;
    let proxied_req = up_jh.await.unwrap();

    assert_eq!(
        String::from_utf8(proxied_req).unwrap(),
        format!(
            "CONNECT localhost:{relay_proxy_port} HTTP/1.1\r\n\
                Fp-Conversion-Type: inplace-add\r\n\
                Fp-Inplace-Mod: 77\r\n\r\n"
        )
    );

    //TODO: test 'encoded' payload from client after handshake
    assert_eq!(
        pretty_hex(&proxied_answ),
        pretty_hex(&vec![0x20, 0x21, 0x21, 0x22])
    );
}

#[tokio::test]
async fn test_server_proxy_n_relay_proxy_combo() {
    let (proxy_port, _) = start_proxy().await;

    let relay = Relay {
        mode: Some(DataModificationType::InplaceAdd),
        relay_to_addr: Some(format!("127.0.0.1:{proxy_port}").parse().unwrap()),
    };
    let (relay_proxy_port, _) = start_proxy_relay(Some(relay)).await;

    let https_srv_port = 50001;
    let jh_ssl_srv = spawn(hyper_ssl_srv_example::run_for_one_request(https_srv_port));

    let jh_client = spawn(
        reqwest::Client::builder()
            .proxy(reqwest::Proxy::https(format!("http://localhost:{relay_proxy_port}")).unwrap())
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
            .get(format!("https://localhost:{https_srv_port}"))
            .send()
            .await
            .unwrap()
            .bytes(),
    );

    jh_ssl_srv.await.unwrap().unwrap();

    let srv_answer = jh_client.await.unwrap().unwrap();
    assert_eq!(srv_answer, "stub answer from ssl serv\n".to_owned());
}

struct NaiveRwServer {
    lsnr: TcpListener,
    mocked_answer: Vec<u8>,
}

impl NaiveRwServer {
    fn bind_port(&self) -> u16 {
        self.lsnr.local_addr().unwrap().port()
    }

    async fn start(mock_answer: Vec<u8>) -> Self {
        let lsnr = TcpListener::bind(LOCALHOST_ANYPORT)
            .await
            .expect("Failed to bind");
        Self {
            lsnr,
            mocked_answer: mock_answer,
        }
    }

    async fn run_for_record(&mut self) -> Vec<u8> {
        let (mut cl, _addr) = self.lsnr.accept().await.unwrap();

        let (mut rh, mut wh) = cl.split();

        let mut buf = [0u8; 200];

        //can be partial it's ok for tests
        let cnt = rh.read(&mut buf).await.unwrap();

        if cnt == 0 {
            panic!("Expected non empty read, but got EOF");
        }

        let wr = self.mocked_answer.as_slice();

        let _ = wh.write_all(wr).await;

        buf[..cnt].into()
    }
}

async fn start_upstream(answer: Vec<u8>) -> (u16, JoinHandle<Vec<u8>>) {
    let mut srv = NaiveRwServer::start(answer).await;
    let port = srv.bind_port();
    let jh = tokio::spawn(async move { srv.run_for_record().await });
    (port, jh)
}

async fn start_proxy_relay(relay: Option<Relay>) -> (u16, JoinHandle<Result<String>>) {
    let mut srv = Server::new(LOCALHOST_ANYPORT, relay, WhiteList::Localhost)
        .await
        .unwrap();
    let port = srv.listen_addr.port();
    let jh = tokio::spawn(async move { srv.run().instrument(warn_span!("RELAY_PROXY")).await });
    (port, jh)
}

async fn start_proxy() -> (u16, JoinHandle<Result<String>>) {
    let mut srv = Server::new(LOCALHOST_ANYPORT, None, WhiteList::Localhost)
        .await
        .unwrap();
    let port = srv.listen_addr.port();
    let jh = tokio::spawn(async move { srv.run().await });
    (port, jh)
}

struct NaiveProxyClient {
    rw_h: (OwnedReadHalf, OwnedWriteHalf),
    remote_port: u16,
}

impl NaiveProxyClient {
    async fn connect(localhost_target_port: u16) -> Self {
        let rw_h = TcpStream::connect(format!("127.0.0.1:{localhost_target_port}"))
            .await
            .unwrap()
            .into_split();

        Self {
            rw_h,
            remote_port: localhost_target_port,
        }
    }

    async fn handshake(&mut self, handshake_data: &str) -> &Self {
        let mut buf = [0u8; 19]; //
        let answ = self
            .write_read1_into_buf(handshake_data.as_bytes(), &mut buf)
            .await;

        assert_eq!(
            pretty_hex(&answ),
            pretty_hex(&"HTTP/1.1 200 OK\r\n\r\n".to_string())
        );

        self
    }

    async fn handshake_minimal(&mut self) -> &Self {
        self.handshake(&format!("CONNECT localhost:{}\r\n\r\n", self.remote_port))
            .await;
        self
    }

    async fn write_read1_into_vec(&mut self, source: &[u8]) -> Vec<u8> {
        let mut buf = [0u8; 1000]; //enough for test exchange
        self.write_read1_into_buf(source, &mut buf).await.into()
    }

    async fn write_read1_into_buf<'a, 'b, 'c>(
        &'c mut self,
        source: &'b [u8],
        dst: &'a mut [u8],
    ) -> &'a [u8] {
        if dst.is_empty() {
            panic!("Attempt to use an empty store buf for read")
        }
        self.rw_h.1.write_all(source).await.unwrap();

        //can be partial it's ok for tests
        let cnt = self.rw_h.0.read(dst).await.unwrap();
        if cnt == 0 {
            panic!("Must not be empty read, but got EOF");
        }
        &dst[0..cnt]
    }
}

#[allow(dead_code)]
fn enable_tracing() {
    let sub = tracing_subscriber::fmt()
        .pretty()
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(false)
        .with_max_level(Level::DEBUG)
        .finish()
        .with(ErrorLayer::default());

    tracing::subscriber::set_global_default(sub).expect("Subscrier set failed");
}
// this code is based on https://github.com/rustls/hyper-rustls/blob/main/examples/server.rs
// simplified for oneshot http request handling
mod hyper_ssl_srv_example {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::vec::Vec;
    use std::{fs, io};

    use eyre::{bail, Context};
    use http::{Method, Request, Response, StatusCode};
    use http_body_util::Full;
    use hyper::body::{Bytes, Incoming};
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::ServerConfig;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    pub async fn run_for_one_request(port: u16) -> eyre::Result<()> {
        let certs = load_certs("./tests/ssl_certs/self_signed_localhost_cert.pem")
            .expect("Failed to load certs file");
        let key = load_private_key("./tests/ssl_certs/self_signed_localhost_key.pem")
            .expect("Failed to load priv key");

        let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);

        let mut srv_cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        srv_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

        let tls_acceptor = TlsAcceptor::from(Arc::new(srv_cfg));

        let lsnr = TcpListener::bind(&addr)
            .await
            .with_context(|| format!("Failed to bind to: {:?}", &addr))?;

        let (tcp_stream, _) = lsnr.accept().await.with_context(|| "Accept failed")?;

        let tls_stream = tls_acceptor
            .accept(tcp_stream)
            .await
            .with_context(|| "TLS Accept failed")?;

        let service = service_fn(handle_request);
        if let Err(cause) = Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(tls_stream), service)
            .await
        {
            bail!("Failed to serve connection. Details: {:#?}", cause);
        }

        Ok(())
    }

    async fn handle_request(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let mut response = Response::new(Full::default());
        match (req.method(), req.uri().path()) {
            (&Method::GET, "/") => {
                *response.body_mut() = Full::from("stub answer from ssl serv\n");
            }
            _ => {
                *response.status_mut() = StatusCode::NOT_FOUND;
            }
        };
        Ok(response)
    }

    //TODO: remove strange unwrap
    fn load_certs(filename: &str) -> eyre::Result<Vec<CertificateDer<'static>>> {
        let file = fs::File::open(filename)?;
        let mut buf_rdr = io::BufReader::new(file);

        let res = rustls_pemfile::certs(&mut buf_rdr)
            .map(|it| it.unwrap())
            .collect();

        Ok(res)
    }

    //TODO: remove strange unwrap
    fn load_private_key(filename: &str) -> eyre::Result<PrivateKeyDer<'static>> {
        let file = fs::File::open(filename)?;
        let mut buf_rdr = io::BufReader::new(file);

        let res = rustls_pemfile::private_key(&mut buf_rdr).map(|key| key.unwrap())?;

        Ok(res)
    }
}
