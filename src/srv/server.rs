use std::net::{Ipv4Addr, SocketAddr};

use color_eyre::Result;

use color_eyre::eyre::Context as _;
use strum_macros::EnumString;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tracing::{instrument, warn_span, Instrument};

use tracing::{event, Level};

use crate::srv::dispatch::ClientConnection;
use crate::{Relay, WhiteList};

pub struct RWDirectedPair {
    pub from_rh: OwnedReadHalf,
    pub to_wh: OwnedWriteHalf,
}

impl RWDirectedPair {
    pub fn entangle_streams(
        client: TcpStream,
        server: TcpStream,
    ) -> (RWDirectedPair, RWDirectedPair) {
        let (cl_rh, cl_wh): (OwnedReadHalf, OwnedWriteHalf) = client.into_split();
        let (srv_rh, srv_wh) = server.into_split();

        let srv_to_client = RWDirectedPair {
            from_rh: srv_rh,
            to_wh: cl_wh,
        };

        let client_to_srv = RWDirectedPair {
            from_rh: cl_rh,
            to_wh: srv_wh,
        };

        (client_to_srv, srv_to_client)
    }
}

#[derive(Debug, EnumString)]
#[strum(serialize_all = "kebab-case")]
pub enum Conversion {
    InplaceAdd,
}

pub struct Server {
    lsnr: TcpListener,
    relay: Option<Relay>,
    white_list: WhiteList,
    pub listen_addr: SocketAddr,
}

impl Server {
    #[cfg(test)]
    pub async fn new(lsn_addr: SocketAddr, relay: Option<Relay>) -> Result<Self> {
        Self::new_wl(lsn_addr, relay, WhiteList::Localhost).await
    }

    #[instrument(level = tracing::Level::INFO)]
    pub async fn new_wl(
        lsn_addr: SocketAddr,
        relay: Option<Relay>,
        white_list: WhiteList,
    ) -> Result<Self> {
        let lsnr = TcpListener::bind(&lsn_addr)
            .await
            .with_context(|| format!("Failed to bind at: {:?}", &lsn_addr))?;

        let la = lsnr.local_addr().unwrap();
        Ok(Self {
            lsnr,
            listen_addr: la,
            relay,
            white_list,
        })
    }

    pub async fn run(&mut self) -> Result<String> {
        event!(
            Level::INFO,
            "Listening for connections at: {:?}. relay_mode: {:#?}",
            self.listen_addr,
            self.relay
        );

        loop {
            match self.lsnr.accept().await {
                Ok((tcp_stream, addr)) => {
                    let uuid = uuid::Uuid::new_v4().to_string();
                    let client = addr.to_string();

                    event!(Level::DEBUG, uuid, client, "New connection");

                    if !self.is_wl_allowed(&addr) {
                        event!(Level::WARN, "Blocked by whitelist. Addr: '{}'", &addr);
                        continue;
                    }

                    let span = warn_span!("request", uuid, client_from = client);

                    let cc = ClientConnection::new(tcp_stream, self.relay.clone());

                    tokio::spawn(async move {
                        Self::process_connection(cc).instrument(span).await.unwrap();
                    });
                }
                Err(cause) => {
                    event!(
                        Level::ERROR,
                        "Accept connection failed. Details: {:?}",
                        cause
                    );
                }
            }
        }
    }

    pub fn is_wl_allowed(&self, addr_to_check: &SocketAddr) -> bool {
        let ip = match addr_to_check {
            SocketAddr::V4(ipv4) => ipv4.ip(),
            _ => return false,
        };

        match self.white_list {
            WhiteList::Any => true,
            WhiteList::Localhost => ip == &Ipv4Addr::LOCALHOST,
            WhiteList::Ips(ref allowed_ips) => {
                if let SocketAddr::V4(ipv4) = addr_to_check {
                    if ipv4.ip() == &Ipv4Addr::LOCALHOST || allowed_ips.contains(ipv4.ip()) {
                        return true;
                    }
                };
                false
            }
        }
    }

    async fn process_connection(cc: ClientConnection) -> Result<()> {
        cc.into_scenario()
            .await
            .with_context(|| "Scenario meta data read failed")?
            .execute()
            .await
            .with_context(|| "Scenario execution failed")?;

        event!(Level::DEBUG, "Disconnecting");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::panic;
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use crate::{srv::server::Server, DataModificationType, Relay, WhiteList};
    use pretty_assertions::assert_eq;

    use eyre::Report;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{
            tcp::{OwnedReadHalf, OwnedWriteHalf},
            TcpListener, TcpStream,
        },
        task::JoinHandle,
    };

    use tracing::{warn_span, Instrument, Level};
    use tracing_error::ErrorLayer;
    use tracing_subscriber::layer::SubscriberExt;
    use xshell::{cmd, Shell};

    use pretty_hex::pretty_hex;

    const LOCALHOST_ANYPORT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

    // using system installed curl client to obtain real https resource data, through proxy
    //
    // NOTE: why curl instead of reqwest or isahc rust lib?
    // reqest and isahc https scenario is nontransparent https mitm proxy scenario, not the
    // transparent tunnel based on CONNECT
    // Mb they can be configured somehow - need to investigate later.
    #[tokio::test]
    async fn test_proxy_vanilla_real_https_with_curl() {
        let (proxy_port, _) = start_proxy().await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let jh = tokio::task::spawn_blocking(move || {
            let sh = Shell::new().unwrap();

            //TODO: replace with in tests https server
            //mb with hyper and rusttls from theri tutorial
            //mb move to ingetrational test
            let url = "https://www.freebsd.org";
            let port_str = proxy_port.to_string();
            let cmd = cmd!(sh, "curl -s --max-time 2 -x 127.0.0.1:{port_str} {url}");

            cmd.read().unwrap()
        });

        let res = jh.await.unwrap();
        assert!(res.starts_with("<!DOCTYPE html>"));
    }

    #[tokio::test]
    async fn test_proxy_vanilla() {
        let (upstream_port, up_jh) = start_upstream("some answer from server\n".into()).await;

        let (proxy_port, _) = start_proxy().await;

        // let all start ...
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut cl = NaiveProxyClient::connect(proxy_port).await;

        cl.handshake(&format!(
            "CONNECT localhost:{upstream_port}\r\n\
                    SOME_HEADER: SOME_VALUE\r\n\r\n"
        ))
        .await;

        //client side sees data as it sent from server - no modification
        let proxy_answ = cl
            .write_read1_into_vec("some query from client".as_bytes())
            .await;
        assert_eq!(
            String::from_utf8(proxy_answ).unwrap(),
            "some answer from server\n"
        );

        //server side sees as it sent from client - no modification
        let proxied_req = up_jh.await.unwrap();
        assert_eq!(
            String::from_utf8(proxied_req).unwrap(),
            "some query from client"
        );
    }

    #[tokio::test]
    async fn test_proxy_conversion_inplace() {
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

    #[tokio::test]
    async fn test_relay_proxy_inplace() {
        let server_answer_payload = "mnno";

        let (upstream_port, up_jh) =
            start_upstream(format!("HTTP/1.1 200 OK\r\n\r\n{}", server_answer_payload).into())
                .await;

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
    async fn test_proxy_n_relay_proxy_chain_with_curl() {
        let (proxy_port, _) = start_proxy().await;

        let relay = Relay {
            mode: Some(DataModificationType::InplaceAdd),
            relay_to_addr: Some(format!("127.0.0.1:{proxy_port}").parse().unwrap()),
        };
        let (relay_proxy_port, _) = start_proxy_relay(Some(relay)).await;

        // let all start ...
        //mb move to ingetrational test
        tokio::time::sleep(Duration::from_millis(200)).await;

        let jh = tokio::task::spawn_blocking(move || {
            let sh = Shell::new().unwrap();

            //TODO: replace with in tests https server
            //mb with hyper and rusttls from theri tutorial
            //mb move to ingetrational test
            let url = "https://www.freebsd.org";
            let port_str = relay_proxy_port.to_string();
            let cmd = cmd!(sh, "curl -s --max-time 5 -x 127.0.0.1:{port_str} {url}");

            cmd.read().unwrap()
        });

        let res = jh.await.unwrap();
        assert!(res.starts_with("<!DOCTYPE html>"));
    }

    #[tokio::test]
    async fn test_is_wl_allowed_when_no_localhost_only() {
        let lh_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        let some_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)), 1234);

        let srv_no_wl = Server::new(LOCALHOST_ANYPORT, None).await.unwrap();
        assert!(srv_no_wl.is_wl_allowed(&lh_addr));
        assert!(!srv_no_wl.is_wl_allowed(&some_addr));
    }

    #[tokio::test]
    async fn test_is_wl_allowed_when_explicit_wl() {
        let lh_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        let allowed_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 1234);
        let some_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)), 1234);

        let wl: HashSet<Ipv4Addr> = vec!["192.168.0.1".parse().unwrap()].into_iter().collect();
        let srv_wl = Server::new_wl(LOCALHOST_ANYPORT, None, WhiteList::Ips(wl))
            .await
            .unwrap();

        assert!(srv_wl.is_wl_allowed(&lh_addr)); //localhost always allowed implicitly
        assert!(!srv_wl.is_wl_allowed(&some_addr));
        assert!(srv_wl.is_wl_allowed(&allowed_addr));
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

    async fn start_proxy_relay(relay: Option<Relay>) -> (u16, JoinHandle<Result<String, Report>>) {
        let mut srv = Server::new(LOCALHOST_ANYPORT, relay).await.unwrap();
        let port = srv.listen_addr.port();
        let jh = tokio::spawn(async move { srv.run().instrument(warn_span!("RELAY_PROXY")).await });
        (port, jh)
    }

    async fn start_proxy() -> (u16, JoinHandle<Result<String, Report>>) {
        let mut srv = Server::new(LOCALHOST_ANYPORT, None).await.unwrap();
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
}
