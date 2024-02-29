use std::net::{Ipv4Addr, SocketAddr};

use strum_macros::EnumString;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use tokio::net::{TcpListener, TcpStream};
use tracing::{event, instrument, warn_span, Instrument as _, Level};

use crate::cli::{Relay, WhiteList};
use crate::srv::dispatch::ClientConnection;

use eyre::{Context as _, Result};

pub struct Server {
    lsnr: TcpListener,
    relay: Option<Relay>,
    white_list: WhiteList,
    pub listen_addr: SocketAddr,
}

impl Server {
    #[instrument(level = tracing::Level::INFO)]
    pub async fn new(
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
