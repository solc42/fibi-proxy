use color_eyre::eyre::Context as _;
use color_eyre::Result;
use tokio::net::TcpStream;
use tracing::{event, Level};

use crate::commands::converters::AddOverflow;
use crate::commands::{http_ok_to_client, mutual_transfer_with_conv};
use crate::srv::server::RWDirectedPair;

#[derive(Debug)]
pub struct Cmd {
    pub client_tcp: tokio::net::TcpStream,
    pub dst_addr: String,
    pub mod_value: u8,
}

impl Cmd {
    pub async fn exec(self) -> Result<()> {
        event!(Level::DEBUG, "Connecting");

        let mod_value = self.mod_value;
        let upstream_srv = TcpStream::connect(&self.dst_addr)
            .await
            .with_context(|| format!("Failed to connect to {:?}", self.dst_addr))?;

        let (client_to_srv, mut srv_to_client) =
            RWDirectedPair::entangle_streams(self.client_tcp, upstream_srv);

        http_ok_to_client(&mut srv_to_client.to_wh).await?;

        event!(Level::INFO, "Channels up. Exchanging data ...");

        mutual_transfer_with_conv(
            srv_to_client,
            client_to_srv,
            AddOverflow::decoder(mod_value),
            AddOverflow::encoder(mod_value),
        )
        .await;

        Ok(())
    }
}
