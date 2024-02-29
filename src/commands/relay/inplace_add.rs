use color_eyre::eyre::{bail, Context as _};
use color_eyre::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt as _};
use tokio::net::TcpStream;

use tracing::{event, Level};

use crate::cli::{DataModificationType, Relay};
use crate::commands::converters::AddOverflow;
use crate::commands::{http_ok_to_client, mutual_transfer_with_conv, HTTP_200_OK_CRLN_CRLN};
use crate::srv::dispatch::{H_CONVERSION_TYPE, H_INPLACE_MOD};
use crate::srv::server::RWDirectedPair;

//TODO: make configurable via cli
const INPLACE_CONVERSION_A: u8 = 77;

#[derive(Debug)]
pub struct Cmd {
    pub client_tcp: TcpStream,
    pub dst_addr: String,
    pub relay: Relay,
}

impl Cmd {
    pub async fn exec(self) -> Result<()> {
        event!(Level::DEBUG, "Connecting");

        let (client_to_srv, mut srv_to_client) = self.handshake().await?;

        http_ok_to_client(&mut srv_to_client.to_wh).await?;

        event!(Level::INFO, "Channels up. Exchanging data ...");

        mutual_transfer_with_conv(
            srv_to_client,
            client_to_srv,
            AddOverflow::encoder(INPLACE_CONVERSION_A),
            AddOverflow::decoder(INPLACE_CONVERSION_A),
        )
        .await;

        Ok(())
    }

    async fn handshake(self) -> Result<(RWDirectedPair, RWDirectedPair)> {
        //TODO: must be restricted in clap mechanics
        let relay_to_addr = &self.relay.relay_to_addr.unwrap().clone();

        let mut relay_to_stream = TcpStream::connect(relay_to_addr)
            .await
            .with_context(|| format!("Failed to connect to {:?}", relay_to_addr))?;

        relay_to_stream
            .write_all(
                format!(
                    "CONNECT {} HTTP/1.1\r\n\
                    {H_CONVERSION_TYPE}: {}\r\n\
                    {H_INPLACE_MOD}: {INPLACE_CONVERSION_A}\r\n\r\n",
                    &self.dst_addr,
                    DataModificationType::InplaceAdd,
                )
                .as_bytes(),
            )
            .await
            .with_context(|| format!("Handshake failed to relay_to_addr: {:?}", relay_to_addr))?;

        let (client_to_srv, mut srv_to_client) =
            RWDirectedPair::entangle_streams(self.client_tcp, relay_to_stream);

        //TODO: this is ugly, but atm it is enough to handle upstream proxy answer
        let mut buf = [0u8; HTTP_200_OK_CRLN_CRLN.len()];
        let r_cnt = srv_to_client
            .from_rh
            .read(&mut buf)
            .await
            .with_context(|| "Failed to read handshake answer")?;

        if &buf[..r_cnt] != HTTP_200_OK_CRLN_CRLN.as_bytes() {
            bail!(
                "Handshake answer missmatches expected 200 ok. Actual: Hex='{:02X?}' LossyString='{:?}')",
                &buf[..r_cnt],
                String::from_utf8_lossy(&buf[..r_cnt]).into_owned()
            )
        }

        Ok((client_to_srv, srv_to_client))
    }
}
