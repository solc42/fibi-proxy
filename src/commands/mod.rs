use std::cmp::Ordering;

use color_eyre::{eyre::Context as _, Result};
use eyre::bail;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::OwnedWriteHalf,
};
use tracing::{event, instrument, warn_span, Instrument, Level};

use crate::srv::server::RWDirectedPair;

use self::{converters::InplaceConversion, relay::inplace_add};

pub mod connect_vanilla;
pub mod relay;
pub mod relayed_inplace_add;

const HTTP_200_OK_CRLN_CRLN: &str = "HTTP/1.1 200 OK\r\n\r\n";

#[derive(Debug)]
pub enum ServerScenario {
    ConnectVanilla(connect_vanilla::Cmd),
    RelayedInplaceAdd(relayed_inplace_add::Cmd),
    RelayInplaceAdd(inplace_add::Cmd),
}

impl ServerScenario {
    pub async fn execute(self) -> Result<()> {
        match self {
            ServerScenario::ConnectVanilla(sc) => {
                let dst_addr = &sc.dst_addr.clone();
                sc.exec()
                    .instrument(warn_span!("ConnectVanilla", dst_addr))
                    .await?;
                Ok(())
            }
            ServerScenario::RelayedInplaceAdd(sc) => {
                let dst_addr = &sc.dst_addr.clone();
                sc.exec()
                    .instrument(warn_span!("RelayedInplaceAdd", dst_addr))
                    .await?;
                Ok(())
            }
            ServerScenario::RelayInplaceAdd(sc) => {
                let dst_addr = &sc.dst_addr.clone();
                sc.exec()
                    .instrument(warn_span!("RelayInplaceAdd", dst_addr))
                    .await?;
                Ok(())
            }
        }
    }
}

#[instrument()]
pub async fn http_ok_to_client(wh: &mut OwnedWriteHalf) -> Result<()> {
    let _ = wh.write(HTTP_200_OK_CRLN_CRLN.as_bytes()).await?;

    Ok(())
}
pub async fn mutual_transfer(srv_to_cl: RWDirectedPair, cl_to_srv: RWDirectedPair) {
    let span = warn_span!("UpstreamToClient");
    tokio::spawn(copy(srv_to_cl).instrument(span));

    copy(cl_to_srv)
        .instrument(warn_span!("ClientToUpstream"))
        .await;
}

async fn copy(mut rwp: RWDirectedPair) {
    tokio::io::copy(&mut rwp.from_rh, &mut rwp.to_wh)
        .await
        .expect("Copy failed");
}

pub async fn mutual_transfer_with_conv<CtoS, StoC>(
    s_to_c: RWDirectedPair,
    c_to_s: RWDirectedPair,
    conv_ctos: CtoS,
    conv_stoc: StoC,
) where
    CtoS: InplaceConversion + Send + 'static,
    StoC: InplaceConversion + Send + 'static,
{
    let span_stc = warn_span!("UpstreamToClient");

    tokio::spawn(async move {
        copy_with_conv(s_to_c, conv_stoc)
            .instrument(span_stc)
            .await
            .expect("UpstreamToClient copy failed");
    });

    copy_with_conv(c_to_s, conv_ctos)
        .instrument(warn_span!("ClientToUpstream"))
        .await
        .expect("ClientToUpstream copy failed");
}

async fn copy_with_conv<C>(mut rwp: RWDirectedPair, conv: C) -> Result<()>
where
    C: InplaceConversion + Send,
{
    //TODO: way nonoptimal but atm it's ok
    let mut buf = [0u8; 1000];
    loop {
        let read_cnt = rwp
            .from_rh
            .read(&mut buf)
            .await
            .with_context(|| "Read failed")?;

        match read_cnt.cmp(&0) {
            Ordering::Greater => {
                event!(
                    Level::TRACE,
                    "read data before mod: '{:02X?}'",
                    &buf[..read_cnt]
                );

                conv.convert(&mut buf);

                event!(
                    Level::TRACE,
                    "writing data after mod: '{:02X?}'",
                    &buf[..read_cnt]
                );

                rwp.to_wh
                    .write_all(&buf[..read_cnt])
                    .await
                    .with_context(|| "Write failed")?;
            }
            Ordering::Equal => {
                event!(Level::DEBUG, "Transfer finished");
                return Ok(());
            }
            Ordering::Less => bail!("Must not be there. Read < 0 ?"),
        }
    }
}

mod converters {

    pub trait InplaceConversion {
        fn convert(&self, data: &mut [u8]);
    }

    pub struct AddOverflow {
        mod_value: u8,
    }

    impl AddOverflow {
        pub fn encoder(mod_value: u8) -> AddOverflow {
            mod_value.into()
        }

        pub fn decoder(mod_value: u8) -> SubOverflow {
            mod_value.into()
        }
    }

    impl From<u8> for AddOverflow {
        fn from(mod_value: u8) -> Self {
            Self { mod_value }
        }
    }

    pub struct SubOverflow {
        mod_value: u8,
    }

    impl From<u8> for SubOverflow {
        fn from(mod_value: u8) -> Self {
            Self { mod_value }
        }
    }

    impl InplaceConversion for AddOverflow {
        fn convert(&self, data: &mut [u8]) {
            (0..data.len()).for_each(|i| {
                let new_val = data[i].overflowing_add(self.mod_value);
                data[i] = new_val.0;
            });
        }
    }

    impl InplaceConversion for SubOverflow {
        fn convert(&self, data: &mut [u8]) {
            (0..data.len()).for_each(|i| {
                let new_val = data[i].overflowing_sub(self.mod_value);
                data[i] = new_val.0;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::commands::converters::{AddOverflow, InplaceConversion, SubOverflow};
    use pretty_assertions::assert_eq;
    use pretty_hex::pretty_hex;

    #[test]
    fn test_add_overflow() {
        let mut data = [0x01, 0xff];

        let conv: AddOverflow = 2.into();
        conv.convert(data.as_mut_slice());
        assert_eq!(pretty_hex(&data), pretty_hex(&[0x03, 0x01]));
    }

    #[test]
    fn test_sub_overflow() {
        let mut data = [0x01, 0xff];

        let conv: SubOverflow = 2.into();
        conv.convert(data.as_mut_slice());

        assert_eq!(pretty_hex(&data), pretty_hex(&[0xff, 0xfd]));
    }
}
