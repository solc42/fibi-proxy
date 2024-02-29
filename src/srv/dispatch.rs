use color_eyre::eyre::{self, anyhow, Context as _};
use color_eyre::Result;
use eyre::eyre;
use std::{collections::HashMap, str::FromStr};

use memchr::memmem::find;
use thiserror::Error;
use tokio::{io::AsyncReadExt, net::TcpStream};
use tracing::{event, Level};

use crate::cli::{DataModificationType, Relay};
use crate::commands::relay::inplace_add;

use crate::commands::{connect_vanilla, relayed_inplace_add, ServerScenario};

use super::server::Conversion;

pub const PROXY_CONNECTION_VERB: &str = "CONNECT";
pub const H_CONVERSION_TYPE: &str = "Fp-Conversion-Type";
pub const H_INPLACE_MOD: &str = "Fp-Inplace-Mod";

pub struct ClientConnection {
    client_tcp: TcpStream,
    relay: Option<Relay>,
}

impl ClientConnection {
    pub fn new(client_tcp: TcpStream, relay: Option<Relay>) -> Self {
        Self { client_tcp, relay }
    }

    pub async fn into_scenario(mut self) -> Result<ServerScenario> {
        let req = self
            .read_request()
            .await
            .with_context(|| "Failed to read request")?;

        match req.req_line {
            RequestLine::Connect(dst_addr) => {
                // relay proxy scenarios
                if self.relay.is_some() {
                    let sc = self.into_relay(dst_addr);
                    return Ok(sc);
                };

                // regular proxy scenarios
                let hdr = req.headers.get(H_CONVERSION_TYPE);
                let conv = match hdr {
                    None => None,
                    Some(val) => Some(
                        val.parse()
                            .with_context(|| format!("Unknown conversion type: {}", val))?,
                    ),
                };

                let sc = match conv {
                    Some(Conversion::InplaceAdd) => {
                        let mod_value: u8 = req
                            .headers
                            .get(H_INPLACE_MOD)
                            .ok_or_else(|| eyre!("Missing required modificator value"))?
                            .parse()
                            .with_context(|| "Failed to parse modificator value")?;

                        ServerScenario::RelayedInplaceAdd(relayed_inplace_add::Cmd {
                            dst_addr,
                            mod_value,
                            client_tcp: self.client_tcp,
                        })
                    }
                    None => ServerScenario::ConnectVanilla(connect_vanilla::Cmd {
                        dst_addr,
                        client_tcp: self.client_tcp,
                    }),
                };

                Ok(sc)
            }
        }
    }

    fn into_relay(self, dst_addr: String) -> ServerScenario {
        //TODO: must be restricted in clap terms
        let relay_mode = self
            .relay
            .clone()
            .and_then(|it| it.mode)
            .expect("Mode must not be empty there");

        match relay_mode {
            DataModificationType::InplaceAdd => ServerScenario::RelayInplaceAdd(inplace_add::Cmd {
                dst_addr,
                client_tcp: self.client_tcp,
                relay: self.relay.expect("Must not be there"),
            }),
        }
    }

    async fn read_request(&mut self) -> Result<Request> {
        let mut buf = vec![0u8; 500];

        //WARN: it's possible, that on read will not actually get the whole CRLF CRLF block, cause of
        //it's size or some partial read. it's ok atm, but must be handled - to read with reries(if possible) at
        //least N bytes chunk. 500 is enough? In proxy queries it's seems ok, but in general ....
        let res = self.client_tcp.read(buf.as_mut_slice()).await;

        match res {
            Ok(cnt) if cnt > 0 => {
                if let Some(_idx) = find(&buf, "\r\n\r\n".as_bytes()) {
                    let req = Request::try_from(&buf)
                        .with_context(|| "Failed to parse request from data buf")?;
                    event!(Level::DEBUG, "Parsed request: {:?}", req);

                    return Ok(req);
                }
                Err(anyhow!(RequestParseError::NoHdrsBlock))
            }
            Ok(_) => Err(anyhow!(RequestParseError::ReadErrorNoData)),

            Err(cause) => Err(anyhow!(cause)),
        }
    }
}

// Based on https://datatracker.ietf.org/doc/html/rfc2616#section-5.1
#[derive(Debug, PartialEq)]
pub enum RequestLine {
    Connect(String),
}

impl FromStr for RequestLine {
    type Err = RequestParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let fields: Vec<&str> = s.split_ascii_whitespace().collect();
        let method = fields.first().ok_or(RequestParseError::ReqLineNoMethod)?;
        let req_uri = fields.get(1).ok_or(RequestParseError::ReqLineNoUri)?;
        if method.to_uppercase() == PROXY_CONNECTION_VERB {
            Ok(RequestLine::Connect(req_uri.to_string()))
        } else {
            Err(RequestParseError::ReqLineUnsupportedMethod(s.to_string()))
        }
    }
}

#[derive(Debug)]
pub struct Request {
    pub req_line: RequestLine,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, PartialEq, Error)]
pub enum RequestParseError {
    #[error("No headers block")]
    NoHdrsBlock,

    #[error("No request line")]
    NoReqLine,

    #[error("No data")]
    ReadErrorNoData,

    #[error("No method in request line")]
    ReqLineNoMethod,

    #[error("No uri in request line")]
    ReqLineNoUri,

    #[error("Unsupported request line method. Request line str: '{0}'")]
    ReqLineUnsupportedMethod(String),
}

impl TryFrom<&Vec<u8>> for Request {
    type Error = RequestParseError;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Request::try_from(value.as_slice())
    }
}

// based on https://datatracker.ietf.org/doc/html/rfc2616#section-5
// data example: CONNECT www.freebsd.org:443 HTTP/1.1\r\nHost: www.freebsd.org:443\r\nUser-Agent: curl/8.4.0\r\nProxy-Connection: Keep-Alive\r\n\r\n\
impl TryFrom<&[u8]> for Request {
    type Error = RequestParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match find(value, "\r\n\r\n".as_bytes()) {
            Some(idx) => {
                let (hdrs, _) = value.split_at(idx);

                let hdrs = String::from_utf8_lossy(hdrs);
                let lines: Vec<&str> = hdrs.split("\r\n").collect();

                let req_line = lines.first().ok_or(RequestParseError::NoReqLine)?.parse()?;

                let headers = lines
                    .get(1..)
                    .unwrap_or_default()
                    .iter()
                    .map(|hdr_line| {
                        let fields: Vec<&str> = hdr_line.split_whitespace().collect();
                        let k = fields.first().map(|it| it.trim_end_matches(':').to_owned());
                        let v = fields.get(1).map(|it| it.to_owned());
                        (k, v)
                    })
                    .filter(|kvp| kvp.0.is_some() && kvp.1.is_some())
                    .map(|kvp| {
                        (
                            kvp.0.unwrap().trim().to_owned(),
                            kvp.1.unwrap().trim().to_owned(),
                        )
                    })
                    .collect::<HashMap<String, String>>();

                Ok(Self { req_line, headers })
            }
            None => Err(RequestParseError::NoHdrsBlock),
        }
    }
}

#[cfg(test)]
mod tests {

    use std::collections::HashMap;

    use super::*;

    #[test]
    fn test_request_parse() {
        let req: Request = "CONNECT www.freebsd.org:443 HTTP/1.1\r\n\
            Host: www.freebsd.org:443\r\n\
            User-Agent: curl/8.4.0\r\n\
            Proxy-Connection: Keep-Alive\r\n\
            SomeBrokenLineWillBeSkipped\r\n\
            Some-Fake-Hdr: Some-Fake-Value\r\n\r\n"
            .as_bytes()
            .try_into()
            .unwrap();

        assert_eq!(
            req.req_line,
            RequestLine::Connect("www.freebsd.org:443".to_string())
        );

        let mut exp_hdrs = HashMap::new();
        exp_hdrs.insert("Host".to_string(), "www.freebsd.org:443".to_string());
        exp_hdrs.insert("Proxy-Connection".to_string(), "Keep-Alive".to_string());
        exp_hdrs.insert("User-Agent".to_string(), "curl/8.4.0".to_string());
        exp_hdrs.insert("Some-Fake-Hdr".to_string(), "Some-Fake-Value".to_string());

        assert_eq!(req.headers, exp_hdrs);
    }

    #[test]
    fn test_request_parse_errors() {
        assert_eq!(
            Request::try_from("\r\n\r\n".as_bytes()).unwrap_err(),
            RequestParseError::ReqLineNoMethod
        );

        assert_eq!(
            Request::try_from("CONNECT\r\n\r\n".as_bytes()).unwrap_err(),
            RequestParseError::ReqLineNoUri
        );

        assert_eq!(
            Request::try_from("CONNECT www.freebsd.org:443 HTTP/1.1\r\n".as_bytes()).unwrap_err(),
            RequestParseError::NoHdrsBlock
        );

        assert_eq!(
            Request::try_from("OPTIONS www.freebsd.org:443 HTTP/1.1\r\n\r\n".as_bytes())
                .unwrap_err(),
            RequestParseError::ReqLineUnsupportedMethod(
                "OPTIONS www.freebsd.org:443 HTTP/1.1".to_string()
            )
        );
    }
}
