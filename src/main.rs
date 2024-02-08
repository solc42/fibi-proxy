use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr},
};

use srv::server::Server;

use clap::{Args, Parser, ValueEnum};
use color_eyre::Result;
use strum_macros::{Display, EnumString};
use tracing::Level;
use tracing_error::ErrorLayer;
use tracing_subscriber::layer::SubscriberExt;

mod commands;
mod srv;

#[tokio::main]
async fn main() -> Result<()> {
    let args = AppArgs::parse();

    init_logs(&args);
    Server::new_wl(
        args.lsn_addr,
        args.relay_opts,
        args.ip_whitelist.unwrap_or_default(),
    )
    .await?
    .run()
    .await?;

    Ok(())
}

#[derive(Parser, Debug)]
struct AppArgs {
    /// listen addr
    #[arg(
        short = 'l',
        long,
        default_value = "127.0.0.1:9002",
        verbatim_doc_comment
    )]
    lsn_addr: SocketAddr,

    /// log style format
    #[arg(
        short = 'L',
        long = "log-style",
        default_value_t = LogStyle::Pretty,
    )]
    log_style: LogStyle,

    /// log verbosity level
    #[arg(short = 'd', long="debug_lvl", default_value_t = Level::WARN)]
    log_level: Level,

    #[command(flatten)]
    relay_opts: Option<Relay>,

    /// coma separated list of ipv4 to be treated as whitelist
    /// any - to allow all
    /// localhost/127.0.0.1 - to allow localhost
    /// if nothing specified - only localhost will be allowed
    /// e.g.: 192.168.0.1,192.168.0.2
    #[arg(short = 'w', long, verbatim_doc_comment, value_parser = whitelist_parser)]
    ip_whitelist: Option<WhiteList>,
}

#[derive(Args, Debug, Clone)]
#[group(required = false, multiple = true)]
pub struct Relay {
    /// relay mode
    #[arg(short, long = "relay-mode", verbatim_doc_comment)]
    mode: Option<DataModificationType>,

    /// in relay mode spcifies remote proxy addr in form "host:port"
    /// e.g.: 192.168.1.1:1234
    #[arg(short, long = "relay-to-addr", verbatim_doc_comment)]
    relay_to_addr: Option<SocketAddr>,
}

#[derive(ValueEnum, EnumString, Clone, Debug, Display)]
#[strum(serialize_all = "kebab_case")]
pub enum DataModificationType {
    ///[alias: ia]
    /// inplace data modification, by add/sub some byte modifier value u8 with overflow
    /// stupid as hell
    #[value(alias = "ia", verbatim_doc_comment)]
    InplaceAdd, //TODO: add customizable modificator value
}

#[derive(Debug, Clone, PartialEq, Default)]
pub enum WhiteList {
    Ips(HashSet<Ipv4Addr>),
    Any,
    #[default]
    Localhost,
}

impl TryFrom<&str> for WhiteList {
    type Error = String;
    fn try_from(value: &str) -> std::result::Result<Self, String> {
        if value == "any" {
            return Ok(WhiteList::Any);
        }

        if value == "localhost" {
            return Ok(WhiteList::Localhost);
        }

        let res: Result<HashSet<Ipv4Addr>, String> = value
            .split(',')
            .map(|it| {
                it.trim()
                    .parse()
                    .map_err(|c| format!("Failed to parse ip from string. Details: {}", c))
            })
            .collect();

        let ips = res?;

        Ok(WhiteList::Ips(ips))
    }
}

fn whitelist_parser(src: &str) -> Result<WhiteList, String> {
    let res = WhiteList::try_from(src)?;
    Ok(res)
}

#[derive(ValueEnum, Clone, Debug, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
enum LogStyle {
    /// [alias: c]
    /// each line contains full event description
    #[value(alias = "c", verbatim_doc_comment)]
    Compact,

    /// [alias: p]
    /// multiline event description with context, line numbers etc
    #[value(alias = "p", verbatim_doc_comment)]
    Pretty,
}

fn init_logs(args: &AppArgs) {
    color_eyre::install().expect("Failed to install color eyre");

    match args.log_style {
        LogStyle::Compact => {
            let sub = tracing_subscriber::fmt()
                .compact()
                .with_max_level(args.log_level)
                .finish()
                .with(ErrorLayer::default());

            tracing::subscriber::set_global_default(sub).expect("Subscrier set failed");
        }
        LogStyle::Pretty => {
            let sub = tracing_subscriber::fmt()
                .pretty()
                .with_max_level(args.log_level)
                .with_line_number(true)
                .with_file(true)
                .with_thread_names(true)
                .finish()
                .with(ErrorLayer::default());

            tracing::subscriber::set_global_default(sub).expect("Subscrier set failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, net::Ipv4Addr};

    use crate::WhiteList;

    #[test]
    fn test_whitelist_try_parse() {
        assert_eq!("any".try_into(), Ok(WhiteList::Any));
        assert_eq!("localhost".try_into(), Ok(WhiteList::Localhost));

        let expected: HashSet<Ipv4Addr> = vec![Ipv4Addr::LOCALHOST, "192.168.0.1".parse().unwrap()]
            .into_iter()
            .collect();

        assert_eq!(
            "127.0.0.1,192.168.0.1".try_into(),
            Ok(WhiteList::Ips(expected.clone()))
        );

        assert_eq!(
            "127.0.0.1 ,  192.168.0.1  ".try_into(),
            Ok(WhiteList::Ips(expected))
        );

        assert_eq!(
            "".try_into(),
            Err::<WhiteList, String>(
                "Failed to parse ip from string. Details: invalid IPv4 address syntax".to_string()
            )
        );

        assert_eq!(
            ",".try_into(),
            Err::<WhiteList, String>(
                "Failed to parse ip from string. Details: invalid IPv4 address syntax".to_string()
            )
        );

        assert_eq!(
            "123.0.0.1,bad_arg".try_into(),
            Err::<WhiteList, String>(
                "Failed to parse ip from string. Details: invalid IPv4 address syntax".to_string()
            )
        );
    }
}
