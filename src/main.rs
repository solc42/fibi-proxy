use clap::Parser as _;
use cli::{AppArgs, LogStyle};
use color_eyre::Result;
use srv::server::Server;
use tracing_error::ErrorLayer;
use tracing_subscriber::layer::SubscriberExt;

mod cli;
mod commands;
mod srv;

#[tokio::main]
async fn main() -> Result<()> {
    let args = AppArgs::parse();

    init_logs(&args);
    Server::new(
        args.lsn_addr,
        args.relay_opts,
        args.ip_whitelist.unwrap_or_default(),
    )
    .await?
    .run()
    .await?;

    Ok(())
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

    use crate::cli::WhiteList;

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
