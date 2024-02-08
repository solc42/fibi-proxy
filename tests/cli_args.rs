use assert_cmd::{assert::OutputAssertExt as _, cargo::CommandCargoExt};
use pretty_assertions::assert_eq;
use std::process::Command;

/**
 * smoke test to control that clap keys configured correctly(e.g. no duplication) from the point of runtime execution.
 * and at the same time help cmd explicit store
 */
#[test]
fn help_stdout_long_smoke_test() {
    let mut app = Command::cargo_bin("fibi-proxy").unwrap();
    let assert = app.arg("--help").assert();

    expect_test::expect_file!["cli_args_data/stdout_help_long.txt"]
        .assert_eq(&String::from_utf8_lossy(&assert.get_output().stdout));
    assert.stderr("").success();
}

#[test]
fn app_failure_runtime_error() {
    let mut app = Command::cargo_bin("fibi-proxy").unwrap();
    let assert = app.arg("-l").arg("127.0.0.1:1").assert();

    let err = String::from_utf8_lossy(&assert.get_output().stderr);

    println!("{:#?}", err);

    assert!(err.contains("Failed to bind at:"));
    //current app behaviour will also produce backtrace, cause traces are good for diag
    //color-eyre trace used
    assert!(err.contains("BACKTRACE"));
    assert!(err.contains("Location"));
    assert.stdout("").failure();
}

#[test]
fn app_failure_invalid_args() {
    let mut app = Command::cargo_bin("fibi-proxy").unwrap();
    let assert = app.arg("-l").arg("127.0.0.1:zzz").assert();

    assert_eq!(
        String::from_utf8_lossy(&assert.get_output().stderr),
        "error: invalid value '127.0.0.1:zzz' for '--lsn-addr <LSN_ADDR>': invalid socket address syntax\n\n\
        For more information, try '--help'.\n"
    );
    assert.stdout("").failure();
}
