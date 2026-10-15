//! tterm-server 進入點。
//!
//! 用法:
//!   tterm-server [--listen 0.0.0.0:8722] [--data ./data]
//! 或環境變數 TTERM_LISTEN / TTERM_DATA(命令列優先)。

use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let mut listen = std::env::var("TTERM_LISTEN").unwrap_or_else(|_| "0.0.0.0:8722".into());
    let mut data = std::env::var("TTERM_DATA").unwrap_or_else(|_| "data".into());

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" if i + 1 < args.len() => {
                listen = args[i + 1].clone();
                i += 2;
            }
            "--data" if i + 1 < args.len() => {
                data = args[i + 1].clone();
                i += 2;
            }
            "--help" | "-h" => {
                eprintln!("tterm-server [--listen 0.0.0.0:8722] [--data ./data]");
                return Ok(());
            }
            other => anyhow::bail!("未知參數:{other}(--help 看用法)"),
        }
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(tterm_server::serve(&listen, &PathBuf::from(data)))
}
