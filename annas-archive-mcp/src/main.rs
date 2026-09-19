mod server;
mod tools;

use std::env;

use rmcp::{ServiceExt, transport::io::stdio};
use server::AnnasArchiveServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let api_key = env::var("ANNAS_ARCHIVE_API_KEY").ok();
    let domains = env::var("ANNAS_ARCHIVE_DOMAINS").ok().map(|val| {
        val.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    });
    let server = AnnasArchiveServer::new(api_key, domains);

    let service = server.serve(stdio()).await?;
    service.waiting().await?;

    Ok(())
}
