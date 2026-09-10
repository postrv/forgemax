//! `forgemax-worker` binary shipped by the `forgemax` crate.
//!
//! `cargo install forgemax` must install both the gateway and the isolated
//! worker. Release archives already include both; this second bin target
//! makes the crates.io install path match.

use anyhow::Result;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    forge_sandbox_worker::run().await
}
