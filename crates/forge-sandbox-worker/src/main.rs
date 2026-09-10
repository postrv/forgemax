//! Forge sandbox worker — isolated child process for V8 execution.
//!
//! Thin binary wrapper around [`forge_sandbox_worker::run`].

use anyhow::Result;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    forge_sandbox_worker::run().await
}
