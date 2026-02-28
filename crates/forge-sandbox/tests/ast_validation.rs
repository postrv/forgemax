//! Integration tests for the AST validator running through the full execute_code path.
//!
//! These tests verify that the AST validator correctly rejects bypass attempts
//! and accepts legitimate code when wired into the executor pipeline.

#![cfg(feature = "ast-validator")]

use forge_sandbox::{ExecutionMode, SandboxConfig, SandboxExecutor, ToolDispatcher};
use std::sync::Arc;

struct StubDispatcher;

#[async_trait::async_trait]
impl ToolDispatcher for StubDispatcher {
    async fn call_tool(
        &self,
        server: &str,
        tool: &str,
        _args: serde_json::Value,
    ) -> Result<serde_json::Value, forge_error::DispatchError> {
        Ok(serde_json::json!({"server": server, "tool": tool}))
    }
}

fn executor() -> SandboxExecutor {
    SandboxExecutor::new(SandboxConfig {
        execution_mode: ExecutionMode::InProcess,
        ..Default::default()
    })
}

/// AST-I01: Bracket constructor bypass is caught through the full pipeline.
#[tokio::test]
async fn ast_i01_bracket_constructor_bypass_rejected() {
    let exec = executor();
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(StubDispatcher);

    let code = r#"async () => { ""["constructor"]["constructor"]("return this")(); }"#;
    let err = exec.execute_code(code, dispatcher, None, None).await;
    assert!(
        err.is_err(),
        "bracket constructor bypass should be rejected"
    );
}

/// AST-I02: String.raw tagged template bypass is caught.
#[tokio::test]
async fn ast_i02_string_raw_tagged_template_rejected() {
    let exec = executor();
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(StubDispatcher);

    let code = r#"async () => { String.raw`\x61\x62\x63`; }"#;
    let err = exec.execute_code(code, dispatcher, None, None).await;
    assert!(
        err.is_err(),
        "String.raw tagged template should be rejected"
    );
}

/// AST-I03: Proxy constructor bypass is caught.
#[tokio::test]
async fn ast_i03_proxy_constructor_rejected() {
    let exec = executor();
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(StubDispatcher);

    let code = r#"async () => { new Proxy({}, { get: (t, p) => t[p] }); }"#;
    let err = exec.execute_code(code, dispatcher, None, None).await;
    assert!(err.is_err(), "Proxy constructor should be rejected");
}

/// AST-I04: Legitimate forge code passes through the full pipeline.
#[tokio::test]
async fn ast_i04_legitimate_code_passes() {
    let exec = executor();
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(StubDispatcher);

    let code = r#"async () => {
        const result = await forge.callTool("myserver", "search", { q: "test" });
        return result;
    }"#;
    let result = exec
        .execute_code(code, dispatcher, None, None)
        .await
        .unwrap();
    assert_eq!(result["server"], "myserver");
    assert_eq!(result["tool"], "search");
}
