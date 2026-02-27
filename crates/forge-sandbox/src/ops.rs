//! deno_core op definitions for the Forge sandbox.
//!
//! The `#[op2]` macro generates additional public items (v8 function pointers,
//! metadata structs) that cannot carry doc comments. We suppress `missing_docs`
//! at the module level — all actual functions and types are documented below.
#![allow(missing_docs)]

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use deno_core::op2;
use deno_core::OpState;
use deno_error::JsErrorBox;

use std::collections::HashSet;

use crate::{ResourceDispatcher, StashDispatcher, ToolDispatcher};

/// Rate limiting state for tool calls within a single execution.
pub struct ToolCallLimits {
    /// Maximum number of tool calls allowed.
    pub max_calls: usize,
    /// Maximum size of serialized arguments per call.
    pub max_args_size: usize,
    /// Number of tool calls made so far.
    pub calls_made: usize,
}

/// Log a message from sandbox code.
#[op2(fast)]
pub fn op_forge_log(#[string] msg: &str) {
    tracing::info!(target: "forge::sandbox::js", "{}", msg);
}

/// Store the execution result in OpState.
#[op2(fast)]
pub fn op_forge_set_result(state: &mut OpState, #[string] json: &str) {
    state.put(ExecutionResult(json.to_string()));
}

/// Call a tool on a downstream server via the ToolDispatcher.
///
/// Enforces per-execution rate limiting and argument size limits via
/// [`ToolCallLimits`] stored in OpState.
#[op2]
#[string]
pub async fn op_forge_call_tool(
    op_state: Rc<RefCell<OpState>>,
    #[string] server: String,
    #[string] tool: String,
    #[string] args_json: String,
) -> Result<String, JsErrorBox> {
    tracing::debug!(
        server = %server,
        tool = %tool,
        args_len = args_json.len(),
        "tool call dispatched"
    );

    // Check and increment tool call limits
    {
        let mut st = op_state.borrow_mut();
        let limits = st.borrow_mut::<ToolCallLimits>();
        if limits.calls_made >= limits.max_calls {
            return Err(JsErrorBox::generic(format!(
                "tool call limit exceeded (max {} calls per execution)",
                limits.max_calls
            )));
        }
        if args_json.len() > limits.max_args_size {
            return Err(JsErrorBox::generic(format!(
                "tool call args too large ({} bytes, max {} bytes)",
                args_json.len(),
                limits.max_args_size
            )));
        }
        limits.calls_made += 1;
    }

    let dispatcher = {
        let st = op_state.borrow();
        st.borrow::<Arc<dyn ToolDispatcher>>().clone()
    };

    let args: serde_json::Value = serde_json::from_str(&args_json)
        .map_err(|e| JsErrorBox::generic(format!("invalid JSON args: {e}")))?;

    let result = dispatcher
        .call_tool(&server, &tool, args)
        .await
        .map_err(|e| {
            JsErrorBox::generic(crate::redact::redact_error_for_llm(
                &server,
                &tool,
                &e.to_string(),
            ))
        })?;

    serde_json::to_string(&result)
        .map_err(|e| JsErrorBox::generic(format!("result serialization failed: {e}")))
}

/// Wrapper for execution results stored in OpState.
pub struct ExecutionResult(pub String);

/// Wrapper for the maximum resource content size, stored in OpState.
pub struct MaxResourceSize(pub usize);

/// Wrapper for the current server group, stored in OpState.
///
/// Used by stash ops to enforce group isolation. `None` means ungrouped.
pub struct CurrentGroup(pub Option<String>);

/// Set of known server names for SR-R6 validation.
///
/// Stored in OpState so `op_forge_read_resource` can reject unknown servers
/// before any dispatch machinery runs.
pub struct KnownServers(pub HashSet<String>);

/// Validate a resource URI for security.
///
/// Rejects:
/// - URIs containing `..` (path traversal)
/// - URIs longer than 2048 bytes
/// - URIs containing null bytes
/// - URIs containing control characters (U+0000..U+001F, U+007F)
fn validate_resource_uri(uri: &str) -> Result<(), String> {
    if uri.len() > 2048 {
        return Err(format!(
            "resource URI too long ({} bytes, max 2048 bytes)",
            uri.len()
        ));
    }
    if uri.contains("..") {
        return Err("resource URI must not contain '..' (path traversal)".into());
    }
    if uri.bytes().any(|b| b == 0) {
        return Err("resource URI must not contain null bytes".into());
    }
    if uri.chars().any(|c| c.is_control()) {
        return Err("resource URI must not contain control characters".into());
    }
    Ok(())
}

/// Read a resource by URI from a downstream server via the ResourceDispatcher.
///
/// Enforces URI validation (SR-R1), per-execution rate limiting (SR-R3),
/// max resource size truncation (SR-R2), and error redaction (SR-R5).
#[op2]
#[string]
pub async fn op_forge_read_resource(
    op_state: Rc<RefCell<OpState>>,
    #[string] server: String,
    #[string] uri: String,
) -> Result<String, JsErrorBox> {
    tracing::debug!(
        server = %server,
        uri = %uri,
        "resource read dispatched"
    );

    // SR-R1: Validate URI
    validate_resource_uri(&uri).map_err(JsErrorBox::generic)?;

    // SR-R6: Reject unknown server names before dispatch
    {
        let st = op_state.borrow();
        if let Some(known) = st.try_borrow::<KnownServers>() {
            if !known.0.contains(&server) {
                return Err(JsErrorBox::generic(format!("unknown server: '{server}'")));
            }
        }
    }

    // SR-R3: Check and increment tool call limits (shared with tool calls)
    {
        let mut st = op_state.borrow_mut();
        let limits = st.borrow_mut::<ToolCallLimits>();
        if limits.calls_made >= limits.max_calls {
            return Err(JsErrorBox::generic(format!(
                "tool call limit exceeded (max {} calls per execution)",
                limits.max_calls
            )));
        }
        limits.calls_made += 1;
    }

    // Get dispatcher and max_resource_size from OpState
    let (dispatcher, max_resource_size) = {
        let st = op_state.borrow();
        let d = st.borrow::<Arc<dyn ResourceDispatcher>>().clone();
        let max_size = st
            .try_borrow::<MaxResourceSize>()
            .map(|m| m.0)
            .unwrap_or(64 * 1024 * 1024); // 64 MB default
        (d, max_size)
    };

    let result = dispatcher.read_resource(&server, &uri).await.map_err(|e| {
        // SR-R5: Use "readResource" instead of the raw URI to prevent path leakage
        JsErrorBox::generic(crate::redact::redact_error_for_llm(
            &server,
            "readResource",
            &e.to_string(),
        ))
    })?;

    // SR-R2: Serialize and truncate if > max_resource_size
    let mut json = serde_json::to_string(&result)
        .map_err(|e| JsErrorBox::generic(format!("result serialization failed: {e}")))?;

    if json.len() > max_resource_size {
        // Truncate to max_resource_size and ensure valid UTF-8 at boundary
        let truncated = &json[..max_resource_size];
        // Find the last valid UTF-8 char boundary
        let end = truncated
            .char_indices()
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        json = json[..end].to_string();
    }

    Ok(json)
}

/// Store a value in the session stash via the StashDispatcher.
///
/// - `key`: The stash key (alphanumeric + `_-.:`).
/// - `value_json`: JSON-serialized value to store.
/// - `ttl_secs`: TTL in seconds; 0 means use server default.
#[op2]
#[string]
pub async fn op_forge_stash_put(
    op_state: Rc<RefCell<OpState>>,
    #[string] key: String,
    #[string] value_json: String,
    #[smi] ttl_secs: u32,
) -> Result<String, JsErrorBox> {
    let (dispatcher, current_group) = {
        let st = op_state.borrow();
        let d = st.borrow::<Arc<dyn StashDispatcher>>().clone();
        let g = st.borrow::<CurrentGroup>().0.clone();
        (d, g)
    };

    let value: serde_json::Value = serde_json::from_str(&value_json)
        .map_err(|e| JsErrorBox::generic(format!("invalid JSON value: {e}")))?;

    let ttl = if ttl_secs == 0 { None } else { Some(ttl_secs) };

    let result = dispatcher
        .put(&key, value, ttl, current_group)
        .await
        .map_err(|e| JsErrorBox::generic(e.to_string()))?;

    serde_json::to_string(&result)
        .map_err(|e| JsErrorBox::generic(format!("result serialization failed: {e}")))
}

/// Retrieve a value from the session stash via the StashDispatcher.
#[op2]
#[string]
pub async fn op_forge_stash_get(
    op_state: Rc<RefCell<OpState>>,
    #[string] key: String,
) -> Result<String, JsErrorBox> {
    let (dispatcher, current_group) = {
        let st = op_state.borrow();
        let d = st.borrow::<Arc<dyn StashDispatcher>>().clone();
        let g = st.borrow::<CurrentGroup>().0.clone();
        (d, g)
    };

    let result = dispatcher
        .get(&key, current_group)
        .await
        .map_err(|e| JsErrorBox::generic(e.to_string()))?;

    serde_json::to_string(&result)
        .map_err(|e| JsErrorBox::generic(format!("result serialization failed: {e}")))
}

/// Delete an entry from the session stash via the StashDispatcher.
#[op2]
#[string]
pub async fn op_forge_stash_delete(
    op_state: Rc<RefCell<OpState>>,
    #[string] key: String,
) -> Result<String, JsErrorBox> {
    let (dispatcher, current_group) = {
        let st = op_state.borrow();
        let d = st.borrow::<Arc<dyn StashDispatcher>>().clone();
        let g = st.borrow::<CurrentGroup>().0.clone();
        (d, g)
    };

    let result = dispatcher
        .delete(&key, current_group)
        .await
        .map_err(|e| JsErrorBox::generic(e.to_string()))?;

    serde_json::to_string(&result)
        .map_err(|e| JsErrorBox::generic(format!("result serialization failed: {e}")))
}

/// List all keys visible to the current group from the session stash.
#[op2]
#[string]
pub async fn op_forge_stash_keys(op_state: Rc<RefCell<OpState>>) -> Result<String, JsErrorBox> {
    let (dispatcher, current_group) = {
        let st = op_state.borrow();
        let d = st.borrow::<Arc<dyn StashDispatcher>>().clone();
        let g = st.borrow::<CurrentGroup>().0.clone();
        (d, g)
    };

    let result = dispatcher
        .keys(current_group)
        .await
        .map_err(|e| JsErrorBox::generic(e.to_string()))?;

    serde_json::to_string(&result)
        .map_err(|e| JsErrorBox::generic(format!("result serialization failed: {e}")))
}

deno_core::extension!(
    forge_ext,
    ops = [
        op_forge_log,
        op_forge_set_result,
        op_forge_call_tool,
        op_forge_read_resource,
        op_forge_stash_put,
        op_forge_stash_get,
        op_forge_stash_delete,
        op_forge_stash_keys
    ],
);

#[cfg(test)]
mod tests {
    use super::*;

    // --- RS-U04: reject URIs with path traversal (..) ---
    #[test]
    fn rs_u04_rejects_uri_with_path_traversal() {
        assert!(validate_resource_uri("file:///logs/../../../etc/passwd").is_err());
        assert!(validate_resource_uri("file:///..").is_err());
        assert!(validate_resource_uri("..").is_err());
        assert!(validate_resource_uri("a/../../b").is_err());
        // Valid URI without traversal should pass
        assert!(validate_resource_uri("file:///logs/app.log").is_ok());
        assert!(validate_resource_uri("postgres://db/table").is_ok());
    }

    // --- RS-U05: reject URIs longer than 2048 bytes ---
    #[test]
    fn rs_u05_rejects_uri_longer_than_2048_bytes() {
        let long_uri = "x".repeat(2049);
        let err = validate_resource_uri(&long_uri).unwrap_err();
        assert!(err.contains("too long"), "should mention too long: {err}");

        // Exactly 2048 should be OK
        let ok_uri = "x".repeat(2048);
        assert!(validate_resource_uri(&ok_uri).is_ok());
    }

    // --- RS-U06: reject URIs with null bytes ---
    #[test]
    fn rs_u06_rejects_uri_with_null_bytes() {
        let uri = "file:///logs\0/app.log";
        let err = validate_resource_uri(uri).unwrap_err();
        assert!(err.contains("null"), "should mention null: {err}");
    }

    // --- RS-U07: reject URIs with control characters ---
    #[test]
    fn rs_u07_rejects_uri_with_control_characters() {
        // SOH (0x01)
        let err = validate_resource_uri("file:///logs\x01/app.log").unwrap_err();
        assert!(err.contains("control"), "should mention control: {err}");

        // Tab (0x09)
        assert!(validate_resource_uri("file:///logs\t/app.log").is_err());

        // Newline (0x0A)
        assert!(validate_resource_uri("file:///logs\n/app.log").is_err());

        // DEL (0x7F)
        assert!(validate_resource_uri("file:///logs\x7f/app.log").is_err());
    }

    // --- RS-S04: path traversal attack variants ---
    #[test]
    fn rs_s04_path_traversal_attack_variants() {
        // Classic traversal
        assert!(validate_resource_uri("../../../etc/passwd").is_err());
        // Traversal with URL-encoded characters still contains ".."
        assert!(validate_resource_uri("file:///logs/..%2F..%2Fetc/passwd").is_err());
        // Double dots at start
        assert!(validate_resource_uri("..").is_err());
        // Double dots embedded
        assert!(validate_resource_uri("file:///../").is_err());
        // Traversal after normal path
        assert!(validate_resource_uri("file:///a/b/../../../etc/shadow").is_err());
    }
}
