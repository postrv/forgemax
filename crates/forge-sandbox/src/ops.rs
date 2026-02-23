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

use crate::ToolDispatcher;

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
        .map_err(|e| JsErrorBox::generic(format!("tool call failed: {e}")))?;

    serde_json::to_string(&result)
        .map_err(|e| JsErrorBox::generic(format!("result serialization failed: {e}")))
}

/// Wrapper for execution results stored in OpState.
pub struct ExecutionResult(pub String);

deno_core::extension!(
    forge_ext,
    ops = [op_forge_log, op_forge_set_result, op_forge_call_tool],
);
