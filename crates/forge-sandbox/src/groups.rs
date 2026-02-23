//! Server group enforcement for cross-server data flow policies.
//!
//! Groups define isolation boundaries between sets of MCP servers. When a group
//! uses "strict" isolation, the first tool call in an execution locks the
//! execution to that group — subsequent calls to servers in a different strict
//! group are denied.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::ToolDispatcher;

/// Isolation mode for a server group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationMode {
    /// Strict: once an execution calls a server in this group, it cannot call
    /// servers in a different strict group.
    Strict,
    /// Open: servers in this group can be called from any execution regardless
    /// of which groups have been accessed.
    Open,
}

/// Compiled group policy (immutable, shared across executions).
#[derive(Debug, Clone)]
pub struct GroupPolicy {
    server_to_group: HashMap<String, String>,
    group_isolation: HashMap<String, IsolationMode>,
}

impl GroupPolicy {
    /// Build a group policy from config group definitions.
    ///
    /// Each entry in `groups` maps a group name to (server list, isolation mode string).
    pub fn from_config(groups: &HashMap<String, (Vec<String>, String)>) -> Self {
        let mut server_to_group = HashMap::new();
        let mut group_isolation = HashMap::new();

        for (group_name, (servers, isolation)) in groups {
            let mode = match isolation.as_str() {
                "strict" => IsolationMode::Strict,
                _ => IsolationMode::Open,
            };
            group_isolation.insert(group_name.clone(), mode);
            for server in servers {
                server_to_group.insert(server.clone(), group_name.clone());
            }
        }

        Self {
            server_to_group,
            group_isolation,
        }
    }

    /// Returns true if no groups are configured.
    pub fn is_empty(&self) -> bool {
        self.group_isolation.is_empty()
    }

    /// Look up which group a server belongs to and its isolation mode.
    pub fn server_group(&self, server: &str) -> Option<(&str, IsolationMode)> {
        self.server_to_group.get(server).map(|group| {
            let mode = self
                .group_isolation
                .get(group)
                .copied()
                .unwrap_or(IsolationMode::Open);
            (group.as_str(), mode)
        })
    }
}

/// A [`ToolDispatcher`] that enforces group isolation policies.
///
/// Created fresh for each execution. The first call to a strict-group server
/// "locks" this dispatcher to that group for the duration of the execution.
pub struct GroupEnforcingDispatcher {
    inner: Arc<dyn ToolDispatcher>,
    policy: Arc<GroupPolicy>,
    locked_group: Mutex<Option<String>>,
}

impl GroupEnforcingDispatcher {
    /// Create a new group-enforcing dispatcher for a single execution.
    pub fn new(inner: Arc<dyn ToolDispatcher>, policy: Arc<GroupPolicy>) -> Self {
        Self {
            inner,
            policy,
            locked_group: Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl ToolDispatcher for GroupEnforcingDispatcher {
    async fn call_tool(&self, server: &str, tool: &str, args: Value) -> Result<Value> {
        // Look up the server's group and isolation mode
        if let Some((group, mode)) = self.policy.server_group(server) {
            if mode == IsolationMode::Strict {
                let mut locked = self.locked_group.lock().await;
                match &*locked {
                    None => {
                        // First strict-group call: lock to this group
                        *locked = Some(group.to_string());
                    }
                    Some(existing) if existing == group => {
                        // Same strict group: allowed
                    }
                    Some(existing) => {
                        return Err(anyhow::anyhow!(
                            "cross-group call denied: server '{}' is in strict group '{}', \
                             but this execution is locked to strict group '{}'",
                            server,
                            group,
                            existing,
                        ));
                    }
                }
            }
            // Open-group servers always pass through
        }
        // Ungrouped servers always pass through

        self.inner.call_tool(server, tool, args).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDispatcher;

    #[async_trait::async_trait]
    impl ToolDispatcher for MockDispatcher {
        async fn call_tool(&self, server: &str, tool: &str, _args: Value) -> Result<Value> {
            Ok(serde_json::json!({"server": server, "tool": tool}))
        }
    }

    fn make_policy(groups: &[(&str, &[&str], &str)]) -> Arc<GroupPolicy> {
        let mut map = HashMap::new();
        for (name, servers, isolation) in groups {
            map.insert(
                name.to_string(),
                (
                    servers.iter().map(|s| s.to_string()).collect(),
                    isolation.to_string(),
                ),
            );
        }
        Arc::new(GroupPolicy::from_config(&map))
    }

    #[tokio::test]
    async fn ungrouped_server_always_allowed() {
        let policy = make_policy(&[("internal", &["vault"], "strict")]);
        let dispatcher = GroupEnforcingDispatcher::new(Arc::new(MockDispatcher), policy);

        let result = dispatcher
            .call_tool("ungrouped", "tool", serde_json::json!({}))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn open_group_always_allowed() {
        let policy = make_policy(&[
            ("internal", &["vault"], "strict"),
            ("analysis", &["narsil"], "open"),
        ]);
        let dispatcher = GroupEnforcingDispatcher::new(Arc::new(MockDispatcher), policy);

        // Call strict group first
        let _ = dispatcher
            .call_tool("vault", "secrets.list", serde_json::json!({}))
            .await
            .unwrap();

        // Open group should still be allowed
        let result = dispatcher
            .call_tool("narsil", "scan", serde_json::json!({}))
            .await;
        assert!(result.is_ok(), "open group should be allowed after strict");
    }

    #[tokio::test]
    async fn strict_group_locks_execution() {
        let policy = make_policy(&[
            ("internal", &["vault", "database"], "strict"),
            ("external", &["slack"], "strict"),
        ]);
        let dispatcher = GroupEnforcingDispatcher::new(Arc::new(MockDispatcher), policy);

        // First call to strict group: locks to "internal"
        let result = dispatcher
            .call_tool("vault", "secrets.list", serde_json::json!({}))
            .await;
        assert!(result.is_ok());

        // Same strict group: allowed
        let result = dispatcher
            .call_tool("database", "query", serde_json::json!({}))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn cross_strict_group_denied() {
        let policy = make_policy(&[
            ("internal", &["vault"], "strict"),
            ("external", &["slack"], "strict"),
        ]);
        let dispatcher = GroupEnforcingDispatcher::new(Arc::new(MockDispatcher), policy);

        // Lock to "internal"
        let _ = dispatcher
            .call_tool("vault", "secrets.list", serde_json::json!({}))
            .await
            .unwrap();

        // Try "external" — should be denied
        let result = dispatcher
            .call_tool("slack", "messages.send", serde_json::json!({}))
            .await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("cross-group"),
            "should mention cross-group: {msg}"
        );
        assert!(msg.contains("slack"), "should mention server: {msg}");
        assert!(
            msg.contains("external"),
            "should mention target group: {msg}"
        );
        assert!(
            msg.contains("internal"),
            "should mention locked group: {msg}"
        );
    }

    #[tokio::test]
    async fn open_group_after_strict_allowed() {
        let policy = make_policy(&[
            ("internal", &["vault"], "strict"),
            ("tools", &["narsil"], "open"),
        ]);
        let dispatcher = GroupEnforcingDispatcher::new(Arc::new(MockDispatcher), policy);

        let _ = dispatcher
            .call_tool("vault", "secrets.list", serde_json::json!({}))
            .await
            .unwrap();

        let result = dispatcher
            .call_tool("narsil", "scan", serde_json::json!({}))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn ungrouped_after_strict_allowed() {
        let policy = make_policy(&[("internal", &["vault"], "strict")]);
        let dispatcher = GroupEnforcingDispatcher::new(Arc::new(MockDispatcher), policy);

        let _ = dispatcher
            .call_tool("vault", "secrets.list", serde_json::json!({}))
            .await
            .unwrap();

        let result = dispatcher
            .call_tool("random", "tool", serde_json::json!({}))
            .await;
        assert!(result.is_ok(), "ungrouped server should be allowed");
    }

    #[tokio::test]
    async fn fresh_dispatcher_is_unlocked() {
        let policy = make_policy(&[
            ("internal", &["vault"], "strict"),
            ("external", &["slack"], "strict"),
        ]);

        // First execution: lock to internal
        let d1 = GroupEnforcingDispatcher::new(Arc::new(MockDispatcher), policy.clone());
        let _ = d1
            .call_tool("vault", "secrets.list", serde_json::json!({}))
            .await
            .unwrap();

        // Second execution: fresh, should be able to use external
        let d2 = GroupEnforcingDispatcher::new(Arc::new(MockDispatcher), policy);
        let result = d2
            .call_tool("slack", "messages.send", serde_json::json!({}))
            .await;
        assert!(result.is_ok(), "fresh dispatcher should be unlocked");
    }

    #[tokio::test]
    async fn empty_policy_allows_everything() {
        let policy = Arc::new(GroupPolicy::from_config(&HashMap::new()));
        assert!(policy.is_empty());

        let dispatcher = GroupEnforcingDispatcher::new(Arc::new(MockDispatcher), policy);
        let result = dispatcher
            .call_tool("any", "tool", serde_json::json!({}))
            .await;
        assert!(result.is_ok());
    }

    #[test]
    fn policy_server_group_lookup() {
        let policy = make_policy(&[
            ("internal", &["vault", "db"], "strict"),
            ("external", &["slack"], "open"),
        ]);

        let (group, mode) = policy.server_group("vault").unwrap();
        assert_eq!(group, "internal");
        assert_eq!(mode, IsolationMode::Strict);

        let (group, mode) = policy.server_group("slack").unwrap();
        assert_eq!(group, "external");
        assert_eq!(mode, IsolationMode::Open);

        assert!(policy.server_group("unknown").is_none());
    }

    #[test]
    fn policy_from_config_handles_empty() {
        let policy = GroupPolicy::from_config(&HashMap::new());
        assert!(policy.is_empty());
    }

    #[tokio::test]
    async fn error_message_is_actionable() {
        let policy = make_policy(&[
            ("secrets", &["vault"], "strict"),
            ("comms", &["slack"], "strict"),
        ]);
        let dispatcher = GroupEnforcingDispatcher::new(Arc::new(MockDispatcher), policy);

        let _ = dispatcher
            .call_tool("vault", "read", serde_json::json!({}))
            .await
            .unwrap();

        let err = dispatcher
            .call_tool("slack", "send", serde_json::json!({}))
            .await
            .unwrap_err();
        let msg = err.to_string();
        // Should contain enough info for the LLM to understand what happened
        assert!(msg.contains("denied"));
        assert!(msg.contains("slack"));
        assert!(msg.contains("comms"));
        assert!(msg.contains("secrets"));
    }
}
