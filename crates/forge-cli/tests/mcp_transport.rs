use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{routing::post, Json, Router};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::TcpListener;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

const OLDEST: &str = "2024-11-05";
const LEGACY: &str = "2025-11-25";
const MODERN: &str = "2026-07-28";
const RESOURCE: &str = "fixture://data";
const DEADLINE: Duration = Duration::from_secs(15);
const CATALOG: &str = "async () => Object.fromEntries(manifest.servers.map(s => [s.name, Object.values(s.categories).flatMap(c => c.tools.map(t => t.name))]))";

struct Remote {
    revision: &'static str,
    catalog: Mutex<Option<Vec<&'static str>>>,
    list_delay_ms: AtomicU64,
    expire_next_call: AtomicBool,
    initialized_sessions: AtomicU64,
    calls: Mutex<Vec<String>>,
}

struct Endpoint {
    url: String,
    remote: Arc<Remote>,
    task: JoinHandle<()>,
}

impl Endpoint {
    async fn start(revision: &'static str) -> Self {
        let remote = Arc::new(Remote {
            revision,
            catalog: Mutex::new(Some(vec!["original"])),
            list_delay_ms: AtomicU64::new(0),
            expire_next_call: AtomicBool::new(false),
            initialized_sessions: AtomicU64::new(0),
            calls: Mutex::new(Vec::new()),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let routes = Router::new()
            .route("/mcp", post(downstream))
            .with_state(remote.clone());
        let task = tokio::spawn(async move { axum::serve(listener, routes).await.unwrap() });
        Self { url, remote, task }
    }

    fn config(&self, name: &str) -> String {
        format!(
            "[servers.{name}]\ntransport = \"sse\"\nurl = {:?}\n",
            self.url
        )
    }

    fn set_catalog(&self, tools: Option<Vec<&'static str>>) {
        *self.remote.catalog.lock().unwrap() = tools;
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn downstream(
    State(remote): State<Arc<Remote>>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Response {
    let method = request["method"].as_str().unwrap();
    let modern = remote.revision == MODERN;
    if modern {
        assert_eq!(headers["mcp-protocol-version"], MODERN);
        assert_eq!(headers["mcp-method"], method);
        assert!(!headers.contains_key("mcp-session-id"));
        assert_eq!(
            request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            MODERN
        );
    } else if method == "server/discover" && remote.revision == OLDEST {
        // Older Streamable HTTP servers can require an initialized session here.
        return (
            StatusCode::BAD_REQUEST,
            "Bad Request: Session ID is required",
        )
            .into_response();
    } else if !matches!(method, "initialize" | "server/discover") {
        assert_eq!(headers["mcp-session-id"], "fixture-session");
    }
    let Some(id) = request.get("id") else {
        return StatusCode::ACCEPTED.into_response();
    };
    if method == "tools/list" {
        sleep(Duration::from_millis(
            remote.list_delay_ms.load(Ordering::Relaxed),
        ))
        .await;
    }
    let capabilities = json!({"tools": {}, "resources": {}});
    let result = match method {
        "initialize" if !modern => json!({
            "protocolVersion": remote.revision,
            "capabilities": capabilities,
            "serverInfo": {"name":"fixture", "version":"1"}
        }),
        "server/discover" if modern => json!({
            "resultType":"complete", "ttlMs":0, "cacheScope":"private",
            "supportedVersions":[remote.revision], "capabilities":capabilities,
            "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"fixture","version":"1"}}
        }),
        "tools/list" => match remote.catalog.lock().unwrap().as_ref() {
            Some(names) => json!({
                "tools": names.iter().map(|name| json!({
                    "name": name,
                    "inputSchema": {"type":"object"}
                })).collect::<Vec<_>>()
            }),
            None => {
                return Json(json!({
                    "jsonrpc":"2.0", "id":id,
                    "error":{"code":-32603, "message":"catalog temporarily unavailable"}
                }))
                .into_response();
            }
        },
        "tools/call" => {
            let name = request["params"]["name"].as_str().unwrap();
            if modern {
                assert_eq!(headers["mcp-name"], name);
            }
            remote.calls.lock().unwrap().push(name.to_owned());
            if remote.expire_next_call.swap(false, Ordering::Relaxed) {
                return StatusCode::NOT_FOUND.into_response();
            }
            match request["params"]["arguments"]["test_result"].as_str() {
                Some("tool_error") => {
                    return Json(json!({
                        "jsonrpc":"2.0", "id":id,
                        "result":{"resultType":"complete","isError":true,"structuredContent":{"message":"fixture rejected the input"}}
                    })).into_response();
                }
                Some("rpc_error") => {
                    return Json(json!({
                        "jsonrpc":"2.0", "id":id,
                        "error":{"code":-32603,"message":"fixture reports a broken pipe in its own work"}
                    })).into_response();
                }
                _ => {}
            }
            let output = json!({"echo":name});
            if modern {
                json!({"structuredContent":output})
            } else {
                json!({"content": [], "structuredContent":output})
            }
        }
        "resources/list" => json!({"resources":[{"uri":RESOURCE,"name":"Fixture data"}]}),
        "resources/read" => {
            assert_eq!(request["params"]["uri"], RESOURCE);
            if modern {
                assert_eq!(headers["mcp-name"], RESOURCE);
            }
            json!({"contents":[{"uri":RESOURCE,"text":"{\"fixture\":true}"}]})
        }
        _ => {
            return Json(json!({
                "jsonrpc":"2.0", "id":id,
                "error":{"code":-32601, "message":"method not found"}
            }))
            .into_response();
        }
    };
    let mut result = result;
    if modern {
        result["resultType"] = json!("complete");
        if matches!(method, "tools/list" | "resources/list" | "resources/read") {
            result["ttlMs"] = json!(60_000);
            result["cacheScope"] = json!("private");
        }
    }
    let reply = json!({"jsonrpc":"2.0", "id":id, "result":result});
    if method == "initialize" {
        remote.initialized_sessions.fetch_add(1, Ordering::Relaxed);
        ([("Mcp-Session-Id", "fixture-session")], Json(reply)).into_response()
    } else if (!modern && method == "tools/call") || (modern && method == "resources/read") {
        (
            [("Content-Type", "text/event-stream")],
            format!("event: message\ndata: {reply}\n\n"),
        )
            .into_response()
    } else {
        Json(reply).into_response()
    }
}

struct Gateway {
    child: Child,
    stdin: ChildStdin,
    stdout: Lines<BufReader<ChildStdout>>,
    next_id: u32,
    revision: &'static str,
}

impl Gateway {
    async fn start(dir: &Path, downstream_config: &str, revision: &'static str) -> Self {
        Self::start_with_refresh(dir, downstream_config, revision, 1).await
    }

    async fn start_with_refresh(
        dir: &Path,
        downstream_config: &str,
        revision: &'static str,
        refresh_secs: u64,
    ) -> Self {
        let config = dir.join("forge.toml");
        tokio::fs::write(
            &config,
            format!(
                "{downstream_config}\n[manifest]\nrefresh_interval_secs = {refresh_secs}\n[sandbox]\nexecution_mode = \"in_process\"\n"
            ),
        )
        .await
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_forgemax"))
            .arg("--config")
            .arg(config)
            .current_dir(dir)
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut gateway = Self {
            child,
            stdin,
            stdout,
            next_id: 0,
            revision,
        };
        if revision == MODERN {
            let info = gateway.request("server/discover", json!({})).await;
            assert_eq!(info["resultType"], "complete", "{info}");
            assert!(info["supportedVersions"]
                .as_array()
                .unwrap()
                .contains(&json!(MODERN)));
            assert!(info["capabilities"]["tools"].is_object());
        } else {
            let info = gateway
                .request(
                    "initialize",
                    json!({
                        "protocolVersion": revision,
                        "clientInfo": {"name":"wire-test", "version":"1"},
                        "capabilities": {}
                    }),
                )
                .await;
            assert_eq!(info["protocolVersion"], revision, "{info}");
            gateway
                .send(&json!({"jsonrpc":"2.0", "method":"notifications/initialized"}))
                .await;
        }
        gateway
    }

    async fn send(&mut self, message: &Value) {
        self.stdin
            .write_all(format!("{message}\n").as_bytes())
            .await
            .unwrap();
    }

    async fn request(&mut self, method: &str, mut params: Value) -> Value {
        if self.revision == MODERN {
            params["_meta"] = json!({
                "io.modelcontextprotocol/protocolVersion": MODERN,
                "io.modelcontextprotocol/clientInfo": {"name":"wire-test", "version":"1"},
                "io.modelcontextprotocol/clientCapabilities": {}
            });
        }
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .await;
        let line = timeout(DEADLINE, self.stdout.next_line())
            .await
            .unwrap_or_else(|_| panic!("timed out on {method}"))
            .unwrap()
            .unwrap_or_else(|| panic!("Forgemax closed stdout during {method}"));
        let reply: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(reply["id"], id, "{reply}");
        reply
            .get("result")
            .unwrap_or_else(|| panic!("{reply}"))
            .clone()
    }

    async fn tool(&mut self, name: &str, code: &str) -> Value {
        let result = self
            .request("tools/call", json!({"name":name,"arguments":{"code":code}}))
            .await;
        if let Some(output) = result.get("structuredContent") {
            return output.clone();
        }
        let text = result["content"][0]["text"].as_str().unwrap();
        serde_json::from_str(text).unwrap_or_else(|e| panic!("{e}: {text}"))
    }

    async fn assert_tools(&mut self) {
        let list = self.request("tools/list", json!({})).await;
        let mut names: Vec<&str> = list["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        names.sort_unstable();
        assert_eq!(names, ["execute", "search"]);
    }

    async fn catalog_when(&mut self, name: &str, expected: Value) -> Value {
        timeout(DEADLINE, async {
            loop {
                let catalog = self.tool("search", CATALOG).await;
                if catalog[name] == expected {
                    break catalog;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("catalog did not show {expected} for {name}"))
    }

    async fn close(self) {
        let Self {
            mut child, stdin, ..
        } = self;
        drop(stdin);
        assert!(timeout(DEADLINE, child.wait())
            .await
            .unwrap()
            .unwrap()
            .success());
    }
}

#[tokio::test]
async fn refresh_keeps_last_catalog_for_only_the_failing_server() {
    let healthy = Endpoint::start(LEGACY).await;
    let failing = Endpoint::start(LEGACY).await;
    let dir = tempfile::tempdir().unwrap();
    let config = healthy.config("healthy") + &failing.config("failing");
    let mut gateway = Gateway::start(dir.path(), &config, LEGACY).await;
    let before = gateway.tool("search", CATALOG).await;
    assert_eq!(
        before,
        json!({"healthy":["original"],"failing":["original"]})
    );

    failing.set_catalog(None);
    healthy.set_catalog(Some(vec!["replacement"]));
    let after = gateway
        .catalog_when("healthy", json!(["replacement"]))
        .await;
    assert_eq!(
        after,
        json!({"healthy":["replacement"],"failing":["original"]})
    );
    gateway.close().await;
}

#[tokio::test]
async fn refresh_updates_dispatch_for_added_removed_and_empty_catalogs() {
    // Deliberately advertises a long list TTL. Explicit refreshes still need the live list.
    let endpoint = Endpoint::start(MODERN).await;
    let dir = tempfile::tempdir().unwrap();
    let mut gateway = Gateway::start(dir.path(), &endpoint.config("fixture"), LEGACY).await;
    let call = |tool| format!("async () => forge.callTool('fixture', '{tool}', {{}})");
    assert_eq!(
        gateway.tool("execute", &call("original")).await,
        json!({"echo":"original"})
    );

    endpoint.set_catalog(Some(vec!["fixture.replacement"]));
    gateway
        .catalog_when("fixture", json!(["replacement"]))
        .await;
    assert_eq!(
        gateway.tool("execute", &call("fixture.replacement")).await,
        json!({"echo":"fixture.replacement"})
    );
    let removed = gateway.tool("execute", &call("original")).await;
    assert_eq!(removed["code"], "TOOL_NOT_FOUND", "{removed}");

    endpoint.set_catalog(Some(vec![]));
    gateway.catalog_when("fixture", json!([])).await;
    let emptied = gateway.tool("execute", &call("fixture.replacement")).await;
    assert_eq!(emptied["code"], "TOOL_NOT_FOUND", "{emptied}");
    assert_eq!(
        *endpoint.remote.calls.lock().unwrap(),
        ["original", "fixture.replacement"]
    );
    gateway.close().await;
}

fn stdio_fixture() -> PathBuf {
    let binary = Path::new(env!("CARGO_BIN_EXE_forgemax"))
        .with_file_name(format!("forge-test-server{}", std::env::consts::EXE_SUFFIX));
    assert!(
        binary.is_file(),
        "build the workspace binaries before running this test"
    );
    binary
}

#[tokio::test]
async fn stdio_gateway_and_downstreams_interoperate_in_both_protocol_eras() {
    let binary = stdio_fixture();
    let config = format!(
        "[servers.old]\ntransport = \"stdio\"\ncommand = {binary:?}\nargs = [\"--legacy\"]\n\
         [servers.new]\ntransport = \"stdio\"\ncommand = {binary:?}\n"
    );
    for incoming in [OLDEST, LEGACY, MODERN] {
        let dir = tempfile::tempdir().unwrap();
        let mut gateway = Gateway::start(dir.path(), &config, incoming).await;
        gateway.assert_tools().await;
        let catalog = gateway.tool("search", CATALOG).await;
        for (name, revision) in [("old", LEGACY), ("new", MODERN)] {
            assert!(catalog[name].as_array().unwrap().contains(&json!("echo")));
            let code = format!("async () => forge.callTool('{name}', 'echo', {{message:'stdio'}})");
            assert_eq!(
                gateway.tool("execute", &code).await,
                json!({"echoed":"stdio","protocolVersion":revision})
            );
            let add = format!("async () => forge.server('{name}').math.add({{a:2,b:3}})");
            let sum = gateway.tool("execute", &add).await;
            assert_eq!(sum["result"].as_f64(), Some(5.0), "{sum}");
        }
        gateway.close().await;
    }
}

#[tokio::test]
async fn http_gateway_downstreams_interoperate_in_both_protocol_eras() {
    let legacy = Endpoint::start(OLDEST).await;
    let modern = Endpoint::start(MODERN).await;
    let dir = tempfile::tempdir().unwrap();
    let config = legacy.config("legacy") + &modern.config("modern");
    let mut gateway = Gateway::start(dir.path(), &config, MODERN).await;
    gateway.assert_tools().await;
    assert_eq!(
        gateway.tool("search", CATALOG).await,
        json!({"legacy":["original"],"modern":["original"]})
    );
    for name in ["legacy", "modern"] {
        let call = format!("async () => forge.callTool('{name}', 'original', {{}})");
        assert_eq!(
            gateway.tool("execute", &call).await,
            json!({"echo":"original"})
        );
        let read = format!("async () => forge.readResource('{name}', '{RESOURCE}')");
        assert_eq!(
            gateway.tool("execute", &read).await,
            json!({"fixture":true})
        );
    }
    gateway.close().await;
}

#[tokio::test]
async fn refresh_reads_the_active_stdio_connection_after_reconnect() {
    let binary = stdio_fixture();
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("reconnected");
    let config = format!(
        "[servers.fixture]\ntransport = \"stdio\"\ncommand = {binary:?}\n\
         [servers.fixture.env]\nFORGE_TEST_RECONNECT_MARKER = {marker:?}\n"
    );
    let mut gateway = Gateway::start(dir.path(), &config, MODERN).await;
    let before = gateway.tool("search", CATALOG).await;
    assert!(!before["fixture"]
        .as_array()
        .unwrap()
        .contains(&json!("reconnected")));

    let echo = "async () => forge.callTool('fixture', 'echo', {message:'disconnect once'})";
    let result = gateway.tool("execute", echo).await;
    assert_eq!(result["code"], "TRANSPORT_DEAD", "{result}");
    assert_eq!(result["retryable"], false);
    assert!(marker.exists());
    timeout(DEADLINE, async {
        loop {
            let catalog = gateway.tool("search", CATALOG).await;
            if catalog["fixture"]
                .as_array()
                .unwrap()
                .contains(&json!("reconnected"))
            {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("refresh did not discover the replacement process");
    let call = "async () => forge.callTool('fixture', 'reconnected', {})";
    assert_eq!(
        gateway.tool("execute", call).await,
        json!({"reconnected":true})
    );
    gateway.close().await;
}

#[tokio::test]
async fn expired_http_session_recovers_without_resubmitting_the_call() {
    let endpoint = Endpoint::start(LEGACY).await;
    let dir = tempfile::tempdir().unwrap();
    let config = endpoint.config("fixture") + "reconnect = true\n";
    let mut gateway = Gateway::start(dir.path(), &config, MODERN).await;
    assert_eq!(
        endpoint.remote.initialized_sessions.load(Ordering::Relaxed),
        1
    );

    endpoint
        .remote
        .expire_next_call
        .store(true, Ordering::Relaxed);
    let call = "async () => forge.callTool('fixture', 'original', {})";
    let failed = gateway.tool("execute", call).await;
    assert_eq!(failed["code"], "TRANSPORT_DEAD", "{failed}");
    assert_eq!(failed["retryable"], false);
    assert_eq!(*endpoint.remote.calls.lock().unwrap(), ["original"]);
    assert_eq!(
        endpoint.remote.initialized_sessions.load(Ordering::Relaxed),
        2
    );
    assert_eq!(
        gateway.tool("execute", call).await,
        json!({"echo":"original"})
    );
    assert_eq!(
        *endpoint.remote.calls.lock().unwrap(),
        ["original", "original"]
    );
    gateway.close().await;
}

#[tokio::test]
async fn structured_tool_failure_and_rpc_failure_remain_failures() {
    let endpoint = Endpoint::start(MODERN).await;
    let dir = tempfile::tempdir().unwrap();
    let config = endpoint.config("fixture") + "reconnect = true\n";
    let mut gateway = Gateway::start(dir.path(), &config, MODERN).await;
    let call = |kind| {
        format!("async () => forge.callTool('fixture', 'original', {{test_result:'{kind}'}})")
    };
    let application = gateway.tool("execute", &call("tool_error")).await;
    let protocol = gateway.tool("execute", &call("rpc_error")).await;
    assert_eq!(application["code"], "TOOL_ERROR", "{application}");
    assert!(application["message"]
        .as_str()
        .unwrap()
        .contains("fixture rejected the input"));
    assert_eq!(protocol["code"], "UPSTREAM_ERROR", "{protocol}");
    assert_eq!(
        *endpoint.remote.calls.lock().unwrap(),
        ["original", "original"]
    );
    gateway.close().await;
}

#[tokio::test]
async fn startup_catalog_wait_is_bounded() {
    let endpoint = Endpoint::start(MODERN).await;
    endpoint
        .remote
        .list_delay_ms
        .store(3_000, Ordering::Relaxed);
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("forge.toml");
    tokio::fs::write(&config, endpoint.config("slow") + "timeout_secs = 1\n")
        .await
        .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_forgemax"));
    command
        .arg("--config")
        .arg(config)
        .args(["manifest", "--json"])
        .kill_on_drop(true);
    let output = timeout(DEADLINE, command.output()).await.unwrap().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "startup accepted a listing after its deadline: {stderr}"
    );
    assert!(stderr.contains("catalog discovery timed out"), "{stderr}");
}

#[tokio::test]
async fn replacement_cannot_dispatch_a_tool_missing_from_its_catalog() {
    let binary = stdio_fixture();
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("reconnected");
    let config = format!(
        "[servers.fixture]\ntransport = \"stdio\"\ncommand = {binary:?}\n\
         [servers.fixture.env]\nFORGE_TEST_RECONNECT_MARKER = {marker:?}\n"
    );
    let mut gateway = Gateway::start_with_refresh(dir.path(), &config, MODERN, 0).await;
    let code = "async () => forge.callTool('fixture', 'echo', {message:'disconnect once'})";
    let _ = gateway.tool("execute", code).await;
    assert!(marker.exists());
    let removed = gateway
        .tool(
            "execute",
            "async () => forge.callTool('fixture', 'math.add', {a:2,b:3})",
        )
        .await;
    assert_eq!(removed["code"], "TOOL_NOT_FOUND", "{removed}");
    gateway.close().await;
}
