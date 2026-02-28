//! Prometheus metrics for the Forge sandbox.
//!
//! This module is only compiled when the `metrics` feature is enabled.
//! Provides counters, histograms, and gauges for sandbox execution observability.

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use std::sync::atomic::AtomicI64;

/// Label set for execution metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ExecutionLabels {
    /// The operation type: "search" or "execute".
    pub operation: String,
}

/// Label set for error metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ErrorLabels {
    /// The error kind: "timeout", "heap_limit", "js_error", "execution".
    pub error_kind: String,
}

/// Prometheus metrics for the Forge sandbox.
pub struct ForgeMetrics {
    /// Total number of executions.
    pub executions_total: Family<ExecutionLabels, Counter>,
    /// Execution duration in seconds.
    pub execution_duration_seconds: Family<ExecutionLabels, Histogram>,
    /// Total number of errors by kind.
    pub errors_total: Family<ErrorLabels, Counter>,
    /// Current number of workers in the pool (bridged from PoolMetrics atomics).
    pub pool_workers_alive: Gauge<i64, AtomicI64>,
}

impl ForgeMetrics {
    /// Create a new `ForgeMetrics` and register all metrics with the given registry.
    pub fn new(registry: &mut Registry) -> Self {
        let executions_total = Family::default();
        registry.register(
            "forge_executions_total",
            "Total sandbox executions",
            executions_total.clone(),
        );

        let execution_duration_seconds =
            Family::<ExecutionLabels, Histogram>::new_with_constructor(|| {
                Histogram::new(
                    [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0].into_iter(),
                )
            });
        registry.register(
            "forge_execution_duration_seconds",
            "Sandbox execution duration",
            execution_duration_seconds.clone(),
        );

        let errors_total = Family::default();
        registry.register(
            "forge_errors_total",
            "Total sandbox errors by kind",
            errors_total.clone(),
        );

        let pool_workers_alive = Gauge::default();
        registry.register(
            "forge_pool_workers_alive",
            "Current workers alive in pool",
            pool_workers_alive.clone(),
        );

        Self {
            executions_total,
            execution_duration_seconds,
            errors_total,
            pool_workers_alive,
        }
    }

    /// Record a successful execution.
    pub fn record_execution(&self, operation: &str, duration_secs: f64) {
        let labels = ExecutionLabels {
            operation: operation.to_string(),
        };
        self.executions_total.get_or_create(&labels).inc();
        self.execution_duration_seconds
            .get_or_create(&labels)
            .observe(duration_secs);
    }

    /// Record an error.
    pub fn record_error(&self, error_kind: &str) {
        let labels = ErrorLabels {
            error_kind: error_kind.to_string(),
        };
        self.errors_total.get_or_create(&labels).inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus_client::encoding::text::encode;

    #[test]
    fn metrics_01_forge_metrics_creates_counters() {
        let mut registry = Registry::default();
        let metrics = ForgeMetrics::new(&mut registry);
        // Should not panic
        let _ = metrics;
    }

    #[test]
    fn metrics_02_execution_counter_increments() {
        let mut registry = Registry::default();
        let metrics = ForgeMetrics::new(&mut registry);
        metrics.record_execution("execute", 0.5);
        metrics.record_execution("execute", 1.0);
        metrics.record_execution("search", 0.1);

        let labels = ExecutionLabels {
            operation: "execute".into(),
        };
        let count = metrics.executions_total.get_or_create(&labels).get();
        assert_eq!(count, 2);
    }

    #[test]
    fn metrics_03_error_counter_increments_on_failure() {
        let mut registry = Registry::default();
        let metrics = ForgeMetrics::new(&mut registry);
        metrics.record_error("timeout");
        metrics.record_error("timeout");
        metrics.record_error("js_error");

        let labels = ErrorLabels {
            error_kind: "timeout".into(),
        };
        let count = metrics.errors_total.get_or_create(&labels).get();
        assert_eq!(count, 2);
    }

    #[test]
    fn metrics_04_pool_gauge_bridges_atomic_counters() {
        let mut registry = Registry::default();
        let metrics = ForgeMetrics::new(&mut registry);
        metrics.pool_workers_alive.set(5);
        assert_eq!(metrics.pool_workers_alive.get(), 5);
    }

    #[test]
    fn metrics_05_duration_histogram_records() {
        let mut registry = Registry::default();
        let metrics = ForgeMetrics::new(&mut registry);
        metrics.record_execution("execute", 0.05);
        metrics.record_execution("execute", 2.5);
        // No assertion on bucket counts, just verify it doesn't panic
    }

    #[test]
    fn metrics_06_metrics_encode_to_text() {
        let mut registry = Registry::default();
        let metrics = ForgeMetrics::new(&mut registry);
        metrics.record_execution("execute", 1.0);
        metrics.record_error("timeout");

        let mut buf = String::new();
        encode(&mut buf, &registry).unwrap();

        assert!(
            buf.contains("forge_executions_total"),
            "should contain execution counter: {buf}"
        );
        assert!(
            buf.contains("forge_errors_total"),
            "should contain error counter: {buf}"
        );
    }

    #[test]
    fn metrics_08_metrics_thread_safe() {
        let mut registry = Registry::default();
        let metrics = std::sync::Arc::new(ForgeMetrics::new(&mut registry));

        let m1 = metrics.clone();
        let h1 = std::thread::spawn(move || {
            m1.record_execution("execute", 0.1);
        });

        let m2 = metrics.clone();
        let h2 = std::thread::spawn(move || {
            m2.record_error("js_error");
        });

        h1.join().unwrap();
        h2.join().unwrap();
        // No assertions — just verify no data races
    }
}
