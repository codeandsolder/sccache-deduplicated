//! Evaluate real native placement decisions using scheduler trace events.
//! Accept JSONL or prefixed journal lines; never interpret unexecuted
//! candidates' predictions as measured counterfactual runtimes.

use std::{
    collections::BTreeMap,
    io::{self, BufRead},
};

use anyhow::{Context, Result, ensure};
use sccache_build::{ContentId, PeerId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Deserialize)]
struct Forecast {
    seconds: f64,
    publication_at: f64,
    completion_seconds: f64,
    inputs_ready_at: Option<f64>,
    negotiation_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
struct Cost {
    execution_nanoseconds: f64,
    output_bytes: f64,
    result_bytes: f64,
    output_requests: f64,
}

#[derive(Debug, PartialEq, Deserialize)]
struct Assignment {
    job: u64,
    worker: PeerId,
    class: ContentId,
    candidates: BTreeMap<PeerId, Forecast>,
    healthy: Vec<PeerId>,
    host_prior: Cost,
}

#[derive(Debug, PartialEq, Deserialize)]
struct Completion {
    job: u64,
    worker: PeerId,
    class: ContentId,
    predicted_publication_seconds: Option<f64>,
    actual_publication_seconds: f64,
    actual_inputs_ready_seconds: Option<f64>,
    actual_result_negotiation_seconds: Option<f64>,
    execution_nanoseconds: f64,
    upload_bytes: f64,
    result_bytes: f64,
    upload_requests: f64,
    predicted_cost: Option<Cost>,
}

#[derive(Debug, PartialEq, Deserialize)]
struct Delivered {
    job: u64,
    worker: PeerId,
    actual_client_completion_seconds: f64,
    staging_nanoseconds: u64,
    direct_bytes: u64,
    scheduler_bytes: u64,
    unique_blobs: u64,
}

#[derive(Default)]
struct Trace {
    assignments: BTreeMap<u64, Assignment>,
    completions: BTreeMap<u64, Completion>,
    deliveries: BTreeMap<u64, Delivered>,
}

fn insert<T: PartialEq>(entries: &mut BTreeMap<u64, T>, job: u64, value: T) -> Result<()> {
    match entries.entry(job) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(value);
        }
        std::collections::btree_map::Entry::Occupied(entry) => {
            ensure!(
                entry.get() == &value,
                "conflicting trace records for job {job}"
            );
        }
    }
    Ok(())
}

impl Trace {
    fn read(lines: impl BufRead) -> Result<Self> {
        let mut trace = Self::default();
        for (index, line) in lines.lines().enumerate() {
            let line = line?;
            let Some(start) = line.find('{') else {
                continue;
            };
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&line[start..]) else {
                continue;
            };
            match value.get("kind").and_then(serde_json::Value::as_str) {
                Some("assigned") => {
                    let event: Assignment = serde_json::from_value(value)
                        .with_context(|| format!("invalid assignment at line {}", index + 1))?;
                    insert(&mut trace.assignments, event.job, event)?;
                }
                Some("completed") => {
                    let event: Completion = serde_json::from_value(value)
                        .with_context(|| format!("invalid completion at line {}", index + 1))?;
                    insert(&mut trace.completions, event.job, event)?;
                }
                Some("delivered") => {
                    let event: Delivered = serde_json::from_value(value)
                        .with_context(|| format!("invalid delivery at line {}", index + 1))?;
                    insert(&mut trace.deliveries, event.job, event)?;
                }
                _ => (),
            }
        }
        Ok(trace)
    }
}

#[derive(Default)]
struct Errors {
    count: u64,
    actual_sum: f64,
    signed_sum: f64,
    absolute: Vec<f64>,
}

#[derive(Serialize)]
struct ErrorSummary {
    samples: u64,
    mean_signed_error: Option<f64>,
    mean_absolute_error: Option<f64>,
    median_absolute_error: Option<f64>,
    p90_absolute_error: Option<f64>,
    weighted_absolute_percentage_error: Option<f64>,
}

impl Errors {
    fn add(&mut self, predicted: f64, actual: f64) -> Result<()> {
        ensure!(
            predicted.is_finite() && predicted >= 0.0 && actual.is_finite() && actual >= 0.0,
            "invalid timing or traffic observation"
        );
        let error = predicted - actual;
        self.count += 1;
        self.actual_sum += actual;
        self.signed_sum += error;
        self.absolute.push(error.abs());
        Ok(())
    }

    fn summarize(mut self) -> ErrorSummary {
        self.absolute.sort_unstable_by(f64::total_cmp);
        let total: f64 = self.absolute.iter().sum();
        let count = f64::from(u32::try_from(self.count).unwrap_or(u32::MAX));
        let quantile = |numerator: usize| {
            self.absolute
                .len()
                .checked_mul(numerator)
                .and_then(|n| n.div_ceil(10).checked_sub(1))
                .and_then(|index| self.absolute.get(index).copied())
        };
        ErrorSummary {
            samples: self.count,
            mean_signed_error: (count > 0.0).then_some(self.signed_sum / count),
            mean_absolute_error: (count > 0.0).then_some(total / count),
            median_absolute_error: quantile(5),
            p90_absolute_error: quantile(9),
            weighted_absolute_percentage_error: (self.actual_sum > 0.0)
                .then_some(100.0 * total / self.actual_sum),
        }
    }
}

#[derive(Default)]
struct Metrics {
    publication_seconds: Errors,
    client_completion_seconds: Errors,
    direct_delivery_bytes: u128,
    scheduler_delivery_bytes: u128,
    delivered_unique_blobs: u128,
    delivery_staging_nanoseconds: u128,
    inputs_ready_seconds: Errors,
    result_negotiation_seconds: Errors,
    learned_execution_seconds: Errors,
    prior_execution_seconds: Errors,
    learned_upload_bytes: Errors,
    learned_result_bytes: Errors,
    prior_result_bytes: Errors,
    prior_upload_bytes: Errors,
    learned_upload_requests: Errors,
    prior_upload_requests: Errors,
    selected_score_gap: Errors,
}

#[derive(Serialize)]
struct MetricSummary {
    publication_seconds: ErrorSummary,
    client_completion_seconds: ErrorSummary,
    direct_delivery_bytes: u128,
    scheduler_delivery_bytes: u128,
    delivered_unique_blobs: u128,
    delivery_staging_nanoseconds: u128,
    inputs_ready_seconds: ErrorSummary,
    result_negotiation_seconds: ErrorSummary,
    learned_execution_seconds: ErrorSummary,
    prior_execution_seconds: ErrorSummary,
    learned_upload_bytes: ErrorSummary,
    learned_result_bytes: ErrorSummary,
    prior_result_bytes: ErrorSummary,
    prior_upload_bytes: ErrorSummary,
    learned_upload_requests: ErrorSummary,
    prior_upload_requests: ErrorSummary,
    selected_score_gap_seconds: ErrorSummary,
}

impl Metrics {
    fn add(&mut self, assignment: &Assignment, completion: &Completion) -> Result<()> {
        ensure!(
            assignment.worker == completion.worker && assignment.class == completion.class,
            "assignment and completion identity mismatch for job {}",
            assignment.job
        );
        let selected = assignment
            .candidates
            .get(&assignment.worker)
            .context("selected worker has no forecast")?;
        let prior = &assignment.host_prior;
        let predicted = completion
            .predicted_cost
            .as_ref()
            .context("missing assigned cost")?;
        ensure!(
            completion.predicted_publication_seconds == Some(selected.publication_at),
            "completion forecast differs from assignment"
        );
        self.publication_seconds.add(
            selected.publication_at,
            completion.actual_publication_seconds,
        )?;
        if let Some((predicted, actual)) = selected
            .inputs_ready_at
            .zip(completion.actual_inputs_ready_seconds)
        {
            self.inputs_ready_seconds.add(predicted, actual)?;
        }
        if let Some((predicted, actual)) = selected
            .negotiation_at
            .zip(completion.actual_result_negotiation_seconds)
        {
            self.result_negotiation_seconds.add(predicted, actual)?;
        }
        self.learned_execution_seconds.add(
            predicted.execution_nanoseconds / 1e9,
            completion.execution_nanoseconds / 1e9,
        )?;
        self.prior_execution_seconds.add(
            prior.execution_nanoseconds / 1e9,
            completion.execution_nanoseconds / 1e9,
        )?;
        self.learned_result_bytes
            .add(predicted.result_bytes, completion.result_bytes)?;
        self.prior_result_bytes
            .add(prior.result_bytes, completion.result_bytes)?;
        self.learned_upload_bytes
            .add(predicted.output_bytes, completion.upload_bytes)?;
        self.prior_upload_bytes
            .add(prior.output_bytes, completion.upload_bytes)?;
        self.learned_upload_requests
            .add(predicted.output_requests, completion.upload_requests)?;
        self.prior_upload_requests
            .add(prior.output_requests, completion.upload_requests)?;
        let best = assignment
            .candidates
            .iter()
            .filter(|(id, _)| assignment.healthy.is_empty() || assignment.healthy.contains(id))
            .map(|(_, forecast)| forecast.seconds)
            .min_by(f64::total_cmp)
            .context("no eligible candidate")?;
        ensure!(best <= selected.seconds, "invalid selected score");
        // Predicted policy cost relative to the best scored eligible worker,
        // not an observed delay (other workers did not execute this action).
        self.selected_score_gap.add(selected.seconds, best)?;
        Ok(())
    }

    fn add_delivery(&mut self, assignment: &Assignment, delivery: &Delivered) -> Result<()> {
        ensure!(
            assignment.worker == delivery.worker,
            "delivery worker differs from assignment for job {}",
            delivery.job
        );
        let selected = assignment
            .candidates
            .get(&assignment.worker)
            .context("selected worker has no delivery forecast")?;
        self.client_completion_seconds.add(
            selected.completion_seconds,
            delivery.actual_client_completion_seconds,
        )?;
        self.direct_delivery_bytes += u128::from(delivery.direct_bytes);
        self.scheduler_delivery_bytes += u128::from(delivery.scheduler_bytes);
        self.delivered_unique_blobs += u128::from(delivery.unique_blobs);
        self.delivery_staging_nanoseconds += u128::from(delivery.staging_nanoseconds);
        Ok(())
    }

    fn summarize(self) -> MetricSummary {
        MetricSummary {
            publication_seconds: self.publication_seconds.summarize(),
            client_completion_seconds: self.client_completion_seconds.summarize(),
            direct_delivery_bytes: self.direct_delivery_bytes,
            scheduler_delivery_bytes: self.scheduler_delivery_bytes,
            delivered_unique_blobs: self.delivered_unique_blobs,
            delivery_staging_nanoseconds: self.delivery_staging_nanoseconds,
            inputs_ready_seconds: self.inputs_ready_seconds.summarize(),
            result_negotiation_seconds: self.result_negotiation_seconds.summarize(),
            learned_execution_seconds: self.learned_execution_seconds.summarize(),
            prior_execution_seconds: self.prior_execution_seconds.summarize(),
            learned_upload_bytes: self.learned_upload_bytes.summarize(),
            learned_result_bytes: self.learned_result_bytes.summarize(),
            prior_result_bytes: self.prior_result_bytes.summarize(),
            prior_upload_bytes: self.prior_upload_bytes.summarize(),
            learned_upload_requests: self.learned_upload_requests.summarize(),
            prior_upload_requests: self.prior_upload_requests.summarize(),
            selected_score_gap_seconds: self.selected_score_gap.summarize(),
        }
    }
}

#[derive(Serialize)]
struct Report {
    assignments: usize,
    completions: usize,
    matched: usize,
    deliveries: usize,
    matched_deliveries: usize,
    assignments_without_completion: usize,
    completions_without_assignment: usize,
    total: MetricSummary,
    workers: BTreeMap<PeerId, MetricSummary>,
}

fn evaluate(trace: &Trace) -> Result<Report> {
    let mut metrics = Metrics::default();
    let mut workers = BTreeMap::<PeerId, Metrics>::new();
    let mut matched = 0;
    for (&id, completion) in &trace.completions {
        if let Some(assignment) = trace.assignments.get(&id) {
            metrics.add(assignment, completion)?;
            workers
                .entry(assignment.worker)
                .or_default()
                .add(assignment, completion)?;
            matched += 1;
        }
    }
    let mut matched_deliveries = 0;
    for (&id, delivery) in &trace.deliveries {
        if let Some(assignment) = trace.assignments.get(&id) {
            metrics.add_delivery(assignment, delivery)?;
            workers
                .entry(assignment.worker)
                .or_default()
                .add_delivery(assignment, delivery)?;
            matched_deliveries += 1;
        }
    }
    ensure!(
        matched > 0 || matched_deliveries > 0,
        "no matched native placement observations"
    );
    Ok(Report {
        assignments: trace.assignments.len(),
        completions: trace.completions.len(),
        matched,
        deliveries: trace.deliveries.len(),
        matched_deliveries,
        assignments_without_completion: trace.assignments.len() - matched,
        completions_without_assignment: trace.completions.len() - matched,
        total: metrics.summarize(),
        workers: workers
            .into_iter()
            .map(|(id, metrics)| (id, metrics.summarize()))
            .collect(),
    })
}

fn main() -> Result<()> {
    let trace = Trace::read(io::stdin().lock())?;
    serde_json::to_writer_pretty(io::stdout().lock(), &evaluate(&trace)?)?;
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_prefixed_logs_and_reports_errors_without_fabricating_counterfactuals() -> Result<()>
    {
        let class = ContentId([7; 32]);
        let worker = PeerId::from_digest([1; 32]).to_string();
        let other = PeerId::from_digest([2; 32]).to_string();
        let assigned = serde_json::json!({
            "kind": "assigned", "job": 1, "worker": worker, "class": class,
            "candidates": {(worker.clone()): {"seconds": 2.01, "publication_at": 1.5, "completion_seconds": 2.0, "inputs_ready_at": 0.25, "negotiation_at": 1.25}, (other.clone()): {"seconds": 2.0, "publication_at": 1.8, "completion_seconds": 1.9}},
            "healthy": [worker, other],
            "host_prior": {"execution_nanoseconds": 1_000_000_000, "output_bytes": 100, "result_bytes": 100, "output_requests": 1},
        });
        let completed = serde_json::json!({
            "kind": "completed", "job": 1, "worker": worker, "class": class,
            "predicted_publication_seconds": 1.5, "actual_publication_seconds": 2.0, "actual_inputs_ready_seconds": 0.5, "actual_result_negotiation_seconds": 1.75, "execution_nanoseconds": 1_500_000_000,
            "upload_bytes": 0, "result_bytes": 1000, "upload_requests": 0,
            "predicted_cost": {"execution_nanoseconds": 1_400_000_000, "output_bytes": 0, "result_bytes": 1000, "output_requests": 0},
        });
        let delivered = serde_json::json!({
            "kind": "delivered", "job": 1, "worker": worker, "actual_client_completion_seconds": 2.25,
            "staging_nanoseconds": 750_000_000, "direct_bytes": 900, "scheduler_bytes": 100, "unique_blobs": 2,
        });
        let mut unmatched = assigned.clone();
        unmatched["job"] = serde_json::json!(2);
        let lines = format!(
            "other log\n[TRACE] {assigned}\n{unmatched}\n{completed}\n{completed}\n{delivered}\n{delivered}\n"
        );
        let report = evaluate(&Trace::read(lines.as_bytes())?)?;
        assert_eq!(report.matched, 1);
        assert_eq!(report.matched_deliveries, 1);
        assert_eq!(
            report.total.client_completion_seconds.mean_absolute_error,
            Some(0.25)
        );
        assert_eq!(report.total.direct_delivery_bytes, 900);
        assert_eq!(report.total.scheduler_delivery_bytes, 100);
        assert_eq!(report.total.delivered_unique_blobs, 2);
        assert_eq!(
            report.total.inputs_ready_seconds.mean_absolute_error,
            Some(0.25)
        );
        assert_eq!(
            report.total.result_negotiation_seconds.mean_absolute_error,
            Some(0.5)
        );
        assert_eq!(report.assignments_without_completion, 1);
        assert_eq!(
            report.total.publication_seconds.mean_absolute_error,
            Some(0.5)
        );
        assert!(
            report.total.learned_execution_seconds.mean_absolute_error
                < report.total.prior_execution_seconds.mean_absolute_error
        );
        assert_eq!(
            report
                .total
                .learned_upload_bytes
                .weighted_absolute_percentage_error,
            None
        );
        assert_eq!(
            report.total.learned_upload_bytes.mean_absolute_error,
            Some(0.0)
        );
        assert_eq!(
            report.total.learned_result_bytes.mean_absolute_error,
            Some(0.0)
        );
        assert_eq!(
            report.total.prior_result_bytes.mean_absolute_error,
            Some(900.0)
        );
        assert!(
            report
                .total
                .selected_score_gap_seconds
                .mean_absolute_error
                .unwrap()
                < 0.02
        );
        Ok(())
    }
}
