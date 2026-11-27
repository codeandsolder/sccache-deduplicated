//! Attribute only measured, host-local wall time. A remote child, an
//! overlapping diagnostic interval, or a gap is never added to phase time.

use super::{SpanKind, TraceDetail, TraceSpan};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhaseDuration {
    pub name: String,
    pub elapsed_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhaseBreakdown {
    pub host: String,
    pub service: String,
    pub operation: String,
    pub elapsed_ns: u64,
    pub phases: Vec<PhaseDuration>,
    pub unobserved_ns: u64,
    pub ambiguous_ns: u64,
    pub clipped: bool,
}

#[derive(Clone, Copy)]
enum Boundary<'a> {
    Start(&'a str),
    End(&'a str),
}

fn same_clock(parent: &TraceSpan, child: &TraceSpan) -> bool {
    parent.host == child.host
        && parent.service == child.service
        && parent.revision == child.revision
}

fn breakdown<'a>(
    parent: &TraceSpan,
    children: impl Iterator<Item = &'a TraceSpan>,
) -> PhaseBreakdown {
    let mut boundaries = Vec::new();
    let mut clipped = false;
    for child in children.filter(|child| child.kind == SpanKind::Phase && same_clock(parent, child))
    {
        let end = child.start_ns.saturating_add(child.duration_ns);
        let from = child.start_ns.saturating_sub(parent.start_ns);
        let until = end.saturating_sub(parent.start_ns);
        clipped |= child.start_ns < parent.start_ns || until > parent.duration_ns;
        let from = from.min(parent.duration_ns);
        let until = until.min(parent.duration_ns);
        if until > from {
            boundaries.push((from, Boundary::Start(child.name.as_str())));
            boundaries.push((until, Boundary::End(child.name.as_str())));
        }
    }
    boundaries.sort_unstable_by_key(|(offset, _)| *offset);
    let mut active = BTreeMap::<&str, usize>::new();
    let mut elapsed = BTreeMap::<&str, u64>::new();
    let mut unobserved_ns = 0;
    let mut ambiguous_ns = 0;
    let mut previous = 0;
    for (offset, boundary) in boundaries {
        let duration = offset - previous;
        match active.len() {
            0 => unobserved_ns += duration,
            1 => {
                if let Some((&name, _)) = active.first_key_value() {
                    *elapsed.entry(name).or_default() += duration;
                }
            }
            _ => ambiguous_ns += duration,
        }
        match boundary {
            Boundary::Start(name) => *active.entry(name).or_default() += 1,
            Boundary::End(name) => {
                if let std::collections::btree_map::Entry::Occupied(mut entry) = active.entry(name)
                {
                    *entry.get_mut() -= 1;
                    if *entry.get() == 0 {
                        entry.remove();
                    }
                }
            }
        }
        previous = offset;
    }
    unobserved_ns += parent.duration_ns - previous;
    let mut phases = elapsed
        .into_iter()
        .filter(|(_, elapsed_ns)| *elapsed_ns != 0)
        .map(|(name, elapsed_ns)| PhaseDuration {
            name: name.to_owned(),
            elapsed_ns,
        })
        .collect::<Vec<_>>();
    phases.sort_unstable_by(|a, b| {
        b.elapsed_ns
            .cmp(&a.elapsed_ns)
            .then_with(|| a.name.cmp(&b.name))
    });
    PhaseBreakdown {
        host: parent.host.clone(),
        service: parent.service.clone(),
        operation: parent.name.clone(),
        elapsed_ns: parent.duration_ns,
        phases,
        unobserved_ns,
        ambiguous_ns,
        clipped,
    }
}

/// Partition the client root and every worker job separately. This does not
/// invent a globally synchronized critical path from cross-host timestamps.
#[must_use = "render the measured breakdown for each parent operation"]
pub fn phase_breakdowns(detail: &TraceDetail) -> Vec<PhaseBreakdown> {
    let mut children = BTreeMap::<&str, Vec<&TraceSpan>>::new();
    for span in &detail.spans {
        children.entry(&span.parent).or_default().push(span);
    }
    detail
        .spans
        .iter()
        .filter(|span| {
            (span.service == "sccache-client" && span.parent.is_empty() && span.name == "compile")
                || (span.service == "sccache-worker" && span.name == "worker_job")
        })
        .map(|parent| {
            breakdown(
                parent,
                children
                    .get(parent.id.as_str())
                    .into_iter()
                    .flatten()
                    .copied(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(
        id: &str,
        parent: &str,
        name: &str,
        start_ns: u64,
        duration_ns: u64,
        kind: SpanKind,
    ) -> TraceSpan {
        TraceSpan {
            id: id.into(),
            parent: parent.into(),
            name: name.into(),
            host: "client".into(),
            service: "sccache-client".into(),
            revision: "revision".into(),
            kind,
            start_ns,
            duration_ns,
            error: false,
            producer: None,
        }
    }

    #[test]
    fn exclusive_wall_time_counts_gaps_conflicts_and_repeated_phases() {
        let root = span("root", "", "compile", 100, 100, SpanKind::Other);
        let mut children = vec![
            span("a", "root", "hash", 90, 40, SpanKind::Phase),
            span("b", "root", "hash", 120, 20, SpanKind::Phase),
            span("c", "root", "lookup", 135, 25, SpanKind::Phase),
            span("d", "root", "hash", 170, 15, SpanKind::Phase),
            span("e", "root", "reply", 190, 30, SpanKind::Phase),
            span("f", "root", "jobserver", 100, 100, SpanKind::Interval),
            span("g", "root", "remote", 100, 100, SpanKind::Phase),
        ];
        children[6].host = "worker".into();
        let result = breakdown(&root, children.iter());
        assert_eq!(
            result.phases,
            vec![
                PhaseDuration {
                    name: "hash".into(),
                    elapsed_ns: 50
                },
                PhaseDuration {
                    name: "lookup".into(),
                    elapsed_ns: 20
                },
                PhaseDuration {
                    name: "reply".into(),
                    elapsed_ns: 10
                },
            ]
        );
        assert_eq!(result.ambiguous_ns, 5);
        assert_eq!(result.unobserved_ns, 15);
        assert!(result.clipped);
        assert_eq!(
            result
                .phases
                .iter()
                .map(|phase| phase.elapsed_ns)
                .sum::<u64>()
                + result.ambiguous_ns
                + result.unobserved_ns,
            root.duration_ns
        );
    }

    #[test]
    fn worker_clock_has_its_own_partition_and_unobserved_root_is_explicit() {
        let root = span("root", "", "compile", 100, 100, SpanKind::Other);
        let mut worker = span("job", "root", "worker_job", 10_000, 50, SpanKind::Other);
        worker.service = "sccache-worker".into();
        worker.host = "worker".into();
        let mut process = span(
            "process",
            "job",
            "compiler_process",
            10_010,
            20,
            SpanKind::Phase,
        );
        process.service.clone_from(&worker.service);
        process.host.clone_from(&worker.host);
        let detail = TraceDetail {
            id: "request".into(),
            request: None,
            omitted_intervals: 0,
            spans: vec![root, worker, process],
            truncated: false,
        };
        let parts = phase_breakdowns(&detail);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].unobserved_ns, 100);
        assert_eq!(parts[1].phases[0].elapsed_ns, 20);
        assert_eq!(parts[1].unobserved_ns, 30);
        assert!(!parts[1].clipped);
    }
}
