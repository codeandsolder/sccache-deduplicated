//! Dependency readiness is separate from worker admission and cache identity.
//!
//! The graph uses compact, plan-local indices. A node becomes eligible only
//! after all its predecessors have completed successfully; the caller owns
//! execution, artifact delivery and cancellation.

use std::{cmp::Reverse, collections::BinaryHeap};

use anyhow::{Context, Result, ensure};

/// Static graph structure, independent of the action payload.
pub struct BuildGraph {
    successors: Vec<Vec<usize>>,
    remaining: Vec<usize>,
    priority: Vec<u64>,
    state: Vec<State>,
    ready: BinaryHeap<(u64, Reverse<usize>)>,
    completed: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Pending,
    Ready,
    Running,
    Complete,
}

impl BuildGraph {
    /// Validate the complete graph and initialize its ready frontier.
    ///
    /// Costs are relative estimates, not execution admission limits. The
    /// longest downstream weighted path takes precedence; ties use plan order.
    ///
    /// # Errors
    /// Returns an error for invalid indices, duplicate edges, cycles or
    /// mismatched costs.
    pub fn new(dependencies: &[Vec<usize>], costs: &[u64]) -> Result<Self> {
        let count = dependencies.len();
        ensure!(costs.len() == count, "missing build node costs");
        let mut successors = vec![Vec::new(); count];
        let mut remaining = Vec::with_capacity(count);
        let mut seen = vec![usize::MAX; count];
        for (index, deps) in dependencies.iter().enumerate() {
            remaining.push(deps.len());
            for &dep in deps {
                ensure!(dep < count, "node {index} depends on unknown node {dep}");
                ensure!(seen[dep] != index, "duplicate edge {dep} -> {index}");
                seen[dep] = index;
                successors[dep].push(index);
            }
        }

        // A single reverse topological pass computes the critical path and
        // rejects cycles, without collecting transitive dependent sets.
        let mut outgoing: Vec<_> = successors.iter().map(Vec::len).collect();
        let mut leaves: Vec<_> = outgoing
            .iter()
            .enumerate()
            .filter_map(|(i, &degree)| (degree == 0).then_some(i))
            .collect();
        let mut priority = costs.to_vec();
        let mut visited = 0;
        while let Some(node) = leaves.pop() {
            visited += 1;
            for &dep in &dependencies[node] {
                priority[dep] = priority[dep].max(costs[dep].saturating_add(priority[node]));
                outgoing[dep] -= 1;
                if outgoing[dep] == 0 {
                    leaves.push(dep);
                }
            }
        }
        ensure!(visited == count, "cycle in build graph");

        let mut graph = Self {
            successors,
            remaining,
            priority,
            state: vec![State::Pending; count],
            ready: BinaryHeap::new(),
            completed: 0,
        };
        for index in 0..count {
            if graph.remaining[index] == 0 {
                graph.make_ready(index);
            }
        }
        Ok(graph)
    }

    fn make_ready(&mut self, index: usize) {
        self.state[index] = State::Ready;
        self.ready.push((self.priority[index], Reverse(index)));
    }

    /// Take the highest-priority eligible node. This does not reserve a
    /// worker; the action still goes through normal scheduler admission.
    pub fn take_ready(&mut self) -> Option<usize> {
        let (_, Reverse(index)) = self.ready.pop()?;
        self.state[index] = State::Running;
        Some(index)
    }

    /// Release dependent nodes after all required artifacts are available.
    ///
    /// # Errors
    /// Returns an error if the node is not currently running.
    pub fn complete(&mut self, index: usize) -> Result<()> {
        let state = self.state.get_mut(index).context("unknown build node")?;
        ensure!(*state == State::Running, "build node is not running");
        *state = State::Complete;
        self.completed += 1;
        for offset in 0..self.successors[index].len() {
            let successor = self.successors[index][offset];
            self.remaining[successor] -= 1;
            if self.remaining[successor] == 0 {
                self.make_ready(successor);
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.completed == self.state.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weighted_diamond_releases_join_only_after_both_branches() -> Result<()> {
        let mut graph = BuildGraph::new(
            &[vec![], vec![0], vec![0], vec![1, 2], vec![]],
            &[1, 2, 8, 3, 5],
        )?;
        assert_eq!(graph.take_ready(), Some(0));
        assert_eq!(graph.take_ready(), Some(4));
        assert_eq!(graph.take_ready(), None);
        graph.complete(0)?;
        assert_eq!(graph.take_ready(), Some(2));
        assert_eq!(graph.take_ready(), Some(1));
        graph.complete(2)?;
        assert_eq!(graph.take_ready(), None);
        graph.complete(1)?;
        assert_eq!(graph.take_ready(), Some(3));
        graph.complete(3)?;
        assert!(!graph.is_complete());
        graph.complete(4)?;
        assert!(graph.is_complete());
        assert!(graph.complete(4).is_err());
        Ok(())
    }

    #[test]
    fn invalid_graphs_are_rejected_before_dispatch() {
        assert!(BuildGraph::new(&[vec![1], vec![0]], &[1, 1]).is_err());
        assert!(BuildGraph::new(&[vec![0]], &[1]).is_err());
        assert!(BuildGraph::new(&[vec![1]], &[1]).is_err());
        assert!(BuildGraph::new(&[vec![], vec![0, 0]], &[1, 1]).is_err());
        assert!(BuildGraph::new(&[vec![]], &[]).is_err());
    }

    #[test]
    fn deep_graph_is_iterative() -> Result<()> {
        let n = 20_000;
        let mut deps = vec![Vec::new()];
        deps.extend((1..n).map(|i| vec![i - 1]));
        let mut graph = BuildGraph::new(&deps, &vec![1; n])?;
        for i in 0..n {
            assert_eq!(graph.take_ready(), Some(i));
            graph.complete(i)?;
        }
        assert!(graph.is_complete());
        Ok(())
    }
}
