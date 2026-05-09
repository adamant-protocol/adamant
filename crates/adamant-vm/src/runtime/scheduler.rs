#![allow(
    clippy::doc_markdown,
    reason = "spec-quoted terminology (Tx_a, Tx_b, color-N, etc.) is more readable without backticks"
)]

//! Parallel-execution scheduler per whitepaper §6.2.3.
//!
//! Phase 5/7 ships the **deterministic, declared-parallelism**
//! scheduler. Per §6.2.3:
//!
//! > The scheduler partitions transactions into groups whose
//! > declared sets do not overlap; each group runs in parallel.
//! > 1. Compute the conflict graph: nodes are transactions; edges
//! >    connect transactions whose read/write sets overlap.
//! > 2. Compute a graph colouring: transactions of the same colour
//! >    have no edges, hence no conflicts.
//! > 3. Execute all transactions of the same colour in parallel
//! >    on available cores.
//! > 4. Once a colour completes, proceed to the next colour.
//! > 5. Across colours, ordering follows the consensus order from
//! >    section 8.
//!
//! # Static conflict detection
//!
//! Per §6.2.3, "conflicts are detected statically (from declared
//! sets) rather than discovered optimistically at runtime. Static
//! detection is possible because Adamant Move requires explicit
//! declaration of read/write sets; this is a deliberate language
//! design choice that pays off at execution."
//!
//! Two transactions conflict iff their declared object-set
//! intersection is non-empty per the §6.2.3 conflict relation:
//!
//! - **Read-write overlap**: tx_a reads object `O` and tx_b writes
//!   `O`, OR tx_a writes `O` and tx_b reads `O`.
//! - **Write-write overlap**: both tx_a and tx_b write `O`.
//!
//! Read-read overlap (both txs only read `O`) is **NOT** a
//! conflict — concurrent reads of the same object are safe.
//!
//! # Coloring algorithm
//!
//! Phase 5/7 ships a greedy coloring (smallest-first available
//! color) that's deterministic given the input ordering. Per
//! §6.2.3 line 638, "across colours, ordering follows the
//! consensus order from section 8" — the consensus order is the
//! input ordering for this scheduler. Within a color, transactions
//! execute in parallel (no consensus-binding ordering); across
//! colors, color-N completes before color-(N+1) begins.
//!
//! Greedy is sufficient for Adamant's typical-workload throughput
//! claims (§6.2.3: "the vast majority of transactions touch
//! disjoint object sets"). Pre-mainnet hardening may swap in a
//! more sophisticated coloring (Welsh-Powell, DSatur) if benchmarks
//! warrant; the API surface is stable.
//!
//! # What's NOT in this sub-arc
//!
//! - **Multi-threaded execution.** This module ships the
//!   scheduling logic only — building the conflict graph and
//!   coloring it. The actual threaded execution (rayon /
//!   std::thread / tokio task spawning) is a separate concern
//!   that depends on the consensus layer's batching surface
//!   (Phase 8). Single-threaded callers can already use the
//!   color-vector to drive sequential execution by walking
//!   colors and dispatching each transaction in turn.
//! - **Conflict-handling on re-execution.** §6.2.3 line 644
//!   describes consensus-order-driven re-execution when
//!   transactions conflict optimistically; that's an alternative
//!   shape (Block-STM-style) that Adamant's static-detection
//!   model doesn't need. Phase 5/7's static-conflict approach
//!   pre-empts the re-execution case entirely.

use std::collections::{BTreeSet, HashSet};

use adamant_types::ObjectId;

use crate::transaction::Transaction;

/// Conflict graph for a batch of transactions per whitepaper §6.2.3.
///
/// Nodes are transaction indices into the input batch; edges
/// connect transactions whose declared read/write sets overlap
/// per the §6.2.3 conflict relation.
#[derive(Clone, Debug, Default)]
pub struct ConflictGraph {
    /// `adjacency[i]` is the set of transaction-indices that
    /// conflict with transaction `i`. Symmetric: if `j ∈ adjacency[i]`
    /// then `i ∈ adjacency[j]`.
    adjacency: Vec<BTreeSet<usize>>,
}

impl ConflictGraph {
    /// Construct an empty graph with `n` nodes.
    #[must_use]
    pub fn empty(n: usize) -> Self {
        Self {
            adjacency: vec![BTreeSet::new(); n],
        }
    }

    /// Number of transaction nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.adjacency.len()
    }

    /// Number of edges (counted once per edge, not twice).
    #[must_use]
    pub fn edge_count(&self) -> usize {
        let total: usize = self.adjacency.iter().map(BTreeSet::len).sum();
        total / 2
    }

    /// Returns the set of transaction-indices conflicting with `i`.
    #[must_use]
    pub fn conflicts_for(&self, i: usize) -> &BTreeSet<usize> {
        &self.adjacency[i]
    }

    /// Add a conflict edge between `i` and `j` (symmetric).
    fn add_edge(&mut self, i: usize, j: usize) {
        if i != j {
            self.adjacency[i].insert(j);
            self.adjacency[j].insert(i);
        }
    }
}

/// Compute the conflict graph for a batch of transactions per
/// whitepaper §6.2.3 step 1.
///
/// Two transactions conflict iff:
///
/// - Their write-sets overlap (write-write conflict), OR
/// - Tx_a's write-set overlaps with tx_b's read-set (RW conflict), OR
/// - Tx_a's read-set overlaps with tx_b's write-set (WR conflict).
///
/// Read-read overlaps do not produce a conflict.
#[must_use]
pub fn compute_conflict_graph(transactions: &[Transaction]) -> ConflictGraph {
    let n = transactions.len();
    let mut graph = ConflictGraph::empty(n);

    // Collect (read_set_ids, write_set_ids) per transaction.
    let mut sets: Vec<(HashSet<ObjectId>, HashSet<ObjectId>)> = transactions
        .iter()
        .map(|tx| {
            let read: HashSet<ObjectId> = tx.body.read_set.iter().map(|(id, _)| *id).collect();
            let write: HashSet<ObjectId> = tx.body.write_set.iter().copied().collect();
            (read, write)
        })
        .collect();

    // Pairwise conflict check. O(n²) on transaction count; fine
    // for batch sizes at the consensus-block scale (thousands).
    // For larger batches a per-object bucketing would reduce to
    // O(n + total_objects); registered as pre-mainnet performance
    // hardening if benchmarks warrant.
    for i in 0..n {
        for j in (i + 1)..n {
            // Need to read sets[i] and sets[j] simultaneously.
            // Split borrow via split_at_mut.
            let (left, right) = sets.split_at_mut(j);
            let (read_i, write_i) = &left[i];
            let (read_j, write_j) = &right[0];
            if conflicts(read_i, write_i, read_j, write_j) {
                graph.add_edge(i, j);
            }
        }
    }
    graph
}

/// Determine whether two transactions' (read-set, write-set)
/// pairs overlap per the §6.2.3 conflict relation.
fn conflicts(
    read_a: &HashSet<ObjectId>,
    write_a: &HashSet<ObjectId>,
    read_b: &HashSet<ObjectId>,
    write_b: &HashSet<ObjectId>,
) -> bool {
    // Write-write: any object in both write sets.
    if !write_a.is_disjoint(write_b) {
        return true;
    }
    // Read-write: a's writes overlap b's reads.
    if !write_a.is_disjoint(read_b) {
        return true;
    }
    // Write-read: b's writes overlap a's reads.
    if !write_b.is_disjoint(read_a) {
        return true;
    }
    false
}

/// Greedy graph coloring per whitepaper §6.2.3 step 2.
///
/// Returns a `Vec<Vec<usize>>` where each inner vector is a color
/// group: transactions in the same color group have no conflicts
/// and may execute in parallel. Color groups are returned in
/// assignment order; per §6.2.3 line 638, "across colours,
/// ordering follows the consensus order" — color N is dispatched
/// before color N+1.
///
/// The greedy algorithm: walk transactions in input order; for
/// each, assign the smallest color index whose group does not
/// contain a conflicting transaction.
///
/// Determinism: for a fixed input ordering and conflict graph,
/// the output is identical — required for consensus per §6.2.4.
#[must_use]
pub fn greedy_coloring(graph: &ConflictGraph) -> Vec<Vec<usize>> {
    let n = graph.node_count();
    let mut color_of: Vec<Option<usize>> = vec![None; n];
    let mut colors: Vec<Vec<usize>> = Vec::new();

    for i in 0..n {
        // Determine which colors are forbidden for this node by
        // its already-colored neighbors.
        let forbidden: BTreeSet<usize> = graph
            .conflicts_for(i)
            .iter()
            .filter_map(|&j| color_of[j])
            .collect();
        // Smallest unforbidden color.
        let mut chosen = 0;
        while forbidden.contains(&chosen) {
            chosen += 1;
        }
        color_of[i] = Some(chosen);
        if chosen >= colors.len() {
            colors.resize_with(chosen + 1, Vec::new);
        }
        colors[chosen].push(i);
    }

    colors
}

/// Schedule a batch of transactions for parallel execution per
/// whitepaper §6.2.3.
///
/// Convenience wrapper composing [`compute_conflict_graph`] and
/// [`greedy_coloring`]. Returns the color-partitioned schedule:
/// each inner vector contains transaction-indices that may
/// execute in parallel; outer-vector ordering pins the inter-
/// color sequencing per the consensus order.
///
/// Caller dispatches each color group to available threads;
/// blocks until all transactions in the current color complete;
/// proceeds to the next color. Single-threaded callers may walk
/// the schedule sequentially with no semantic difference (per
/// §6.2.3, parallel execution is an optimization, not a
/// requirement).
#[must_use]
pub fn schedule(transactions: &[Transaction]) -> Vec<Vec<usize>> {
    let graph = compute_conflict_graph(transactions);
    greedy_coloring(&graph)
}

#[cfg(test)]
mod tests {
    use super::*;
    use adamant_types::{Address, FunctionId, ModuleRef, Signature as Sig, StealthCommitment};

    use crate::transaction::{
        AccountRef, AuthEvidence, CallParams, GasBudget, Transaction, TxBody,
    };

    fn obj(id: u8) -> ObjectId {
        ObjectId::from_bytes([id; 32])
    }

    fn tx_with_sets(read: Vec<ObjectId>, write: Vec<ObjectId>) -> Transaction {
        Transaction {
            body: TxBody {
                authorising_account: AccountRef::Cleartext(Address::from_bytes([0; 32])),
                fee_payer: None,
                read_set: read.into_iter().map(|id| (id, 0)).collect(),
                write_set: write,
                created_objects: vec![],
                gas_budget: GasBudget {
                    computation: 0,
                    storage: 0,
                    rent: 0,
                    bandwidth: 0,
                    proof_verification: 0,
                    proof_generation: 0,
                },
                call: CallParams {
                    target_module: ModuleRef(obj(0xFE)),
                    target_function: FunctionId::new("f".to_string()).unwrap(),
                    type_arguments: vec![],
                    arguments: vec![],
                },
                nonce: 0,
            },
            auth: AuthEvidence {
                signatures: vec![Sig::Ed25519([0; 64])],
                witnesses: vec![],
            },
        }
    }

    /// Empty batch produces an empty schedule.
    #[test]
    fn empty_batch_empty_schedule() {
        let schedule = schedule(&[]);
        assert!(schedule.is_empty());
    }

    /// Single transaction → single color group of size 1.
    #[test]
    fn single_tx_single_color() {
        let txs = vec![tx_with_sets(vec![obj(1)], vec![obj(1)])];
        let schedule = schedule(&txs);
        assert_eq!(schedule.len(), 1);
        assert_eq!(schedule[0], vec![0]);
    }

    /// Two transactions with disjoint sets → both in the same
    /// color group (run in parallel).
    #[test]
    fn disjoint_sets_share_color() {
        let txs = vec![
            tx_with_sets(vec![obj(1)], vec![obj(1)]),
            tx_with_sets(vec![obj(2)], vec![obj(2)]),
        ];
        let schedule = schedule(&txs);
        assert_eq!(schedule.len(), 1);
        assert_eq!(schedule[0], vec![0, 1]);
    }

    /// Two transactions with write-write overlap → different colors.
    #[test]
    fn write_write_conflict_separates_colors() {
        let txs = vec![
            tx_with_sets(vec![], vec![obj(5)]),
            tx_with_sets(vec![], vec![obj(5)]),
        ];
        let schedule = schedule(&txs);
        assert_eq!(schedule.len(), 2);
        assert_eq!(schedule[0], vec![0]);
        assert_eq!(schedule[1], vec![1]);
    }

    /// Read-write conflict (a writes, b reads): different colors.
    #[test]
    fn read_write_conflict_separates_colors() {
        let txs = vec![
            tx_with_sets(vec![obj(7)], vec![obj(7)]),
            tx_with_sets(vec![obj(7)], vec![]),
        ];
        let schedule = schedule(&txs);
        assert_eq!(schedule.len(), 2);
    }

    /// Read-read overlap is NOT a conflict.
    #[test]
    fn read_read_overlap_no_conflict() {
        let txs = vec![
            tx_with_sets(vec![obj(9)], vec![]),
            tx_with_sets(vec![obj(9)], vec![]),
        ];
        let schedule = schedule(&txs);
        assert_eq!(schedule.len(), 1);
        assert_eq!(schedule[0], vec![0, 1]);
    }

    /// Three-way conflict: tx 0 conflicts with both 1 and 2; 1
    /// and 2 don't conflict with each other.
    /// Greedy: 0 → color 0. 1 conflicts with 0 → color 1. 2
    /// conflicts with 0 → color 1 (still ok since not conflicting
    /// with 1).
    #[test]
    fn three_way_conflict_uses_two_colors() {
        let txs = vec![
            tx_with_sets(vec![], vec![obj(1), obj(2)]),
            tx_with_sets(vec![obj(1)], vec![]),
            tx_with_sets(vec![obj(2)], vec![]),
        ];
        let schedule = schedule(&txs);
        assert_eq!(schedule.len(), 2);
        assert_eq!(schedule[0], vec![0]);
        assert_eq!(schedule[1], vec![1, 2]);
    }

    /// Whitepaper §6.2.3 line 642: "the vast majority of
    /// transactions touch disjoint object sets" → most should
    /// share color 0. Verify with a realistic-shape batch.
    #[test]
    fn realistic_workload_mostly_in_first_color() {
        // 10 disjoint transactions + 2 conflicting on obj(99).
        let mut txs = Vec::new();
        for i in 0..10 {
            txs.push(tx_with_sets(vec![obj(i)], vec![obj(i)]));
        }
        // Two conflicting txs on a hot object.
        txs.push(tx_with_sets(vec![], vec![obj(99)]));
        txs.push(tx_with_sets(vec![], vec![obj(99)]));

        let schedule = schedule(&txs);
        assert_eq!(schedule.len(), 2);
        // Color 0 has the 10 disjoint + 1 of the conflicting pair.
        assert_eq!(schedule[0].len(), 11);
        // Color 1 has the other conflicting tx.
        assert_eq!(schedule[1], vec![11]);
    }

    /// Determinism per §6.2.4: same input → same schedule
    /// (required for consensus).
    #[test]
    fn schedule_is_deterministic() {
        let txs = vec![
            tx_with_sets(vec![obj(1)], vec![obj(1)]),
            tx_with_sets(vec![obj(2)], vec![obj(2)]),
            tx_with_sets(vec![obj(1)], vec![obj(3)]),
        ];
        let s1 = schedule(&txs);
        let s2 = schedule(&txs);
        assert_eq!(s1, s2);
    }

    #[test]
    fn conflict_graph_edge_count_pairwise() {
        let txs = vec![
            tx_with_sets(vec![], vec![obj(1)]),
            tx_with_sets(vec![], vec![obj(1)]),
            tx_with_sets(vec![], vec![obj(1)]),
        ];
        let g = compute_conflict_graph(&txs);
        // Triangle: 3 edges.
        assert_eq!(g.edge_count(), 3);
        assert_eq!(g.node_count(), 3);
    }

    #[test]
    fn shielded_account_ref_does_not_affect_scheduling() {
        let mut tx = tx_with_sets(vec![obj(1)], vec![obj(1)]);
        tx.body.authorising_account =
            AccountRef::Shielded(StealthCommitment::from_bytes([0xAB; 32]));
        let schedule = schedule(&[tx]);
        assert_eq!(schedule.len(), 1);
    }
}
