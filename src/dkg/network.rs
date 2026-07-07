//! Phase 7 — Tokio network simulation (gated behind the `network` feature).
//!
//! The DMKG protocol itself is synchronous; this module wraps message passing in
//! an async layer so we can measure **network cost separately from computation**.
//! It models the two communication patterns the protocol uses:
//!
//! * [`broadcast_round`] — the **all-to-all** pattern of the non-aggregatable
//!   Pedersen `(x1,x2,y1,y2)` layer: every node ships its (encrypted) shares to
//!   every other node. `n·(n−1)` messages, `O(n²)` bytes, **one** latency round.
//! * [`tree_gossip`] — the **binary-tree aggregation** of the aggregatable `z`
//!   SCRAPE layer: transcripts are combined up a tree. `n−1` messages,
//!   `⌈log₂ n⌉` sequential latency rounds.
//!
//! Each link delivery waits `latency` (injected WAN latency, 50–200 ms in the
//! benchmarks) before the payload arrives, so the wall-clock numbers reflect the
//! round structure of each pattern. Payloads are opaque byte buffers; their sizes
//! come from the real `CanonicalSerialize` message sizes measured in the
//! benchmark binary, keeping the byte accounting faithful without re-running the
//! cryptography inside the network layer.

use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Timing + volume of one simulated communication phase. The network and compute
/// clocks are deliberately kept apart: this struct is *network only*.
#[derive(Clone, Copy, Debug)]
pub struct NetworkReport {
    /// Wall-clock time for the whole phase (dominated by latency rounds).
    pub wall: Duration,
    /// Number of point-to-point messages delivered.
    pub messages: usize,
    /// Total bytes delivered across all links.
    pub bytes: usize,
    /// Number of sequential latency rounds the pattern requires.
    pub rounds: usize,
}

/// All-to-all broadcast: every one of `n` nodes sends a `payload`-byte message to
/// each of the other `n−1` nodes. All links fire concurrently, so the phase takes
/// a single latency round regardless of `n` (bandwidth is not modelled), while the
/// message and byte counts grow as `O(n²)`.
pub async fn broadcast_round(n: usize, latency: Duration, payload: usize) -> NetworkReport {
    let start = Instant::now();

    // One inbound channel per node.
    let mut receivers = Vec::with_capacity(n);
    let mut senders = Vec::with_capacity(n);
    for _ in 0..n {
        let (tx, rx) = mpsc::unbounded_channel::<usize>();
        senders.push(tx);
        receivers.push(rx);
    }

    // Each node ships to every peer; each delivery is delayed by `latency`.
    let mut send_tasks = Vec::new();
    for from in 0..n {
        for (to, tx) in senders.iter().enumerate() {
            if from == to {
                continue;
            }
            let tx = tx.clone();
            send_tasks.push(tokio::spawn(async move {
                tokio::time::sleep(latency).await;
                let _ = tx.send(payload);
            }));
        }
    }
    drop(senders);

    // Each node drains its inbox, counting bytes.
    let mut recv_tasks = Vec::new();
    for mut rx in receivers.into_iter() {
        recv_tasks.push(tokio::spawn(async move {
            let mut bytes = 0usize;
            let mut count = 0usize;
            while let Some(p) = rx.recv().await {
                bytes += p;
                count += 1;
            }
            (count, bytes)
        }));
    }
    for t in send_tasks {
        let _ = t.await;
    }
    let mut messages = 0usize;
    let mut bytes = 0usize;
    for t in recv_tasks {
        if let Ok((c, b)) = t.await {
            messages += c;
            bytes += b;
        }
    }

    NetworkReport {
        wall: start.elapsed(),
        messages,
        bytes,
        rounds: 1,
    }
}

/// Binary-tree aggregation gossip: `n` leaves combine pairwise up the tree. Each
/// of the `⌈log₂ n⌉` levels is a sequential latency round (a node must receive its
/// child's transcript before forwarding), and only `n−1` messages are sent. This
/// is the communication shape that makes the aggregatable `z` layer `O(n log n)`.
pub async fn tree_gossip(n: usize, latency: Duration, payload: usize) -> NetworkReport {
    let start = Instant::now();
    let mut messages = 0usize;
    let mut bytes = 0usize;
    let mut rounds = 0usize;

    // Number of nodes still active at the current level.
    let mut active = n;
    while active > 1 {
        rounds += 1;
        let pairs = active / 2;
        // All sends at this level happen concurrently, then we wait one latency.
        let mut tasks = Vec::with_capacity(pairs);
        for _ in 0..pairs {
            tasks.push(tokio::spawn(async move {
                tokio::time::sleep(latency).await;
                payload
            }));
        }
        for t in tasks {
            if let Ok(p) = t.await {
                messages += 1;
                bytes += p;
            }
        }
        // Aggregation: each pair collapses to one; odd node carries up.
        active -= pairs;
    }

    NetworkReport {
        wall: start.elapsed(),
        messages,
        bytes,
        rounds,
    }
}

/// Build a multi-threaded Tokio runtime and run [`broadcast_round`] to completion.
pub fn run_broadcast_round(n: usize, latency: Duration, payload: usize) -> NetworkReport {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(broadcast_round(n, latency, payload))
}

/// Build a multi-threaded Tokio runtime and run [`tree_gossip`] to completion.
pub fn run_tree_gossip(n: usize, latency: Duration, payload: usize) -> NetworkReport {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(tree_gossip(n, latency, payload))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_broadcast_counts() {
        // n·(n−1) messages, O(n²) bytes, one latency round.
        let r = run_broadcast_round(8, Duration::from_millis(0), 100);
        assert_eq!(r.messages, 8 * 7);
        assert_eq!(r.bytes, 8 * 7 * 100);
        assert_eq!(r.rounds, 1);
    }

    #[test]
    fn test_tree_rounds_logarithmic() {
        // ⌈log₂ n⌉ rounds, n−1 messages for a power-of-two n.
        let r = run_tree_gossip(16, Duration::from_millis(0), 100);
        assert_eq!(r.rounds, 4);
        assert_eq!(r.messages, 15);
    }

    #[test]
    fn test_latency_dominates_tree_wall() {
        // With 20 ms links, 8 leaves ⇒ 3 rounds ⇒ ~60 ms wall.
        let r = run_tree_gossip(8, Duration::from_millis(20), 100);
        assert_eq!(r.rounds, 3);
        assert!(r.wall >= Duration::from_millis(55));
    }
}
