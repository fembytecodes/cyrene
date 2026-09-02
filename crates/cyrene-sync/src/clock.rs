use cyrene_core::ReplicaId;
use serde::{Deserialize, Serialize};

/// A totally ordered hybrid logical timestamp.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Timestamp {
    /// Greatest observed physical time in Unix milliseconds.
    pub physical_ms: u64,
    /// Logical counter used when physical time does not advance.
    pub logical: u32,
    /// Replica breaking otherwise equal timestamps deterministically.
    pub replica: ReplicaId,
}

/// Mutable hybrid logical clock state for one replica.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Clock {
    replica: ReplicaId,
    physical_ms: u64,
    logical: u32,
}

impl Clock {
    /// Creates a clock for `replica` with no observed time.
    pub const fn new(replica: ReplicaId) -> Self {
        Self {
            replica,
            physical_ms: 0,
            logical: 0,
        }
    }

    /// Advances the clock for a local event at `now_ms`.
    pub fn tick(&mut self, now_ms: u64) -> Timestamp {
        if now_ms > self.physical_ms {
            self.physical_ms = now_ms;
            self.logical = 0;
        } else {
            self.logical = self.logical.saturating_add(1);
        }
        self.timestamp()
    }

    /// Incorporates a remote timestamp without trusting it as physical time.
    pub fn observe(&mut self, remote: Timestamp, now_ms: u64) {
        let physical = self.physical_ms.max(remote.physical_ms).max(now_ms);
        let logical = if physical == self.physical_ms && physical == remote.physical_ms {
            self.logical.max(remote.logical).saturating_add(1)
        } else if physical == self.physical_ms {
            self.logical.saturating_add(1)
        } else if physical == remote.physical_ms {
            remote.logical.saturating_add(1)
        } else {
            0
        };
        self.physical_ms = physical;
        self.logical = logical;
    }

    /// Returns the clock's current timestamp without advancing it.
    pub const fn timestamp(self) -> Timestamp {
        Timestamp {
            physical_ms: self.physical_ms,
            logical: self.logical,
            replica: self.replica,
        }
    }
}

#[cfg(test)]
mod tests {
    use cyrene_core::ReplicaId;

    use super::Clock;

    #[test]
    fn remains_monotonic_when_physical_time_moves_backwards() {
        let mut clock = Clock::new(ReplicaId::from_u128(1));
        let first = clock.tick(100);
        let second = clock.tick(50);
        assert!(second > first);
        assert_eq!(second.physical_ms, 100);
    }

    #[test]
    fn advances_past_observed_remote_time() {
        let first_id = ReplicaId::from_u128(1);
        let second_id = ReplicaId::from_u128(2);
        let remote = Clock::new(first_id).tick(500);
        let mut local = Clock::new(second_id);
        local.observe(remote, 100);
        assert!(local.tick(100) > remote);
    }
}
