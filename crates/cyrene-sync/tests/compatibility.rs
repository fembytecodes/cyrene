//! Checked-in compatibility fixtures for published replication messages.

use cyrene_core::{DocumentId, ReplicaId, SpaceId};
use cyrene_sync::{Change, ChangeId, Operation, Timestamp};

const CHANGE_V1: &str = include_str!("fixtures/change-v1-put.json");

#[test]
fn change_v1_fixture_remains_readable_and_byte_stable() {
    let expected = Change {
        id: ChangeId {
            replica: ReplicaId::from_u128(1),
            counter: 1,
        },
        space: SpaceId::from_u128(2),
        timestamp: Timestamp {
            physical_ms: 1_000,
            logical: 0,
            replica: ReplicaId::from_u128(1),
        },
        operation: Operation::Put {
            collection: "notes".into(),
            document: DocumentId::from_u128(3),
            schema: 42,
            payload: vec![1, 2, 3],
        },
    };
    let decoded: Change = serde_json::from_str(CHANGE_V1.trim()).unwrap();
    assert_eq!(decoded, expected);
    assert_eq!(serde_json::to_string(&expected).unwrap(), CHANGE_V1.trim());
}
