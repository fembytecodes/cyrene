use cyrene_core::{Error, ErrorCode, Result};

use crate::Document;

const MAGIC: &[u8; 4] = b"CYR\0";
const FORMAT_VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 8 + 4;
const CHECKSUM_LEN: usize = 32;

pub(crate) fn encode<T: Document>(value: &T) -> Result<Vec<u8>> {
    // Serializing through `Value` canonicalizes object keys because
    // `serde_json::Map` uses ordered keys without `preserve_order` enabled.
    let canonical = serde_json::to_value(value).map_err(|error| {
        Error::with_source(
            ErrorCode::InvalidInput,
            "the document couldn't be converted to its canonical form",
            error,
        )
    })?;
    let body = serde_json::to_vec(&canonical).map_err(|error| {
        Error::with_source(
            ErrorCode::InvalidInput,
            "the canonical document couldn't be encoded",
            error,
        )
    })?;
    let length = u32::try_from(body.len()).map_err(|error| {
        Error::with_source(
            ErrorCode::InvalidInput,
            "the encoded document exceeds Cyrene's format limit",
            error,
        )
    })?;

    let mut envelope = Vec::with_capacity(HEADER_LEN + body.len() + CHECKSUM_LEN);
    envelope.extend_from_slice(MAGIC);
    envelope.push(FORMAT_VERSION);
    envelope.extend_from_slice(&T::SCHEMA.fingerprint.to_be_bytes());
    envelope.extend_from_slice(&length.to_be_bytes());
    envelope.extend_from_slice(&body);
    let checksum = blake3::hash(&envelope);
    envelope.extend_from_slice(checksum.as_bytes());
    Ok(envelope)
}

pub(crate) fn decode<T: Document>(envelope: &[u8]) -> Result<T> {
    if envelope.len() < HEADER_LEN + CHECKSUM_LEN {
        return Err(invalid_envelope("stored document envelope is truncated"));
    }
    if &envelope[..4] != MAGIC {
        return Err(invalid_envelope(
            "stored document has an unknown format marker",
        ));
    }
    if envelope[4] != FORMAT_VERSION {
        return Err(invalid_envelope(format!(
            "stored document format {} is unsupported (expected {FORMAT_VERSION})",
            envelope[4]
        )));
    }

    let fingerprint = u64::from_be_bytes(
        envelope[5..13]
            .try_into()
            .expect("the fixed header length was checked"),
    );
    if fingerprint != T::SCHEMA.fingerprint {
        return Err(invalid_envelope(format!(
            "stored document schema fingerprint {fingerprint:016x} does not match {:016x}",
            T::SCHEMA.fingerprint
        )));
    }
    let body_len = u32::from_be_bytes(
        envelope[13..17]
            .try_into()
            .expect("the fixed header length was checked"),
    ) as usize;
    let expected_len = HEADER_LEN
        .checked_add(body_len)
        .and_then(|length| length.checked_add(CHECKSUM_LEN))
        .ok_or_else(|| invalid_envelope("stored document length overflows this platform"))?;
    if envelope.len() != expected_len {
        return Err(invalid_envelope("stored document length is inconsistent"));
    }

    let checksum_start = HEADER_LEN + body_len;
    let expected_checksum = &envelope[checksum_start..];
    let actual_checksum = blake3::hash(&envelope[..checksum_start]);
    if expected_checksum != actual_checksum.as_bytes() {
        return Err(invalid_envelope("stored document checksum does not match"));
    }
    serde_json::from_slice(&envelope[HEADER_LEN..checksum_start]).map_err(|error| {
        Error::with_source(
            ErrorCode::InvalidData,
            "stored document does not match its Rust type",
            error,
        )
    })
}

fn invalid_envelope(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde::{Deserialize, Serialize};

    use crate::{Document, ErrorCode};

    #[derive(Debug, Deserialize, Document, Eq, PartialEq, Serialize)]
    struct Example {
        values: HashMap<String, u32>,
    }

    #[test]
    fn encoding_is_deterministic_for_differently_inserted_maps() {
        let first = Example {
            values: HashMap::from([("b".into(), 2), ("a".into(), 1)]),
        };
        let second = Example {
            values: HashMap::from([("a".into(), 1), ("b".into(), 2)]),
        };
        assert_eq!(
            super::encode(&first).unwrap(),
            super::encode(&second).unwrap()
        );
    }

    #[test]
    fn corruption_is_detected_before_deserialization() {
        let value = Example {
            values: HashMap::from([("safe".into(), 1)]),
        };
        let mut bytes = super::encode(&value).unwrap();
        bytes[super::HEADER_LEN] ^= 1;

        let error = super::decode::<Example>(&bytes).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidData);
        assert!(error.message().contains("checksum"));
    }
}
