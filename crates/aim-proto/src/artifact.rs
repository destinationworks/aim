//! Content-addressed Brotli Q6 artifact helpers shared by hub and client.

use brotli::enc::{BrotliEncoderParams, StandardAlloc};
use brotli::{BrotliDecompressStream, BrotliResult, BrotliState};
use sha2::{Digest, Sha256};

use crate::{MAX_ARTIFACT_BR_BYTES, MAX_ARTIFACT_RAW_BYTES};

/// Computes lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Compresses `raw` using Brotli quality level 6. Refuses inputs above
/// `MAX_ARTIFACT_RAW_BYTES` or outputs above `MAX_ARTIFACT_BR_BYTES`.
pub fn compress_q6(raw: &[u8]) -> Result<(String, Vec<u8>), String> {
    if raw.len() > MAX_ARTIFACT_RAW_BYTES {
        return Err(format!(
            "artifact exceeds {MAX_ARTIFACT_RAW_BYTES} bytes uncompressed"
        ));
    }
    let hash = sha256_hex(raw);
    let params = BrotliEncoderParams {
        quality: 6,
        lgwin: 22,
        size_hint: raw.len(),
        ..Default::default()
    };
    let mut compressed = Vec::new();
    brotli::BrotliCompress(&mut &raw[..], &mut compressed, &params)
        .map_err(|e| format!("brotli compression failed: {e}"))?;
    if compressed.len() > MAX_ARTIFACT_BR_BYTES {
        return Err(format!(
            "compressed artifact exceeds {MAX_ARTIFACT_BR_BYTES} bytes"
        ));
    }
    Ok((hash, compressed))
}

/// Decompresses a Brotli payload with a strict upper bound, rejects any
/// trailing bytes past the Brotli stream end, and checks SHA-256 against
/// `expected_sha256`.
pub fn decompress_verified(compressed: &[u8], expected_sha256: &str) -> Result<Vec<u8>, String> {
    if compressed.len() > MAX_ARTIFACT_BR_BYTES {
        return Err(format!(
            "compressed artifact exceeds {MAX_ARTIFACT_BR_BYTES} bytes"
        ));
    }
    let mut state = BrotliState::new(
        StandardAlloc::default(),
        StandardAlloc::default(),
        StandardAlloc::default(),
    );
    let mut available_in = compressed.len();
    let mut input_offset = 0usize;
    let mut total_out = 0usize;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];

    loop {
        let mut available_out = chunk.len();
        let mut output_offset = 0usize;
        let res = BrotliDecompressStream(
            &mut available_in,
            &mut input_offset,
            compressed,
            &mut available_out,
            &mut output_offset,
            &mut chunk,
            &mut total_out,
            &mut state,
        );
        if output_offset > 0 {
            if raw.len().saturating_add(output_offset) > MAX_ARTIFACT_RAW_BYTES {
                return Err(format!(
                    "decompressed artifact exceeds {MAX_ARTIFACT_RAW_BYTES} bytes"
                ));
            }
            raw.extend_from_slice(&chunk[..output_offset]);
        }
        match res {
            BrotliResult::NeedsMoreOutput => continue,
            BrotliResult::NeedsMoreInput => {
                return Err("truncated brotli stream".into());
            }
            BrotliResult::ResultFailure => {
                return Err("invalid brotli stream".into());
            }
            BrotliResult::ResultSuccess => break,
        }
    }

    if available_in != 0 || input_offset != compressed.len() {
        return Err("unexpected trailing data after brotli stream".into());
    }
    let actual = sha256_hex(&raw);
    if actual != expected_sha256 {
        return Err(format!(
            "artifact sha256 mismatch: expected {expected_sha256}, got {actual}"
        ));
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brotli_q6_roundtrip_and_digest_verification() {
        let raw = b"repeated log line for compression\n".repeat(200);
        let (hash, br) = compress_q6(&raw).unwrap();
        assert!(br.len() < raw.len());
        let restored = decompress_verified(&br, &hash).unwrap();
        assert_eq!(restored, raw);

        assert!(decompress_verified(&br, &"0".repeat(64)).is_err());
        assert!(decompress_verified(b"not valid brotli", &hash).is_err());

        let mut smuggled = br.clone();
        smuggled.extend_from_slice(b"trailing-bytes");
        assert!(decompress_verified(&smuggled, &hash).is_err());
    }
}
