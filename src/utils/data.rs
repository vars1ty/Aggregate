use crate::errors::AggregateErrors;
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use std::io::{Read, Write};

/// Utilities for interacting with data.
pub struct DataUtils;

impl DataUtils {
    /// Compresses the specified bytes.
    pub fn compress_bytes(bytes: &[u8]) -> Result<Vec<u8>, AggregateErrors> {
        let mut encoder = ZlibEncoder::new(Vec::with_capacity(64), Compression::fast());
        encoder.write_all(bytes).map_err(|error| {
            AggregateErrors::Io("Failed writing input data into encoder", error)
        })?;
        encoder
            .finish()
            .map_err(|error| AggregateErrors::Io("Failed compressing input data", error))
    }

    /// Decompresses the given bytes.
    pub fn decompress_bytes(bytes: Vec<u8>, output: &mut Vec<u8>) -> Result<(), AggregateErrors> {
        ZlibDecoder::new(bytes.as_slice())
            .read_to_end(output)
            .map_err(|error| AggregateErrors::Io("Failed decompressing input data", error))?;
        Ok(())
    }

    /// Attempts to split `data` into chunks of data to be sent.
    pub fn split_data_to_chunks(
        data: Vec<u8>,
        max_chunk_size: usize,
    ) -> Result<Vec<Vec<u8>>, AggregateErrors> {
        if data.is_empty() {
            return Err(AggregateErrors::SplitInputIsEmpty);
        }

        let total_combined_length = data.len();
        let chunks_needed = total_combined_length.div_ceil(max_chunk_size);
        let mut chunks = Vec::with_capacity(chunks_needed);

        if total_combined_length <= max_chunk_size {
            chunks.insert(0, data);
            return Ok(chunks);
        }

        let remaining_data = data;
        let mut start = 0;

        while start < total_combined_length {
            let chunk_end = (start + max_chunk_size).min(total_combined_length);
            let chunk_size = chunk_end - start;

            // Can't easily avoid this allocation. drain() would also cause
            // it to happen as it would create a new vec and move it all over.
            let mut chunk = Vec::with_capacity(chunk_size);
            chunk.extend_from_slice(&remaining_data[start..chunk_end]);
            chunks.push(chunk);

            start = chunk_end;
        }

        Ok(chunks)
    }
}
