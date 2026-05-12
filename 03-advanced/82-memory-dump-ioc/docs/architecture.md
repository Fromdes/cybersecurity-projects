# Architecture — Memory Dump IOC Extractor

## Streaming Design

Large memory dumps (2–32GB) require streaming. The extractor reads 1MB chunks with a 256-byte overlap at chunk boundaries to avoid splitting multi-byte IOC values.

## IOC Regex Pipeline

1. Compiled byte patterns (`rb"..."`) applied directly to binary chunks.
2. IPv4: extra filter removes private/loopback addresses.
3. Hashes: `_looks_like_hash_text()` rejects all-same-char or mostly-digit sequences.
4. Results deduplicated via sets across all chunks.
