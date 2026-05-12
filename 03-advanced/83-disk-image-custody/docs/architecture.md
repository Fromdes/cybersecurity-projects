# Architecture — Disk Image Hash & Chain-of-Custody

## Single-Pass Multi-Hash

`hash_image()` uses four `hashlib` objects updated in the same loop, so the file is read only once regardless of how many algorithms are computed.

## Chain-of-Custody Model

Each `CustodyEntry` is frozen (immutable once created) and appended. The entire chain is serialized to a single JSON file. The actor and timestamp are auto-captured so the record cannot be falsified without modifying the file.

## Transfer Safety

`transfer` command re-hashes the image before recording the event. If the hash does not match the original `HashResult.sha256`, it aborts and does not add an entry — preventing accidental or malicious transfer of a modified image.
