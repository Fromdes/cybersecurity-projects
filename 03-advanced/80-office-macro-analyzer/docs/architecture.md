# Architecture — Office Macro Risk Analyzer

## Analysis Path

1. Format detection: OLE2 magic bytes vs OOXML (ZIP) magic.
2. oletools `VBA_Parser` extracts VBA modules from OLE2/OOXML containers.
3. Each VBA module scanned with `_scan_vba_text()` (15 regex patterns).
4. oletools built-in `analyze_macros()` supplements with keyword-level analysis.
5. Fallback: if oletools unavailable, scan raw bytes with same patterns.
6. `_score_from_indicators()` computes weighted 0-100 risk score.

## Fallback Guarantee

The analyzer never raises on missing oletools — regex fallback always runs.
