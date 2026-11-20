# Changelog

## 0.2.1

### Fixed
- Plain AI instructions in `data-*` attributes and the page `<title>` are now reported (AI-002). 0.2.0 scanned these places only for obfuscated or encoded instructions, so a plain or partly obfuscated instruction there was missed.
- A page could hide an encoded payload behind a few hundred junk blobs, because decoding stopped after 200 blobs. The limit is now 5,000 blobs or 1.5 s per page.
- `data-*` attributes beyond the 500th were never scanned; the cap is now 5,000.
- When either limit is reached, the scan now says so in its notices instead of skipping content silently.

## 0.2.0

### Added
- **AI-007** decodes text smuggled in invisible Unicode: tag characters ("ASCII smuggling"), variation-selector runs and zero-width binary. Severity follows the decoded content; emoji flags and sequences are ignored.
- **AI-008** catches AI instructions disguised with look-alike letters from other scripts, fullwidth or mathematical letters, leetspeak, spaced-out letters, invisible characters inside words, or right-to-left override reversal.
- **AI-009** decodes base64, hex, percent-encoded and JavaScript-escaped blobs (up to two layers) and reports those that decode to AI instructions or spam.
- **HID-006** flags bidirectional override characters in left-to-right text ("Trojan Source").
- Hidden-text and spam rules (HID-001/002/005, SPM-001, MET-001) now also match de-obfuscated text, so look-alike spellings such as a Cyrillic "casino" are caught.
- `data-*` attributes are now scanned.

### Security
- Reports and all tool results are stripped of invisible characters. Previously Unicode tag characters could pass through excerpts into the agent reading the results.

### Fixed
- Parsing pages with thousands of sibling elements was quadratic (HTML-comment selector computation); a 2 MB page now parses in about 0.15 s instead of 3 s.

## 0.1.0

- First release: `geo_scan_url`, `geo_trace_redirects`, `geo_get_report`; redirect, hidden-content, spam, metadata and AI-injection rules; SSRF protection; SQLite storage.
