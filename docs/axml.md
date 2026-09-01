# Binary Android XML (AXML)

Real APKs store `AndroidManifest.xml` as Android binary XML, not text. AndroidSecForge
decodes it with a self-contained parser (`backend/app/analysis/axml.py`) — no external
tool is required.

## Chunk format

The decoder reads the documented `ResChunk` layout:

- `RES_XML` file header (magic `03 00 08 00`, total size).
- `RES_STRING_POOL` — UTF-8 or UTF-16 string pool (flag-driven), length-prefixed strings.
- `RES_XML_RESOURCE_MAP` — skipped (attribute names are resolved from the string pool).
- `RES_XML_START_NAMESPACE` / `END_NAMESPACE` — prefix → URI mapping.
- `RES_XML_START_ELEMENT` / `END_ELEMENT` — element tree with attributes.

Attribute values are resolved from the raw string reference, or decoded from the typed
`Res_value` (`TYPE_STRING`, `TYPE_INT_DEC`, `TYPE_INT_BOOLEAN`, `TYPE_REFERENCE`, …).

## Safety

- Malformed, truncated, or non-AXML input raises `AXMLError`; the pipeline records this as a degraded manifest rather than crashing.
- The parser only reads structured data — it never executes anything from the APK.
- Chunk sizes and offsets are bounds-checked.

## Plain XML

`parse_manifest()` dispatches: binary AXML → `decode_axml`, text starting with `<` →
`ElementTree`, anything else → `unsupported_binary_xml`. Both paths produce the same
typed `ParsedManifest`.

## Encoder (test fixtures only)

`encode_axml()` produces a valid binary manifest from a small element spec. It exists to
generate the deterministic `AndroidSecForge-TestApp` fixture and to round-trip test the
decoder; it is not used in production analysis.
