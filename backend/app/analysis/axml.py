"""Self-contained Android binary XML (AXML) decoder and a minimal encoder.

The decoder reads the ``AndroidManifest.xml`` chunk format produced by aapt/aapt2
without relying on any external tool. It is deliberately defensive: malformed or
truncated input raises :class:`AXMLError` rather than crashing or executing data.

The encoder is only used to build deterministic binary-AXML test fixtures; it
produces output that this decoder round-trips and that follows the documented
chunk layout closely enough for basic parsers.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# ResChunk_header types
_RES_STRING_POOL = 0x0001
_RES_XML = 0x0003
_RES_XML_START_NAMESPACE = 0x0100
_RES_XML_END_NAMESPACE = 0x0101
_RES_XML_START_ELEMENT = 0x0102
_RES_XML_END_ELEMENT = 0x0103
_RES_XML_CDATA = 0x0104
_RES_XML_RESOURCE_MAP = 0x0180

_UTF8_FLAG = 1 << 8
_NO_ENTRY = 0xFFFFFFFF

# Res_value data types
_TYPE_REFERENCE = 0x01
_TYPE_ATTRIBUTE = 0x02
_TYPE_STRING = 0x03
_TYPE_FLOAT = 0x04
_TYPE_INT_DEC = 0x10
_TYPE_INT_HEX = 0x11
_TYPE_INT_BOOLEAN = 0x12


class AXMLError(ValueError):
    """Raised when binary XML cannot be decoded safely."""


@dataclass
class AXMLElement:
    tag: str
    # attributes keyed by (namespace_uri, local_name) -> string value
    attributes: dict[tuple[str | None, str], str] = field(default_factory=dict)
    children: list["AXMLElement"] = field(default_factory=list)

    def get(self, name: str, namespace: str | None = ANDROID_NS) -> str | None:
        return self.attributes.get((namespace, name))

    def findall(self, tag: str) -> list["AXMLElement"]:
        return [child for child in self.children if child.tag == tag]

    def find(self, tag: str) -> "AXMLElement | None":
        for child in self.children:
            if child.tag == tag:
                return child
        return None


def is_binary_axml(data: bytes) -> bool:
    """Return whether ``data`` begins with the AXML magic (RES_XML chunk)."""
    if len(data) < 8:
        return False
    chunk_type = int.from_bytes(data[0:2], "little")
    header_size = int.from_bytes(data[2:4], "little")
    return chunk_type == _RES_XML and header_size == 8


def _u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 2], "little")


def _u32(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 4], "little")


def _read_utf16_len(data: bytes, off: int) -> tuple[int, int]:
    value = _u16(data, off)
    off += 2
    if value & 0x8000:
        value = ((value & 0x7FFF) << 16) | _u16(data, off)
        off += 2
    return value, off


def _read_utf8_len(data: bytes, off: int) -> tuple[int, int]:
    value = data[off]
    off += 1
    if value & 0x80:
        value = ((value & 0x7F) << 8) | data[off]
        off += 1
    return value, off


def _parse_string_pool(data: bytes, base: int) -> list[str]:
    string_count = _u32(data, base + 8)
    flags = _u32(data, base + 16)
    strings_start = _u32(data, base + 20)
    is_utf8 = bool(flags & _UTF8_FLAG)
    strings: list[str] = []
    offsets_base = base + 28
    data_base = base + strings_start
    for index in range(string_count):
        offset = _u32(data, offsets_base + index * 4)
        pos = data_base + offset
        if pos >= len(data):
            raise AXMLError("string pool offset out of range")
        if is_utf8:
            _chars, pos = _read_utf8_len(data, pos)
            byte_len, pos = _read_utf8_len(data, pos)
            raw = data[pos:pos + byte_len]
            strings.append(raw.decode("utf-8", errors="replace"))
        else:
            char_len, pos = _read_utf16_len(data, pos)
            raw = data[pos:pos + char_len * 2]
            strings.append(raw.decode("utf-16-le", errors="replace"))
    return strings


def _string(pool: list[str], ref: int) -> str | None:
    if ref == _NO_ENTRY or ref >= len(pool):
        return None
    return pool[ref]


def _decode_value(pool: list[str], data_type: int, data: int) -> str:
    if data_type == _TYPE_STRING:
        return _string(pool, data) or ""
    if data_type == _TYPE_INT_BOOLEAN:
        return "true" if data != 0 else "false"
    if data_type in (_TYPE_INT_DEC,):
        return str(_as_signed(data))
    if data_type == _TYPE_INT_HEX:
        return hex(data)
    if data_type == _TYPE_REFERENCE:
        return f"@{data:#010x}"
    if data_type == _TYPE_ATTRIBUTE:
        return f"?{data:#010x}"
    if data_type == _TYPE_FLOAT:
        return str(struct.unpack("<f", struct.pack("<I", data))[0])
    return str(data)


def _as_signed(value: int) -> int:
    return value - 0x100000000 if value & 0x80000000 else value


def decode_axml(data: bytes) -> AXMLElement:
    """Decode binary AXML bytes into an :class:`AXMLElement` tree."""
    if not is_binary_axml(data):
        raise AXMLError("not Android binary XML")
    total = _u32(data, 4)
    limit = min(total, len(data)) if total else len(data)

    pool: list[str] = []
    namespaces: dict[str, str] = {}
    root: AXMLElement | None = None
    stack: list[AXMLElement] = []

    pos = 8
    while pos + 8 <= limit:
        chunk_type = _u16(data, pos)
        chunk_size = _u32(data, pos + 4)
        if chunk_size < 8 or pos + chunk_size > len(data):
            raise AXMLError("invalid chunk size")

        if chunk_type == _RES_STRING_POOL:
            pool = _parse_string_pool(data, pos)
        elif chunk_type == _RES_XML_START_NAMESPACE:
            prefix = _string(pool, _u32(data, pos + 16))
            uri = _string(pool, _u32(data, pos + 20))
            if prefix is not None and uri is not None:
                namespaces[uri] = prefix
        elif chunk_type == _RES_XML_START_ELEMENT:
            element = _parse_start_element(data, pos, pool)
            if root is None:
                root = element
            if stack:
                stack[-1].children.append(element)
            stack.append(element)
        elif chunk_type == _RES_XML_END_ELEMENT:
            if stack:
                stack.pop()
        # END_NAMESPACE / CDATA / RESOURCE_MAP are ignored for manifest parsing.

        pos += chunk_size

    if root is None:
        raise AXMLError("no root element")
    return root


def _parse_start_element(data: bytes, base: int, pool: list[str]) -> AXMLElement:
    name_ref = _u32(data, base + 20)
    attribute_start = _u16(data, base + 24)
    attribute_size = _u16(data, base + 26)
    attribute_count = _u16(data, base + 28)
    tag = _string(pool, name_ref) or ""
    element = AXMLElement(tag=tag)
    attr_base = base + 16 + attribute_start
    for index in range(attribute_count):
        entry = attr_base + index * attribute_size
        ns_uri = _string(pool, _u32(data, entry))
        local_name = _string(pool, _u32(data, entry + 4))
        raw_value_ref = _u32(data, entry + 8)
        data_type = data[entry + 15]
        typed_data = _u32(data, entry + 16)
        raw_value = _string(pool, raw_value_ref)
        if raw_value is not None and data_type == _TYPE_STRING:
            value = raw_value
        else:
            value = _decode_value(pool, data_type, typed_data)
        if local_name:
            element.attributes[(ns_uri, local_name)] = value
    return element


# ---------------------------------------------------------------------------
# Minimal encoder (test-fixture generation only)
# ---------------------------------------------------------------------------


def _encode_utf8_len(count: int) -> bytes:
    if count > 0x7F:
        return bytes([(count >> 8) | 0x80, count & 0xFF])
    return bytes([count])


def _encode_string_pool(strings: list[str]) -> bytes:
    blob = bytearray()
    offsets: list[int] = []
    for value in strings:
        offsets.append(len(blob))
        encoded = value.encode("utf-8")
        blob += _encode_utf8_len(len(value))
        blob += _encode_utf8_len(len(encoded))
        blob += encoded
        blob += b"\x00"
    while len(blob) % 4:
        blob += b"\x00"
    header_size = 28
    strings_start = header_size + len(strings) * 4
    size = strings_start + len(blob)
    chunk = bytearray()
    chunk += struct.pack("<HH", _RES_STRING_POOL, header_size)
    chunk += struct.pack("<I", size)
    chunk += struct.pack("<I", len(strings))
    chunk += struct.pack("<I", 0)  # style count
    chunk += struct.pack("<I", _UTF8_FLAG)
    chunk += struct.pack("<I", strings_start)
    chunk += struct.pack("<I", 0)  # styles start
    for offset in offsets:
        chunk += struct.pack("<I", offset)
    chunk += blob
    return bytes(chunk)


@dataclass
class BuildAttr:
    name: str
    value: str
    kind: str = "string"  # string | int | bool
    namespace: str | None = ANDROID_NS


@dataclass
class BuildElement:
    tag: str
    attrs: list[BuildAttr] = field(default_factory=list)
    children: list["BuildElement"] = field(default_factory=list)


def encode_axml(root: BuildElement) -> bytes:
    """Encode a simple element tree into binary AXML for test fixtures."""
    strings: list[str] = []
    index: dict[str, int] = {}

    def intern(value: str) -> int:
        if value not in index:
            index[value] = len(strings)
            strings.append(value)
        return index[value]

    intern("android")
    intern(ANDROID_NS)

    def collect(element: BuildElement) -> None:
        intern(element.tag)
        for attr in element.attrs:
            intern(attr.name)
            if attr.kind == "string":
                intern(attr.value)
        for child in element.children:
            collect(child)

    collect(root)

    pool = _encode_string_pool(strings)

    body = bytearray()
    body += _start_namespace(intern("android"), intern(ANDROID_NS))
    body += _encode_element(root, intern)
    body += _end_namespace(intern("android"), intern(ANDROID_NS))

    total = 8 + len(pool) + len(body)
    header = struct.pack("<HH", _RES_XML, 8) + struct.pack("<I", total)
    return header + pool + bytes(body)


def _start_namespace(prefix_ref: int, uri_ref: int) -> bytes:
    return (
        struct.pack("<HH", _RES_XML_START_NAMESPACE, 16)
        + struct.pack("<I", 24)
        + struct.pack("<i", -1)  # line number
        + struct.pack("<i", -1)  # comment
        + struct.pack("<I", prefix_ref)
        + struct.pack("<I", uri_ref)
    )


def _end_namespace(prefix_ref: int, uri_ref: int) -> bytes:
    return (
        struct.pack("<HH", _RES_XML_END_NAMESPACE, 16)
        + struct.pack("<I", 24)
        + struct.pack("<i", -1)
        + struct.pack("<i", -1)
        + struct.pack("<I", prefix_ref)
        + struct.pack("<I", uri_ref)
    )


def _encode_element(element: BuildElement, intern) -> bytes:
    name_ref = intern(element.tag)
    android_uri_ref = intern(ANDROID_NS)
    attributes = bytearray()
    for attr in element.attrs:
        ns_ref = android_uri_ref if attr.namespace == ANDROID_NS else _NO_ENTRY
        name = intern(attr.name)
        if attr.kind == "string":
            value_ref = intern(attr.value)
            raw = value_ref
            data_type = _TYPE_STRING
            typed = value_ref
        elif attr.kind == "bool":
            raw = _NO_ENTRY
            data_type = _TYPE_INT_BOOLEAN
            typed = 0xFFFFFFFF if attr.value in ("true", "1", "True") else 0
        else:  # int
            raw = _NO_ENTRY
            data_type = _TYPE_INT_DEC
            typed = int(attr.value) & 0xFFFFFFFF
        attributes += struct.pack("<I", ns_ref & 0xFFFFFFFF)
        attributes += struct.pack("<I", name)
        attributes += struct.pack("<I", raw & 0xFFFFFFFF)
        attributes += struct.pack("<H", 8)  # value size
        attributes += struct.pack("<B", 0)  # res0
        attributes += struct.pack("<B", data_type)
        attributes += struct.pack("<I", typed & 0xFFFFFFFF)

    header_and_ext = bytearray()
    header_and_ext += struct.pack("<i", -1)  # line number
    header_and_ext += struct.pack("<i", -1)  # comment
    header_and_ext += struct.pack("<i", -1)  # namespace
    header_and_ext += struct.pack("<I", name_ref)
    header_and_ext += struct.pack("<H", 20)  # attribute start
    header_and_ext += struct.pack("<H", 20)  # attribute size
    header_and_ext += struct.pack("<H", len(element.attrs))
    header_and_ext += struct.pack("<H", 0)  # id index
    header_and_ext += struct.pack("<H", 0)  # class index
    header_and_ext += struct.pack("<H", 0)  # style index
    header_and_ext += attributes

    start_size = 8 + len(header_and_ext)
    start = struct.pack("<HH", _RES_XML_START_ELEMENT, 16) + struct.pack("<I", start_size) + bytes(header_and_ext)

    children = bytearray()
    for child in element.children:
        children += _encode_element(child, intern)

    end = (
        struct.pack("<HH", _RES_XML_END_ELEMENT, 16)
        + struct.pack("<I", 24)
        + struct.pack("<i", -1)
        + struct.pack("<i", -1)
        + struct.pack("<i", -1)
        + struct.pack("<I", name_ref)
    )
    return start + bytes(children) + end
