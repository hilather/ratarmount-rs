"""Reproduce solid-hashes.7z with Python's liblzma; no 7z executable needed."""

import lzma
from pathlib import Path
import struct
import zlib


def number(value):
    for count in range(8):
        if value < 1 << (7 + 7 * count):
            return bytes([(0xFF << (8 - count) & 0xFF) | (value >> (8 * count))]) + value.to_bytes(8, "little")[:count]
    return b"\xff" + value.to_bytes(8, "little")


def bits(values):
    result = bytearray((len(values) + 7) // 8)
    for i, value in enumerate(values):
        if value:
            result[i // 8] |= 0x80 >> (i % 8)
    return bytes(result)


def property_bytes(kind, value):
    return bytes([kind]) + number(len(value)) + value


# Archive order deliberately differs from name order, with empty/anti entries
# and a symlink interspersed among regular streams. These occupy member indices
# even though they do not get content hashes.
members = [
    ("dir/", None, 0o40755, False),
    ("dir/b.txt", b"second file\n" * 32, 0o100644, False),
    ("empty", None, 0o100644, False),
    ("gone", None, 0o100644, True),
    ("link", b"dir/b.txt", 0o120777, False),
    ("dir/text.txt", b"content hash\n" * 32, 0o100644, False),
    ("emptydir/", None, 0o40755, False),
    ("dir/c.txt", b"third member\n" * 32, 0o100644, False),
]
streams = [body for _, body, _, _ in members if body is not None]
payload = b"".join(streams)
packed = lzma.compress(payload, format=lzma.FORMAT_RAW,
                       filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 4096}])
# MainStreamsInfo: one LZMA2 folder (dictionary property 0 = 4096), multiple
# substreams. All integrity CRCs are optional except the two header CRCs.
header = b"\x01\x04\x06\x00\x01\x09" + number(len(packed)) + b"\x00"
header += b"\x07\x0b\x01\x00\x01\x21\x21\x01\x00\x0c" + number(len(payload)) + b"\x00"
header += b"\x08\x0d" + number(len(streams)) + b"\x09"
header += b"".join(number(len(body)) for body in streams[:-1]) + b"\x00\x00"
header += b"\x05" + number(len(members))
header += property_bytes(14, bits([body is None for _, body, _, _ in members]))
empty = [m for m in members if m[1] is None]
header += property_bytes(15, bits([mode & 0o170000 != 0o40000 for _, _, mode, _ in empty]))
header += property_bytes(16, bits([anti for _, _, _, anti in empty]))
header += property_bytes(17, b"\x00" + "".join(name + "\0" for name, _, _, _ in members).encode("utf-16le"))
header += property_bytes(21, b"\x01\x00" + b"".join(
    struct.pack("<I", (mode << 16) | 0x8000 | (0x10 if mode & 0o170000 == 0o40000 else 0))
    for _, _, mode, _ in members))
header += b"\x00\x00"
start = struct.pack("<QQI", len(packed), len(header), zlib.crc32(header))
archive = b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", zlib.crc32(start)) + start + packed + header
Path(__file__).with_name("solid-hashes.7z").write_bytes(archive)
