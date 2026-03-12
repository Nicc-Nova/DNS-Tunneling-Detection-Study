# dnsish.py
# Toy, DNS-inspired label encoding for localhost lab use.
# NOT real DNS. Uses a magic header and forbids DNS compression pointers.

from __future__ import annotations

import base64
import struct
import zlib
from dataclasses import dataclass
from typing import List, Optional, Tuple

MAGIC = b"DNSISH"   # Identifies toy protocol (NOT DNS)
VER = 1

MAX_LABEL = 63
MAX_LABELS = 40

# Trailer: msg_id(2) seq(2) total(2) crc32(4) rsv(2) = 12 bytes
TRAILER_LEN = 12

# Flags (bitfield, identify packet type
FLAG_DATA = 1 << 0
FLAG_ACK = 1 << 1
FLAG_BEACON = 1 << 2


class ParseError(Exception):
    pass


@dataclass
class ParsedPacket:
    ver: int
    flags: int
    labels_raw: List[bytes]
    msg_id: int
    seq: int
    total: int
    crc32: int
    rsv: int
    extra_len: int

    @property #convenience for logging/debugging
    def labels_str(self) -> List[str]:
        return [lb.decode("ascii", errors="replace") for lb in self.labels_raw]


def crc32_u32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def b32_encode_no_pad(data: bytes) -> str:
    """RFC 4648 base32; strip '=' padding to shorten."""
    return base64.b32encode(data).decode("ascii").rstrip("=")


def b32_decode_no_pad(text: str) -> bytes:
    """Decode base32 that may omit '=' padding; case-insensitive."""
    t = text.strip().upper()
    pad = (-len(t)) % 8
    t += "=" * pad
    return base64.b32decode(t.encode("ascii"), casefold=True)


def encode_labels(labels: List[bytes]) -> bytes:
    """Encode DNS-style labels: [len][bytes]... terminated by 0x00. No compression."""
    if len(labels) > MAX_LABELS:
        raise ValueError("too many labels")

    out = bytearray()
    for lb in labels:
        if not isinstance(lb, (bytes, bytearray)):
            raise TypeError("label must be bytes")
        if len(lb) > MAX_LABEL:
            raise ValueError(f"label too long: {len(lb)} > {MAX_LABEL}")
        out.append(len(lb))
        out += lb

    out.append(0)  # terminator
    return bytes(out)


def decode_labels(buf: bytes, offset: int) -> Tuple[List[bytes], int]:
    """Decode DNS-style labels starting at offset. Returns (labels, new_offset)."""
    labels: List[bytes] = []
    i = offset

    for _ in range(MAX_LABELS):
        if i >= len(buf):
            raise ParseError("ran out of bytes while parsing labels")

        L = buf[i]
        i += 1

        if L == 0:
            return labels, i

        # Reject DNS compression pointers and any 0b11xxxxxx forms
        if (L & 0xC0) != 0:
            raise ParseError(f"compression/pointer-like length byte: 0x{L:02x}")

        if L > MAX_LABEL:
            raise ParseError(f"label too long: {L}")

        if i + L > len(buf):
            raise ParseError("label overruns packet")

        labels.append(buf[i:i + L])
        i += L

    raise ParseError("too many labels or missing terminator")


def build_packet(
    *,
    flags: int,
    labels: List[bytes],
    msg_id: int,
    seq: int,
    total: int,
    payload: Optional[bytes] = None,
) -> bytes:
    """
    Build a toy DNS-ish packet.
    - labels: may include fixed 'domain-like' labels and/or payload labels.
    - trailer crc32 is computed over payload if provided, else 0.
    """
    if not (0 <= msg_id <= 0xFFFF and 0 <= seq <= 0xFFFF and 0 <= total <= 0xFFFF):
        raise ValueError("msg_id/seq/total out of range")

    out = bytearray()
    out += MAGIC
    out += bytes([VER, flags & 0xFF, 0])  # ver, flags, reserved

    out += encode_labels(labels)

    crc = crc32_u32(payload) if payload is not None else 0
    out += struct.pack(">HHHIH", msg_id, seq, total, crc, 0)
    return bytes(out)


def parse_packet(datagram: bytes) -> ParsedPacket:
    """Parse a toy DNS-ish packet."""
    header_len = len(MAGIC) + 3  # MAGIC + ver + flags + reserved
    if len(datagram) < header_len + 1 + TRAILER_LEN:
        raise ParseError("too short")

    if datagram[:len(MAGIC)] != MAGIC:
        raise ParseError("bad magic")

    ver = datagram[len(MAGIC)]
    flags = datagram[len(MAGIC) + 1]
    offset = len(MAGIC) + 3

    labels_raw, offset = decode_labels(datagram, offset)

    if offset + TRAILER_LEN > len(datagram):
        raise ParseError("missing trailer")

    msg_id, seq, total, crc32, rsv = struct.unpack_from(">HHHIH", datagram, offset)
    offset += TRAILER_LEN
    extra_len = len(datagram) - offset

    return ParsedPacket(
        ver=ver,
        flags=flags,
        labels_raw=labels_raw,
        msg_id=msg_id,
        seq=seq,
        total=total,
        crc32=crc32,
        rsv=rsv,
        extra_len=extra_len,
    )


def payload_to_labels(payload: bytes, prefix_labels: Optional[List[bytes]] = None) -> List[bytes]:
    """Convert payload bytes to base32 text split across <=63B labels."""
    if prefix_labels is None:
        prefix_labels = []
    b32 = b32_encode_no_pad(payload)
    chunks = [b32[i:i + MAX_LABEL] for i in range(0, len(b32), MAX_LABEL)]
    return prefix_labels + [c.encode("ascii") for c in chunks]


def labels_to_payload(labels_raw: List[bytes], skip_prefix: int = 0) -> bytes:
    """Reassemble payload from base32 labels, skipping optional prefix labels."""
    if skip_prefix < 0 or skip_prefix > len(labels_raw):
        raise ValueError("invalid skip_prefix")
    b32_text = b"".join(labels_raw[skip_prefix:]).decode("ascii", errors="strict")
    return b32_decode_no_pad(b32_text)