from __future__ import annotations

ARZL_MAGIC = b"ARZL"

ARLZ_LITERAL_CTX_COUNT = 8
ARLZ_LITERAL_TREE_SIZE = 255
ARLZ_DIST_TREE_SIZE = 31
ARLZ_SHORT_DIST_TREE_SIZE = 7
ARLZ_DIST_SLOTS = 18
ARLZ_STATE_COUNT = 8
ARLZ_LEN_SLOTS = 8
ARLZ_EOF_LEN = 255

ERROR_INVALID_DATA = 0x80560200
ERROR_BUFFER_OVERFLOW = 0x80560201

# Byte offsets inside the SceArlzProbs structure from arlz.c.
_LIT_OFF = 0x000
_LIT_STRIDE = ARLZ_LITERAL_TREE_SIZE
_DIST_TREE_OFF = 0x7F8
_SHORT_DIST_TREE_OFF = 0x8F0
_DIST_BITS_OFF = 0x928
_IS_MATCH_OFF = 0xB68
_LEN_BITS_OFF = 0xBA8
_PROBS_SIZE = 0xCA8
# A little slack for the pointer-style accesses in the reference code.
_PROBS_PADDING = 256


class ArlzError(RuntimeError):
    """Base class for ARZL errors."""

    code: int

    def __init__(self, code: int, message: str | None = None):
        self.code = code
        super().__init__(message or f"ARZL error 0x{code:08X}")


class ArlzInvalidDataError(ArlzError):
    def __init__(self) -> None:
        super().__init__(ERROR_INVALID_DATA, "invalid ARZL data")


class ArlzBufferOverflowError(ArlzError):
    def __init__(self) -> None:
        super().__init__(ERROR_BUFFER_OVERFLOW, "ARZL output buffer overflow")


class _Decoder:
    __slots__ = ("src", "pos", "range", "code", "probs", "lit_shift")

    def __init__(self, src: bytes) -> None:
        self.src = src
        self.pos = 5
        prop = src[0]
        fill = ((8 - ((prop >> 3) & 3)) << 4) & 0xF0
        self.probs = bytearray([fill]) * (_PROBS_SIZE + _PROBS_PADDING)
        self.lit_shift = prop & 7
        self.range = 0xFFFFFFFF
        self.code = (src[1] << 24) | (src[2] << 16) | (src[3] << 8) | src[4]

    def _var_bits(self, table_off: int, slot: int, pos_ctx: int,
                  low_ctx: int) -> int:
        r = self.range
        c = self.code
        p = self.pos
        src = self.src
        probs = self.probs
        extra = slot - 3

        # The reference uses a byte pointer into the probability struct, so
        # offsets 8/16/24 may intentionally cross into the next sub-table.
        prob_off = (table_off + slot * 32
                    + (((pos_ctx << slot) & 3) * 8) + (low_ctx & 7))

        if (r >> 24) == 0:
            r = (r << 8) & 0xFFFFFFFF
            c = ((c << 8) | src[p]) & 0xFFFFFFFF
            p += 1

        prob = probs[prob_off]
        next_prob = (prob - (prob >> 4)) & 0xFFFFFFFF
        bound = prob * (r >> 8)
        if c >= bound:
            c -= bound
            r -= bound
            high = 4
            val = 2
        else:
            next_prob = (next_prob + 15) & 0xFFFFFFFF
            r = bound
            high = 6
            val = 3
        probs[prob_off] = next_prob & 0xFF

        if extra >= 0:
            if extra != 0:
                if (r >> 24) == 0:
                    r = (r << 8) & 0xFFFFFFFF
                    c = ((c << 8) | src[p]) & 0xFFFFFFFF
                    p += 1

                prob = next_prob & 0xFF
                next_prob = (prob - (prob >> 4)) & 0xFFFFFFFF
                bound = prob * (r >> 8)
                if c >= bound:
                    r -= bound
                    c -= bound
                else:
                    next_prob = (next_prob + 15) & 0xFFFFFFFF
                    high = (high + 1) & 0xFFFFFFFF
                    r = bound
                probs[prob_off] = next_prob & 0xFF

                if extra != 1:
                    if (r >> 24) == 0:
                        r = (r << 8) & 0xFFFFFFFF
                        c = ((c << 8) | src[p]) & 0xFFFFFFFF
                        p += 1

                    while True:
                        r >>= 1
                        extra -= 1
                        high = ((high << 1) + (1 if c < r else 0)) & 0xFFFFFFFF
                        if c >= r:
                            c -= r
                        if extra == 1:
                            break

                high = (high << 1) & 0xFFFFFFFF

            if (r >> 24) == 0:
                r = (r << 8) & 0xFFFFFFFF
                c = ((c << 8) | src[p]) & 0xFFFFFFFF
                p += 1

            prob = probs[prob_off + 24]
            next_prob = (prob - (prob >> 4)) & 0xFFFFFFFF
            bound = prob * (r >> 8)
            if c >= bound:
                c -= bound
                r -= bound
            else:
                high = (high + 1) & 0xFFFFFFFF
                r = bound
                next_prob = (next_prob + 15) & 0xFFFFFFFF
            val = high
            probs[prob_off + 24] = next_prob & 0xFF

        if slot > 0:
            if (r >> 24) == 0:
                r = (r << 8) & 0xFFFFFFFF
                c = ((c << 8) | src[p]) & 0xFFFFFFFF
                p += 1

            prob = probs[prob_off + 8]
            val = (val << 1) & 0xFFFFFFFF
            next_prob = (prob - (prob >> 4)) & 0xFFFFFFFF
            bound = prob * (r >> 8)
            if c >= bound:
                r -= bound
                c -= bound
            else:
                next_prob = (next_prob + 15) & 0xFFFFFFFF
                val = (val + 1) & 0xFFFFFFFF
                r = bound
            probs[prob_off + 8] = next_prob & 0xFF

            if slot != 1:
                if (r >> 24) == 0:
                    r = (r << 8) & 0xFFFFFFFF
                    c = ((c << 8) | src[p]) & 0xFFFFFFFF
                    p += 1

                prob = probs[prob_off + 16]
                val = (val << 1) & 0xFFFFFFFF
                next_prob = (prob - (prob >> 4)) & 0xFFFFFFFF
                bound = prob * (r >> 8)
                if c >= bound:
                    c -= bound
                    r -= bound
                else:
                    val = (val + 1) & 0xFFFFFFFF
                    r = bound
                    next_prob = (next_prob + 15) & 0xFFFFFFFF
                probs[prob_off + 16] = next_prob & 0xFF

        self.range = r
        self.code = c
        self.pos = p
        return val

    def decode(self, capacity: int) -> tuple[bytes, int]:
        src = self.src
        prop = src[0]

        if prop & 0x80:
            size = self.code
            if capacity < size:
                raise ArlzBufferOverflowError()
            return bytes(src[5:5 + size]), 5 + size

        probs = self.probs
        lit_shift = self.lit_shift
        r = self.range
        c = self.code
        p = self.pos
        out = bytearray(capacity)
        out_end = capacity
        out_pos = 0
        sym = 0
        state = 0

        if out_end == 0:
            raise ArlzBufferOverflowError()

        while True:
            # --- decode_literal ---
            ctx = (sym & ~0x700) | ((out_pos & 7) << 8)
            lit_off = (((ctx >> lit_shift) & 7) * _LIT_STRIDE)

            sym = 1
            while True:
                if (r >> 24) == 0:
                    r = (r << 8) & 0xFFFFFFFF
                    c = ((c << 8) | src[p]) & 0xFFFFFFFF
                    p += 1

                prob = probs[lit_off + sym - 1]
                sym <<= 1
                bound = prob * (r >> 8)
                next_prob = (prob - (prob >> 3)) & 0xFFFFFFFF
                r -= bound
                if c < bound:
                    sym += 1
                    next_prob = (next_prob + 31) & 0xFFFFFFFF
                    r = bound
                else:
                    c -= bound
                probs[lit_off + (sym >> 1) - 1] = next_prob & 0xFF
                if sym > 0xFF:
                    break

            while True:
                next_out = out_pos + 1
                out[out_pos] = sym & 0xFF

                # isMatch[0][state]: 0 = literal, 1 = match
                if (r >> 24) == 0:
                    r = (r << 8) & 0xFFFFFFFF
                    c = ((c << 8) | src[p]) & 0xFFFFFFFF
                    p += 1

                match_off = _IS_MATCH_OFF + state
                prob = probs[match_off]
                next_prob = (prob - (prob >> 4)) & 0xFFFFFFFF
                bound = prob * (r >> 8)
                if c >= bound:
                    probs[match_off] = next_prob & 0xFF
                    out_pos = next_out
                    state = state - 1 if state != 0 else 0
                    r -= bound
                    c -= bound
                    if out_pos >= out_end:
                        raise ArlzBufferOverflowError()
                    break

                probs[match_off] = (next_prob + 15) & 0xFF
                r = bound

                # isMatch[1][state]: 0 = 2-byte match, 1 = longer match
                if (r >> 24) == 0:
                    r = (r << 8) & 0xFFFFFFFF
                    c = ((c << 8) | src[p]) & 0xFFFFFFFF
                    p += 1

                match_off = _IS_MATCH_OFF + 8 + state
                prob = probs[match_off]
                next_prob = (prob - (prob >> 4)) & 0xFFFFFFFF
                bound = prob * (r >> 8)
                if c >= bound:
                    r -= bound
                    c -= bound
                    probs[match_off] = next_prob & 0xFF
                    len_slot = -1
                    length = 1
                    tree_base = _SHORT_DIST_TREE_OFF
                    tree_limit = 64
                else:
                    probs[match_off] = (next_prob + 15) & 0xFF
                    r = bound

                    len_slot = 0
                    while len_slot < 6:
                        if (r >> 24) == 0:
                            r = (r << 8) & 0xFFFFFFFF
                            c = ((c << 8) | src[p]) & 0xFFFFFFFF
                            p += 1

                        match_off = (_IS_MATCH_OFF
                                     + (len_slot + 2) * 8 + state)
                        prob = probs[match_off]
                        next_prob = (prob - (prob >> 4)) & 0xFFFFFFFF
                        bound = prob * (r >> 8)
                        if c >= bound:
                            probs[match_off] = next_prob & 0xFF
                            c -= bound
                            r -= bound
                            break
                        probs[match_off] = (next_prob + 15) & 0xFF
                        r = bound
                        len_slot += 1

                    self.range = r
                    self.code = c
                    self.pos = p
                    length = self._var_bits(_LEN_BITS_OFF, len_slot,
                                            next_out, state)
                    r = self.range
                    c = self.code
                    p = self.pos

                    if length == ARLZ_EOF_LEN:
                        return bytes(out[:next_out]), p

                    if length > 2:
                        tree_base = _DIST_TREE_OFF + len_slot + 1
                        tree_limit = 256
                    else:
                        tree_base = _SHORT_DIST_TREE_OFF + len_slot + 1
                        tree_limit = 64

                tree_idx = 8
                while True:
                    node_off = tree_base + tree_idx - 8
                    if (r >> 24) == 0:
                        r = (r << 8) & 0xFFFFFFFF
                        c = ((c << 8) | src[p]) & 0xFFFFFFFF
                        p += 1

                    prob = probs[node_off]
                    tree_idx <<= 1
                    bound = prob * (r >> 8)
                    next_prob = (prob - (prob >> 3)) & 0xFFFFFFFF
                    r -= bound
                    if c < bound:
                        tree_idx += 8
                        r = bound
                        next_prob = (next_prob + 31) & 0xFFFFFFFF
                    else:
                        c -= bound
                    probs[node_off] = next_prob & 0xFF
                    if tree_idx >= tree_limit:
                        break

                rem = tree_idx - tree_limit
                if rem != 0:
                    dist_slot = (rem >> 3) - 1
                    self.range = r
                    self.code = c
                    self.pos = p
                    dist = self._var_bits(_DIST_BITS_OFF, dist_slot,
                                          1 if length > 2 else 0,
                                          len_slot) - 1
                    r = self.range
                    c = self.code
                    p = self.pos
                else:
                    dist = 0

                if dist == 0xFFFFFFFF or next_out <= dist:
                    raise ArlzInvalidDataError()

                match_end = next_out + length
                if out_end <= match_end:
                    raise ArlzBufferOverflowError()

                # The match source is one byte before next_out - dist; this
                # mirrors the byte-wise copy in the reference implementation.
                src_start = next_out - dist - 1
                if length <= dist + 1:
                    out[next_out:match_end] = out[src_start:src_start + length]
                else:
                    for i in range(length):
                        out[next_out + i] = out[src_start + i]
                sym = out[match_end - dist - 1]

                state = 7
                out_pos = match_end


def arzl_decode(src: bytes, capacity: int | None = None) -> tuple[bytes, int]:
    """Decode an ARZL stream, returning ``(output, consumed)``.

    ``src`` must start at the ARZL property byte (i.e. directly after the
    optional ``ARZL`` magic).  If ``capacity`` is omitted it is grown until
    the stream fits.
    """
    if len(src) < 5:
        raise ArlzInvalidDataError()

    capacity = max(len(src), 1) if capacity is None else max(capacity, 1)

    while True:
        decoder = _Decoder(src)
        try:
            return decoder.decode(capacity)
        except ArlzBufferOverflowError:
            capacity *= 2
        except IndexError:
            raise ArlzInvalidDataError() from None


def arzl_decompress(src: bytes, capacity: int | None = None) -> bytes:
    """Decode an ARZL stream.  An ``ARZL`` magic prefix is optional."""
    if src[:4] == ARZL_MAGIC:
        src = src[4:]
    return arzl_decode(src, capacity)[0]


def _get_bits(word: int, shift: int, width: int) -> int:
    return (word >> shift) & ((1 << width) - 1)


def _set_bits(word: int, shift: int, width: int, value: int) -> int:
    mask = ((1 << width) - 1) << shift
    return (word & ~mask) | ((value << shift) & mask)


def arzl_arm_filter(data: bytes, encode: int = 0) -> bytes:
    """Apply the SKBL Thumb-2 MOVT / BL filter.

    ``encode`` selects the direction: ``0`` decodes (the usual case),
    non-zero encodes.
    """
    size = len(data)
    if size == 0:
        return b""

    buf = bytearray(data) + bytearray(4)
    p = 0
    while p < size:
        next_off = p + 4
        insn = int.from_bytes(buf[p:p + 4], "little")
        op = insn & 0xF800F800

        if (insn & 0x8000FBF0) == 0x0000F2C0:
            # MOVT: swap the Rd and imm4 nibbles.
            rd = _get_bits(insn, 24, 4)
            imm4 = _get_bits(insn, 0, 4)
            value = (insn & ~0xF) | rd
            value = _set_bits(value, 24, 4, imm4)
            buf[p:p + 4] = value.to_bytes(4, "little")
        elif op == 0xF800F000:
            # BL: relocate the 22-bit branch offset.
            imm11_hi = _get_bits(insn, 0, 11)
            imm11_lo = _get_bits(insn, 16, 11)
            target = imm11_lo | (imm11_hi << 11)
            offset = next_off >> 1
            rel = (target - offset) if encode == 0 else (target + offset)
            rel &= 0xFFFFFFFF
            value = 0xF800F000
            value = _set_bits(value, 0, 11, rel >> 11)
            value = _set_bits(value, 16, 11, rel)
            buf[p:p + 4] = value.to_bytes(4, "little")
        elif (op >> 27) == 0x1E:
            next_off = p + 2

        p = next_off

    return bytes(buf[:size])


def unarzl(data: bytes) -> bytes:
    """Decode an ARZL-compressed segment and undo the ARM filtering."""
    if data[:4] == ARZL_MAGIC:
        data = data[4:]
    return arzl_arm_filter(arzl_decompress(data), encode=0)


# Aliases matching the C function names.
sce_arlz_decode = arzl_decode
sce_arlz_arm_filter = arzl_arm_filter

__all__ = [
    "ARZL_MAGIC",
    "ArlzError",
    "ArlzInvalidDataError",
    "ArlzBufferOverflowError",
    "arzl_decode",
    "arzl_decompress",
    "arzl_arm_filter",
    "unarzl",
    "sce_arlz_decode",
    "sce_arlz_arm_filter",
]
