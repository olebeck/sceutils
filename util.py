import struct


def _make_unpacker(tag):
    fmt = f"<{tag}"
    size = struct.calcsize(fmt)
    unpacker = struct.Struct(fmt)

    def f(data, off=0):
        return unpacker.unpack(data[off:off + size])[0]
    return f


def _make_unpacker_big(tag):
    fmt = f">{tag}"
    size = struct.calcsize(fmt)
    unpacker = struct.Struct(fmt)

    def f(data, off=0):
        return unpacker.unpack(data[off:off + size])[0]
    return f


u8 = _make_unpacker("B")
u16 = _make_unpacker("H")
u32 = _make_unpacker("I")
u64 = _make_unpacker("Q")

u8b = _make_unpacker_big("B")
u16b = _make_unpacker_big("H")
u32b = _make_unpacker_big("I")
u64b = _make_unpacker_big("Q")


def c_str(data):
    return data[:data.find(b"\x00")].decode("utf8")
