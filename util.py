import struct

def _make_unpacker(fmt):
    size = struct.calcsize(fmt)
    unpacker = struct.Struct(fmt)

    def f(data, off=0):
        return unpacker.unpack(data[off:off + size])[0]
    return f

u8 = _make_unpacker("<B")
u16 = _make_unpacker("<H")
u32 = _make_unpacker("<I")
u64 = _make_unpacker("<Q")

u8b = _make_unpacker(">B")
u16b = _make_unpacker(">H")
u32b = _make_unpacker(">I")
u64b = _make_unpacker(">Q")


def c_str(data):
    return data[:data.find(b"\x00")].decode("utf8")



FSTYPE = [
    "unknown0",
    "os0",
    "unknown2",
    "unknown3",
    "vs0_chmod",
    "unknown5",
    "unknown6",
    "unknown7",
    "pervasive8",
    "boot_slb2",
    "vs0",
    "devkit_cp",
    "motionC",
    "bbmc",
    "unknownE",
    "motionF",
    "touch10",
    "touch11",
    "syscon12",
    "syscon13",
    "pervasive14",
    "unknown15",
    "vs0_tarpatch",
    "sa0",
    "pd0",
    "pervasive19",
    "unknown1A",
    "psp_emulist",
]

def make_filename(hdr, filetype, typecount):
    magic, version, flags, moffs, metaoffs = struct.unpack("<IIIIQ", hdr[0:24])
    if magic == 0x454353 and version == 3 and flags == 0x30040:
        meta = hdr[metaoffs:]
        t = u8(meta, 4)
        if t < 0x1C:
            name = f"{FSTYPE[t]}-{typecount[t]:02}.pkg"
            typecount[t] += 1
            return name
    return f"unknown-0x{filetype:x}.pkg"
