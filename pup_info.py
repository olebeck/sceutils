#!/usr/bin/env python3

from collections import defaultdict
from dataclasses import dataclass
import struct, enum
from typing import IO

from util import make_filename

def s_read(format, f):
    return struct.unpack(format, f.read(struct.calcsize(format)))

pup_types = {
    0x100: "version.txt",
    0x101: "license.xml",
    0x200: "psp2swu.self",
    0x204: "cui_setupper.self",
    0x400: "package_scewm.wm",
    0x401: "package_sceas.as",
    0x2005: "UpdaterES1.CpUp",
    0x2006: "UpdaterES2.CpUp",
}


class PupTarget(enum.IntEnum):
    TEST = 4
    CEX = 2
    DEX = 1

SCEUF_HEADER_SIZE = 0x80
SCEUF_FILEREC_SIZE = 0x20
@dataclass
class SCEUF:
    magic: bytes #char[7]
    format_flag: int #u8
    format_version: int #u64
    version: int #u32
    build_no: int #u32
    seg_num: int #u64
    header_len: int #u64
    data_len: int #u64
    sign_alg: int #u32
    sign_key_idx: int #u32
    attr: int #u32
    target: PupTarget #u32
    sub_target: int #u32
    support_list: int #u32
    base_version: int #u32
    base_build: int #u32
    unk: bytes #char[0x30]

    @staticmethod
    def read(f: IO[bytes]):
        ret = SCEUF(*s_read("7sBQIIQQQIIIIIIII48s", f))
        ret.target = PupTarget(ret.target)
        ret.unk = None
        return ret

    def print(self):
        print("-" * 80)
        print(f"PUP Version: 0x{self.format_version:x}")
        print(f"Firmware Version: 0x{self.version:08X}")
        print(f"Build Number: {self.build_no}")
        print(f"Number of Files: {self.seg_num}")
        print(f"Target: {self.target.name}")
        print("-" * 80)




def print_info(name: str):
    typecount = defaultdict(int)

    with open(name, "rb") as f:
        header = SCEUF.read(f)
        header.print()

        for x in range(header.seg_num):
            f.seek(SCEUF_HEADER_SIZE + x * SCEUF_FILEREC_SIZE)
            rec = f.read(SCEUF_FILEREC_SIZE)
            filetype, offset, length, flags = struct.unpack("<QQQQ", rec)
            filename = pup_types.get(filetype)

            if not filename:
                f.seek(offset)
                hdr = f.read(0x1000)
                filename = make_filename(hdr, filetype, typecount)

            print(f"{filename=} {filetype=} {offset=:x} {length=:x} {flags=:x}")

if __name__ == "__main__":
    import sys
    fname = sys.argv[1]
    print_info(fname)
