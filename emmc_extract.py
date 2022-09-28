#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import struct, sys, itertools
from enum import Enum

EMMC_BLOCK_SIZE = 512


class EmmcPartitionCode(Enum):
    EMPTY = 0
    IDSTORAGE = 1
    SLB2 = 2
    OS0 = 3
    VS0 = 4
    VD0 = 5
    TM0 = 6
    UR0 = 7
    UX0 = 8
    GRO0 = 9
    GRW0 = 0xA
    UD0 = 0xB
    SA0 = 0xC
    UNKOWN_MC = 0xD
    PD0 = 0xE


class EmmcPartitionType(Enum):
    UNKNOWN_0 = 0
    FAT16 = 0x6
    EXFAT = 0x7
    UNKNOWN = 0xB
    RAW = 0xDA


def sizeof_fmt(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


class EmmcPartition:
    Size = 0x11

    def __init__(self, data):
        (
            offset,
            size,
            code,
            type,
            self.active,
            self.flags,
        ) = struct.unpack('<IIBB?I2x', data)

        self.offset = offset * EMMC_BLOCK_SIZE
        self.size = size * EMMC_BLOCK_SIZE
        self.code = EmmcPartitionCode(code)
        self.type = EmmcPartitionType(type)

    def __str__(self):
        ret = ''
        ret += 'EmmcPartition:\n'
        ret += f'Offset (bytes):   0x{self.offset:X}\n'
        ret += f'Size (bytes):     0x{self.size:X} ({sizeof_fmt(self.size)})\n'
        ret += f'Code:             {self.code}\n'
        ret += f'Type:             {self.type}\n'
        ret += f'Active:           {self.active}\n'
        ret += f'Flags:            0x{self.flags:08X}\n'
        return ret


class EmmcMasterBlock:
    Size = 0x200

    def __init__(self, data):
        (
            self.magic,
            self.version,
            size,
            signature
        ) = struct.unpack('<32sII40x272x94x16x16x16x16xH', data)

        if signature != 0xAA55:
            raise TypeError('Invalid boot signature')

        if self.version != 3:
            raise TypeError('Unknown version')

        self.size = size * EMMC_BLOCK_SIZE

        partitions = data[0x50:0x160]
        partitions = [EmmcPartition(partitions[x:x + EmmcPartition.Size]) for x in range(0, len(partitions), EmmcPartition.Size)]
        self.partitions = [p for p in itertools.takewhile(lambda x: x.offset != 0, partitions)]

    def __str__(self):
        ret = ''
        ret += 'EmmcMasterBlock:\n'
        ret += f'Magic:          {self.magic}\n'
        ret += f'Version:        {self.version}\n'
        ret += f'Size (bytes):   0x{self.size:X} ({sizeof_fmt(self.size)})\n'
        ret += 'Partitions:\n'

        for p in self.partitions:
            ret += f'{p}\n'

        return ret


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("emmc")
    args = parser.parse_args(args)

    with open(args.emmc, "rb") as emmc:
        master = EmmcMasterBlock(emmc.read(EmmcMasterBlock.Size))
        print(master)

        for p in master.partitions:
            has_inactive = len([x for x in master.partitions if x.code == p.code]) > 1
            active_str = ""
            if has_inactive:
                active_str = "_active" if p.active else "_inactive"

            part_code = str(p.code).split(".", 1)[-1]

            name = f'{part_code}{active_str}.bin'.lower()

            print(f'extracting {name}... ')

            with open(name, 'wb') as f:
                emmc.seek(p.offset)
                length = 0

                while length != p.size:
                    data = emmc.read(p.size - length)
                    if len(data) == 0 or data is None:
                        break

                    f.write(data)
                    length += len(data)
                    print(f'{100*length/p.size:.2f}%... ')

            if length != p.size:
                print(f'output {name} is truncated ({100*length/p.size:.2f}% dumped)')

if __name__ == "__main__":
    main(sys.argv)
