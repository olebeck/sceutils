#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from glob import glob
import os
import struct, sys, itertools
import subprocess
from enum import Enum
import zipfile
import pup_fiction

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
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

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

        self.offset = offset*EMMC_BLOCK_SIZE
        self.size = size*EMMC_BLOCK_SIZE
        self.code = EmmcPartitionCode(code)
        self.type = EmmcPartitionType(type)

    def __str__(self):
        str = ''
        str += 'EmmcPartition:\n'
        str += 'Offset (bytes):   0x{:X}\n'.format(self.offset)
        str += 'Size (bytes):     0x{:X} ({})\n'.format(self.size, sizeof_fmt(self.size))
        str += 'Code:             {}\n'.format(self.code)
        str += 'Type:             {}\n'.format(self.type)
        str += 'Active:           {}\n'.format(self.active)
        str += 'Flags:            0x{:08X}\n'.format(self.flags)
        return str

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

        self.size = size*EMMC_BLOCK_SIZE

        partitions = data[0x50:0x160]
        partitions = [
            EmmcPartition(partitions[x:x+EmmcPartition.Size])
            for x in range(0, len(partitions), EmmcPartition.Size)
        ]
        self.partitions = [p for p in itertools.takewhile(lambda x: x.offset != 0, partitions)]

    def __str__(self):
        ret =  'EmmcMasterBlock:\n'
        ret += 'Magic:          {}\n'.format(self.magic)
        ret += 'Version:        {}\n'.format(self.version)
        ret += 'Size (bytes):   0x{:X} ({})\n'.format(self.size, sizeof_fmt(self.size))
        ret += 'Partitions:\n'

        for p in self.partitions:
            ret += '{}\n'.format(p)

        return ret

def main(fname: str):
    " main "

    if fname.endswith(".zip"):
        z = zipfile.PyZipFile(fname)
        emmc = z.open(z.namelist()[0], "r")
    else:
        emmc = open(fname, "rb")

    try:
        base = os.path.dirname(fname)
        master = EmmcMasterBlock(emmc.read(EmmcMasterBlock.Size))
        print(master)

        for p in master.partitions:
            partition_name = p.code.name.lower()
            if len([x for x in master.partitions if x.code == p.code]) > 1:
                partition_name = f"{partition_name}_{'active' if p.active else 'inactive'}"
            name = f'{partition_name}.bin'

            partition_image_name = f"{base}/{name}"
            print(f'extracting {partition_image_name}... ')

            if os.path.exists(partition_image_name):
                print("skip, exists")
                continue

            with open(partition_image_name, "wb") as f:
                emmc.seek(p.offset)
                length = 0

                while length != p.size:
                    data = emmc.read(min(p.size - length, int(100e6)))
                    if len(data) == 0 or data is None:
                        break

                    f.write(data)
                    length += len(data)
                    print(f'{100*length/p.size:.2f}%... ')

            if length != p.size:
                print(f'output {name} is truncated ({100*length/p.size:.2f}% dumped)')

            if p.code in (EmmcPartitionCode.OS0, EmmcPartitionCode.VS0):
                print(f"Extracting {partition_name}")
                partition_out = os.path.join(base, "fs", partition_name)
                subprocess.call(["7z", "x", partition_image_name, f"-o{partition_out}"])

                partition_dec_out = os.path.join(base, "fs_dec", partition_name)
                pup_fiction.decrypt_selfs(partition_out, partition_dec_out)

                if p.code == EmmcPartitionCode.OS0:
                    pup_fiction.decrypt_os0(base)
                    bootimage_out = partition_dec_out+"/kd/bootimage"
                    os.makedirs(bootimage_out, exist_ok=True)
                    pup_fiction.extract_bootimage(partition_dec_out+"/kd/bootimage.elf", bootimage_out)

    finally:
        emmc.close()


if __name__ == "__main__":
    fname_arg = sys.argv[1]
    if len(sys.argv) > 2:
        pup_fiction.use_keys(sys.argv[2])

    if os.path.isdir(fname_arg):
        for zipname in glob(fname_arg+"/*/*.zip"):
            zipname = zipname.replace("\\","/")
            print(zipname)
            main(zipname)
    else:
        main(fname_arg)
