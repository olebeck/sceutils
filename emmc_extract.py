#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from glob import glob
import os
import struct, sys, itertools
import subprocess
from enum import Enum
import zipfile

import pup_fiction
from keys import use_keys

DO_EXTRACT = True
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
        ret =  'EmmcPartition:\n'
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

        self.size = size*EMMC_BLOCK_SIZE

        partitions = data[0x50:0x160]
        partitions = [
            EmmcPartition(partitions[x:x+EmmcPartition.Size])
            for x in range(0, len(partitions), EmmcPartition.Size)
        ]
        self.partitions = [p for p in itertools.takewhile(lambda x: x.offset != 0, partitions)]

    def __str__(self):
        ret =  'EmmcMasterBlock:\n'
        ret += f'Magic:          {self.magic}\n'
        ret += f'Version:        {self.version}\n'.format()
        ret += f'Size (bytes):   0x{self.size:X} ({sizeof_fmt(self.size)})\n'
        ret += 'Partitions:\n'

        for p in self.partitions:
            ret += f'{p}\n'

        return ret

def main(fname: str, output_arg: str):
    " main "

    if fname.endswith(".zip"):
        z = zipfile.PyZipFile(fname)
        emmc = z.open(z.namelist()[0], "r")
    else:
        emmc = open(fname, "rb")

    os.makedirs(output_arg, exist_ok=True)

    try:
        base = output_arg
        master = EmmcMasterBlock(emmc.read(EmmcMasterBlock.Size))
        print(master)

        for p in master.partitions:
            partition_name = p.code.name.lower()
            if len([x for x in master.partitions if x.code == p.code]) > 1:
                partition_name = f"{partition_name}_{'active' if p.active else 'inactive'}"
            name = f'{partition_name}.bin'

            partition_image_name = f"{base}/{name}"
            print(f'extracting {partition_image_name}... ')

            if not os.path.exists(partition_image_name):
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

            if p.code in (EmmcPartitionCode.OS0, EmmcPartitionCode.VS0) and DO_EXTRACT:
                print(f"Extracting {partition_name}")
                partition_out = os.path.join(base, "fs", partition_name)
                if not os.path.exists(partition_out):
                    subprocess.call(["7z", "x", partition_image_name, f"-o{partition_out}"])

                partition_dec_out = os.path.join(base, "fs_dec", partition_name)
                if not os.path.exists(partition_dec_out):
                    print("Decryping selfs")
                    pup_fiction.decrypt_selfs(partition_out, partition_dec_out)

                if p.code == EmmcPartitionCode.OS0:
                    if not os.path.exists(partition_dec_out):
                        print("decrypting os0")
                        pup_fiction.decrypt_os0(base)

                    try:
                        bootimage_out = partition_dec_out+"/kd/bootimage"
                        if not os.path.exists(bootimage_out):
                            print("decrypting bootimage")
                            os.makedirs(bootimage_out, exist_ok=True)
                            pup_fiction.extract_bootimage(partition_dec_out+"/kd/bootimage.elf", bootimage_out)
                    except Exception as e:
                        print("error extracting bootimage")
                        print(e)

            if p.code == EmmcPartitionCode.SLB2 and DO_EXTRACT:
                slb2_out = os.path.join(base, partition_name)
                if not os.path.exists(slb2_out):
                    print("extracting slb2")
                    os.makedirs(slb2_out, exist_ok=True)
                    pup_fiction.slb2_extract(partition_image_name, slb2_out)

                slb2_dec_out = os.path.join(base, partition_name+"_dec")
                if not os.path.exists(slb2_dec_out):
                    print("decrypting slb2")
                    os.makedirs(slb2_dec_out, exist_ok=True)
                    try:
                        pup_fiction.slb2_decrypt(slb2_out, slb2_dec_out)
                    except KeyError as e:
                        with open(slb2_dec_out+"/error.txt", "w", encoding="utf8") as f:
                            f.write(str(e))
                        print(e)

    finally:
        emmc.close()


if __name__ == "__main__":
    fname_arg = sys.argv[1]
    output_arg = sys.argv[2]

    use_keys(sys.argv[3] if len(sys.argv) > 3 else "keys_external.py")

    if os.path.isdir(fname_arg):
        for zipname in glob(fname_arg+"/*/*.zip"):
            zipname = zipname.replace("\\","/")
            print(zipname)
            main(zipname, output_arg)
        for imgname in glob(fname_arg+"/*/*.img"):
            print(imgname)
            main(imgname, output_arg)
    else:
        main(fname_arg, output_arg)
