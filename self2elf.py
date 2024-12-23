#!/usr/bin/python3

import os
import sys
from typing import IO
import zlib
import argparse
import sceutils
from scetypes import SecureBool, SceHeader, SelfHeader, AppInfoHeader, ElfHeader, ElfPhdr, ElfShdr, SegmentInfo, SceVersionInfo, SceControlInfo, SceControlInfoDigest256, ControlType, SceControlInfoDRM, SceRIF
from Crypto.Cipher import AES
from Crypto.Util import Counter

from util import use_keys


def self2elf(inf: IO[bytes], outf=open(os.devnull, "wb"), klictxt=b'\0'*16, silent=False, ignore_sysver=False):
    npdrmtype = 0

    sce = SceHeader(inf.read(SceHeader.Size))
    if not silent:
        print(sce)
    self_hdr = SelfHeader(inf.read(SelfHeader.Size))

    inf.seek(self_hdr.appinfo_offset)
    appinfo_hdr = AppInfoHeader(inf.read(AppInfoHeader.Size))
    if ignore_sysver:
        appinfo_hdr.sys_version = -1
    if not silent:
        print(appinfo_hdr)

    inf.seek(self_hdr.sceversion_offset)
    verinfo_hdr = SceVersionInfo(inf.read(SceVersionInfo.Size))
    if not silent:
        print(verinfo_hdr)

    inf.seek(self_hdr.controlinfo_offset)
    controlinfo_hdr = None
    while controlinfo_hdr is None or controlinfo_hdr.more:
        controlinfo_hdr = SceControlInfo(inf.read(SceControlInfo.Size))
        if not silent:
            print(controlinfo_hdr)
    
        if controlinfo_hdr.type == ControlType.CONTROL_FLAGS:
            inf.read(0x20)

        elif controlinfo_hdr.type == ControlType.DIGEST_SHA256:
            controldigest256 = SceControlInfoDigest256(inf.read(SceControlInfoDigest256.Size))
            if not silent:
                print(controldigest256)

        elif controlinfo_hdr.type == ControlType.NPDRM_VITA:
            controlnpdrm = SceControlInfoDRM(inf.read(SceControlInfoDRM.Size))
            npdrmtype = controlnpdrm.npdrm_type
            if not silent:
                print(controlnpdrm)
        
        elif controlinfo_hdr.type == ControlType.UNK_SIG1:
            inf.read(controlinfo_hdr.size-0x10)
        
        elif controlinfo_hdr.type == ControlType.UNK_HASH1:
            inf.read(controlinfo_hdr.size-0x10)

        else:
            #print(f"WARN: Unhandled ControlInfo {controlinfo_hdr.type}")
            inf.read(controlinfo_hdr.size-0x10)

    # read ehdr
    inf.seek(self_hdr.elf_offset)
    dat = inf.read(ElfHeader.Size)
    elf_hdr = ElfHeader(dat)
    if not silent:
        print(elf_hdr)

    # read phdr
    elf_phdrs: list[ElfPhdr] = []
    inf.seek(self_hdr.phdr_offset)
    for i in range(elf_hdr.e_phnum):
        dat = inf.read(ElfPhdr.Size)
        phdr = ElfPhdr(dat)
        if not silent:
            print(phdr)
        elf_phdrs.append(phdr)
    
    # read shdr
    elf_shdrs: list[ElfShdr] = []
    inf.seek(self_hdr.shdr_offset)
    for i in range(elf_hdr.e_shnum):
        dat = inf.read(ElfShdr.Size)
        shdr = ElfShdr(dat)
        if not silent:
            print(shdr)
        elf_shdrs.append(shdr)
    
    # read segment infos
    encrypted = False
    segment_infos: list[SegmentInfo] = []
    inf.seek(self_hdr.segment_info_offset)
    for i in range(elf_hdr.e_phnum):
        segment_info = SegmentInfo(inf.read(SegmentInfo.Size))
        if not silent:
            print(segment_info)
        segment_infos.append(segment_info)
        if segment_info.plaintext == SecureBool.NO:
            encrypted = True

    # falsely has sections set to what it was before stripping
    if elf_hdr.e_machine == 0xf00d:
        elf_hdr.e_shoff = 0
        elf_hdr.e_shnum = 0

    # placeholder elf header
    elf_header_offset = outf.tell()
    outf.write(b"0" * ElfHeader.Size)

    # get keys
    scesegs = {}
    if encrypted:
        scesegs = sceutils.get_segments(inf, sce, appinfo_hdr.sys_version, appinfo_hdr.self_type, npdrmtype, klictxt, silent)

    # placeholder phdrs
    phdrs_offset = outf.tell()
    outf.write(b"0" * (ElfPhdr.Size * len(elf_phdrs)))

    phdr_offsets_out: list[int] = [0] * elf_hdr.e_phnum
    # copy segments, decrypted and decompressed if needed
    for i in range(elf_hdr.e_phnum):
        idx = scesegs[i].idx if scesegs else i
        phdr = elf_phdrs[idx]
        segment_info = segment_infos[idx]

        if phdr.p_filesz == 0:
            continue

        if not silent:
            print(f'Dumping segment {idx}...')

        # data
        inf.seek(segment_info.offset)
        dat = inf.read(segment_info.size)

        # encryption
        if segment_infos[idx].plaintext == SecureBool.NO:
            ctr = Counter.new(128, initial_value=int.from_bytes(scesegs[i].iv, "big"))
            section_aes = AES.new(scesegs[i].key, AES.MODE_CTR, counter=ctr)
            dat = section_aes.decrypt(dat)
        
        # compression
        if segment_infos[idx].compressed == SecureBool.YES:
            z = zlib.decompressobj()
            dat = z.decompress(dat)

        # write alignment
        align_bytes = outf.tell() % phdr.p_align
        outf.write(b"\0" * align_bytes)

        # write back
        phdr_offsets_out[i] = outf.tell()
        outf.write(dat)

    # write phdrs
    outf.seek(phdrs_offset)
    for phdr, data_offset in zip(elf_phdrs, phdr_offsets_out):
        prev_offset = phdr.p_offset
        phdr.p_offset = data_offset
        outf.write(phdr.pack())
        phdr.p_offset = prev_offset

    # placeholder shdr
    shdrs_offset = outf.seek(0, 2)
    outf.write(b"0" * (ElfShdr.Size * elf_hdr.e_shnum))

    # write shdr data that isnt in any segments, ie things not loaded by the os
    shdr_offsets_out: list[int] = [0] * elf_hdr.e_shnum
    for i in range(elf_hdr.e_shnum):
        shdr = elf_shdrs[i]
        # sections that are inside of segments dont need to be copied again, need to adjust the sh_offset
        overlaps = False
        for phdr, phdr_offset in zip(elf_phdrs, phdr_offsets_out):
            if shdr.sh_offset >= phdr.p_offset and shdr.sh_offset < phdr.p_offset + phdr.p_filesz:
                shdr_offsets_out[i] = shdr.sh_offset + (phdr_offset - phdr.p_offset)
                overlaps = True
                break
        if overlaps:
            continue

        inf.seek(shdr.sh_offset + sce.header_length)
        dat = inf.read(shdr.sh_size)
        
        shdr_offsets_out[i] = outf.tell()
        outf.write(dat)

    # write shdrs
    if elf_hdr.e_shnum > 0:
        outf.seek(shdrs_offset)
        for shdr, data_offset in zip(elf_shdrs, shdr_offsets_out):
            prev_offset = shdr.sh_offset
            shdr.sh_offset = data_offset
            outf.write(shdr.pack())
            shdr.sh_offset = prev_offset
    
    # write ehdr
    outf.seek(elf_header_offset)
    elf_hdr.e_phoff = phdrs_offset
    if elf_hdr.e_shnum > 0:
        elf_hdr.e_shoff = shdrs_offset
    outf.write(elf_hdr.pack())


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--inputfile", help="input file name", type=str, required=True)
    parser.add_argument("-o", "--outputfile", help="output file name", type=str, required=True)
    parser.add_argument("-k", "--keyriffile", help="NoNpdrm RIF file name", type=str)
    parser.add_argument("-z", "--zrif", help="zrif string", type=str)
    parser.add_argument("-K", "--keys", help="keys filename", type=str, default="keys_external.py")
    args = parser.parse_args(args)
    
    use_keys(args.keys)

    if args.outputfile == "null":
        args.outputfile = os.devnull
    
    with open(args.inputfile, "rb") as inf:
        with open(args.outputfile, "wb") as outf:
            if args.keyriffile:
                with open(args.keyriffile, "rb") as rif:
                    lic = SceRIF(rif.read(SceRIF.Size))
                    self2elf(inf, outf, lic.klicense)
            elif args.zrif:
                rif = sceutils.zrif_decode(args.zrif)[:SceRIF.Size]
                lic = SceRIF(rif)
                self2elf(inf, outf, lic.klicense)
            else:
                self2elf(inf, outf)


if __name__ == "__main__":
    
    main(sys.argv[1:])
