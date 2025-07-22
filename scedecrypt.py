#!/usr/bin/python3

import os
import sys
if __name__ == "__main__":
    sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import argparse
import pathlib
import binascii
import zlib
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
from typing import IO

from sceutils.scetypes import SceHeader, SceType, KeyType, SelfType, SceSegment, SelfHeader, AppInfoHeader, MetadataInfo, MetadataHeader, MetadataSection, SrvkHeader, SpkgHeader, CompressionType, EncryptionType
import sceutils.keys as keys


def print_metadata_keyvault(keys):
    print(' Metadata Vault:')
    for i, key in enumerate(keys):
        print(f'  {i:#0{4}x}:      {binascii.b2a_hex(key)}')


def get_segments(inf: IO[bytes], sce_hdr: SceHeader, sysver=-1, self_type=SelfType.NONE, keytype=0, klictxt=b"\0"*16, silent=False, use_spkg2=False) -> dict[int, SceSegment]:
    inf.seek(sce_hdr.metadata_offset + 48)
    dat = inf.read(sce_hdr.header_length - sce_hdr.metadata_offset - 48)
    sce_type = sce_hdr.sce_type if not use_spkg2 else (sce_hdr.sce_type, 2)
    (key, iv) = keys.SCE_KEYS.get(KeyType.METADATA, sce_type, sysver, sce_hdr.key_revision, self_type)
    hdr_dec = AES.new(key, AES.MODE_CBC, iv)
    if self_type == SelfType.APP:
        keytype = 0
        if sce_hdr.key_revision >= 2:
            keytype = 1
        (np_key, np_iv) = keys.SCE_KEYS.get(KeyType.NPDRM, sce_type, sysver, keytype, self_type)
        npdrm_dec = AES.new(np_key, AES.MODE_CBC, np_iv)
        predec = npdrm_dec.decrypt(klictxt)
        npdrm_dec2 = AES.new(predec, AES.MODE_CBC, np_iv)
        dec_in = npdrm_dec2.decrypt(dat[0:MetadataInfo.Size()])
    else:
        dec_in = dat[0:MetadataInfo.Size()]

    dec = hdr_dec.decrypt(dec_in)
    metadata_info = MetadataInfo.unpack(dec)
    if not silent:
        print(metadata_info)
    contents_dec = AES.new(metadata_info.key, AES.MODE_CBC, metadata_info.iv)
    dec = contents_dec.decrypt(dat[MetadataInfo.Size():])
    metadata_hdr = MetadataHeader.unpack(dec[0:MetadataHeader.Size()])
    if not silent:
        print(metadata_hdr)
    segs = {}
    start = MetadataHeader.Size() + metadata_hdr.section_count * MetadataSection.Size()
    vault = [dec[start + 16 * x:start + 16 * (x + 1)] for x in range(metadata_hdr.key_count)]
    if not silent:
        print_metadata_keyvault(vault)
    for i in range(metadata_hdr.section_count):
        dat = dec[MetadataHeader.Size() + i * MetadataSection.Size():]
        metsec = MetadataSection.unpack(dat[:MetadataSection.Size()])
        if not silent:
            print(metsec)
        if metsec.encryption == EncryptionType.AES128CTR:
            segs[i] = SceSegment(metsec.offset, metsec.seg_idx, metsec.size, metsec.compression == CompressionType.DEFLATE, vault[metsec.key_idx], vault[metsec.iv_idx])
    return segs


def get_key_type(inf, sce_hdr, silent=False):
    if sce_hdr.sce_type == SceType.SELF:
        inf.seek(32)
        self_hdr = SelfHeader.unpack(inf)
        inf.seek(self_hdr.appinfo_offset)
        appinfo_hdr = AppInfoHeader.unpack(inf)
        if not silent:
            print(appinfo_hdr)
        return (appinfo_hdr.sys_version, appinfo_hdr.self_type), False
    elif sce_hdr.sce_type == SceType.SRVK:
        inf.seek(sce_hdr.header_length)
        srvk = SrvkHeader.unpack(inf)
        if not silent:
            print(srvk)
        return (srvk.sys_version, SelfType.NONE), False
    elif sce_hdr.sce_type == SceType.SPKG:
        inf.seek(sce_hdr.header_length)
        spkg = SpkgHeader.unpack(inf)
        if not silent:
            print(spkg)
        return (spkg.update_version << 16, SelfType.NONE), spkg.field_48 == 0x40
    else:
        print(f'Unknown system version for type {sce_hdr.sce_types}')
        return -1



def scedecrypt(inf, outdir, decompress=True, silent=False):
    sce = SceHeader.unpack(inf)
    if not silent:
        print(sce)
    (sysver, selftype), use_spkg2 = get_key_type(inf, sce, silent)
    scesegs = get_segments(inf, sce, sysver, selftype, silent=silent, use_spkg2=use_spkg2)
    for i, sceseg in scesegs.items():
        if not silent:
            print(f'Decrypting segment {i}...')
        outf = open(os.path.join(outdir, f"{os.path.basename(inf.name)}.seg{i:02}"), "wb")
        inf.seek(sceseg.offset)
        dat = inf.read(sceseg.size)
        ctr = Counter.new(128, initial_value=int.from_bytes(sceseg.iv, "big"))
        section_aes = AES.new(sceseg.key, AES.MODE_CTR, counter=ctr)
        dat = section_aes.decrypt(dat)
        if decompress and sceseg.compressed:
            if not silent:
                print(f'Decompressing segment {i}...')
            z = zlib.decompressobj()
            dat = z.decompress(dat)
        outf.write(dat)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", type=pathlib.Path)
    parser.add_argument("outdir", type=pathlib.Path)
    parser.add_argument("-keys", type=pathlib.Path, default="keys_external.py", required=False)
    args = parser.parse_args()

    keys.use_keys(args.keys)

    with open(args.filename, "rb") as inf:
        scedecrypt(inf, args.outdir)
