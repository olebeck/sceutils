#!/usr/bin/python3

import argparse
import os
import pathlib
import sys
import zlib
import sceutils
from scetypes import SceHeader
from Crypto.Cipher import AES
from Crypto.Util import Counter
from importlib import import_module

from util import use_keys


def scedecrypt(inf, outdir, decompress=True, silent=False):
    sce = SceHeader(inf.read(SceHeader.Size))
    if not silent:
        print(sce)
    (sysver, selftype) = sceutils.get_key_type(inf, sce, silent)
    scesegs = sceutils.get_segments(inf, sce, sysver, selftype, silent=silent)
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

    use_keys(args.keys)

    with open(args.filename, "rb") as inf:
        scedecrypt(inf, args.outdir)
