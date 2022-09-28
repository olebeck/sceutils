#!/usr/bin/env python3

import argparse
import pathlib
import struct
from collections import defaultdict
import os
import glob
import subprocess
import sys
from typing import Optional

from Crypto.Cipher import AES

from util import u8, u32, c_str, use_keys
from scedecrypt import scedecrypt
from self2elf import self2elf
from decrypt_cpupdate import decrypt_unpack_cpup, extract_cpup
import pup_info

unarzl_exe = os.path.join(os.path.dirname(os.path.realpath(__file__)), "unarzl", "unarzl")
if sys.platform == "win32":
    unarzl_exe += ".exe"
if not os.path.exists(unarzl_exe):
    print("Please cd to unarzl and type make")
    sys.exit(-1)

SCEUF_HEADER_SIZE = 0x80
SCEUF_FILEREC_SIZE = 0x20

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

partitions = ["os0", "vs0", "sa0", "pd0"]

g_typecount = defaultdict(int)



def make_filename(hdr, filetype):
    magic, version, flags, moffs, metaoffs = struct.unpack("<IIIIQ", hdr[0:24])
    if magic == 0x454353 and version == 3 and flags == 0x30040:
        meta = hdr[metaoffs:]
        t = u8(meta, 4)
        if t < 0x1C:
            name = f"{FSTYPE[t]}-{g_typecount[t]:02}.pkg"
            g_typecount[t] += 1
            return name
    return f"unknown-0x{filetype:x}.pkg"


def pup_extract_files(pup, output):
    with open(pup, "rb") as fin:
        header = pup_info.SCEUF.read(fin)
        if header.magic[0:5] != b"SCEUF":
            print("Invalid PUP")
            return -1
        header.print()

        for x in range(header.seg_num):
            fin.seek(SCEUF_HEADER_SIZE + x * SCEUF_FILEREC_SIZE)
            rec = fin.read(SCEUF_FILEREC_SIZE)
            filetype, offset, length, flags = struct.unpack("<QQQQ", rec)

            filename = pup_types.get(filetype)
            if not filename:
                fin.seek(offset)
                hdr = fin.read(0x1000)
                filename = make_filename(hdr, filetype)
            # print("filename {filename} type {filetype} offset {offset:x} length {length:x} flags {flags:x}")

            with open(os.path.join(output, filename), "wb") as fout:
                fin.seek(offset)
                fout.write(fin.read(length))
            print(f"- {filename}")
        print("-" * 80)


def join_files(mask: str, output: str):
    files = sorted(glob.glob(mask))
    if len(files) == 0:
        return
    with open(output, "wb") as fout:
        for filename in files:
            with open(filename, "rb") as fin:
                fout.write(fin.read())
            os.remove(filename)


def pup_decrypt_packages(src, dst):
    files = list(map(os.path.basename, glob.glob(os.path.join(src, "*.pkg"))))
    files.sort()

    for filename in files:
        filepath = os.path.join(src, filename)
        with open(filepath, "rb") as fin:
            try:
                scedecrypt(fin, dst, silent=True)
                print(f"Decrypted {filename}")
            except KeyError:
                print(f"[!] Couldn't decrypt {filename}")

    for filename in ["cui_setupper.self", "psp2swu.self"]:
        filepath = os.path.join(src, filename)
        with open(filepath, "rb") as fin:
            with open(os.path.join(dst, filename.replace(".self", ".elf")), "wb") as fout:
                try:
                    self2elf(fin, fout, silent=True, ignore_sysver=True)
                    print(f"Decrypted {filename}")
                except KeyError:
                    print(f"[!] Couldn't decrypt {filename}")

    for pkg in partitions:
        join_files(os.path.join(dst, f"{pkg}-*.pkg.seg02"), os.path.join(dst, f"{pkg}.bin"))

    print("-" * 80)


def slb2_extract(src, dst):
    with open(src, "rb") as fin:
        hdr = fin.read(0x200)
        magic, version, flags, file_count, total_blocks = struct.unpack("<IIIII", hdr[0:20])
        if magic != 0x32424C53:
            raise RuntimeError("Invalid SLB2 file")
        print(f"SLB2 version: {version}, flags: 0x{flags:X}, file_count: {file_count}, total_blocks: 0x{total_blocks:X}")

        for x in range(file_count):
            entry_start = 0x20 + x * 0x30
            entry = hdr[entry_start:entry_start + 0x30]
            filename = c_str(entry[0x10:])

            block_offset, filesize = struct.unpack("<II", entry[0:8])

            with open(os.path.join(dst, filename), "wb") as fout:
                fin.seek(block_offset * 0x200)
                fout.write(fin.read(filesize))
                print(f"- {filename}")

    print("-" * 80)


def enc_decrypt(src, dst):
    from keys import ENC_KEY, ENC_IV

    with open(src, "rb") as fin:
        data = fin.read()

    magic, offset, plaintext_size, unk, data_size = struct.unpack("<IIIII", data[0:20])

    if magic != 0x64B2C8E5:
        raise RuntimeError("enc format invalid")

    aes = AES.new(ENC_KEY, AES.MODE_CBC, ENC_IV)
    data = data[offset:offset + data_size]
    with open(dst, "wb") as fout:
        fout.write(aes.decrypt(data))


def decrypt_scewm(src, dst):
    from keys import SCEWM_KEY, SCEWM_IV
    aes = AES.new(SCEWM_KEY, AES.MODE_CBC, SCEWM_IV)

    with open(src, "rb") as fin:
        data = fin.read()[0x20:]

    with open(os.path.join(dst, os.path.basename(src)), "wb") as fout:
        dec = aes.decrypt(data)
        fout.write(dec[0x100:-0x100])


def decrypt_sceas(src, dst):
    if not os.path.exists(src):
        return
    with open(src, "rb") as fin:
        fin.seek(0x20)
        data = fin.read()

    from keys import SCEAS_KEY, SCEAS_IV
    aes = AES.new(SCEAS_KEY, AES.MODE_CBC, SCEAS_IV)
    with open(os.path.join(dst, os.path.basename(src)), "wb") as fout:
        fout.write(aes.decrypt(data))
    print(f"Decrypted: {os.path.basename(src)}")


def slb2_decrypt(src, dst):
    for filename in ["second_loader.enc", "secure_kernel.enc"]:
        dst_filename = filename.replace(".enc", ".bin")
        src_path = os.path.join(src, filename)
        if not os.path.exists(src_path):
            print(f"couldnt find {filename}")
            continue
        enc_decrypt(src_path, os.path.join(dst, dst_filename))
        print(f"Decrypted {filename} to {dst_filename}")

    for filename in ["kernel_boot_loader.self", "prog_rvk.srvk"]:
        filepath = os.path.join(src, filename)
        if not os.path.exists(filepath):
            print(f"couldnt find {filename}")
            continue
        with open(filepath, "rb") as fin:
            scedecrypt(fin, dst, silent=True)
        print(f"Decrypted {filename}")

    for filename in ["kprx_auth_sm.self"]:
        dst_filename = filename.replace(".self", ".elf")
        filepath = os.path.join(src, filename)
        if not os.path.exists(filepath):
            print(f"couldnt find {filename}")
            continue

        print(f"self2elf {filename}")
        with open(filepath, "rb") as fin:
            with open(os.path.join(dst, dst_filename), "wb") as fout:
                self2elf(fin, fout, silent=True)

    # hacky fix for pups without nsbl
    nsbl_path = os.path.join(dst, "kernel_boot_loader.self.seg03")
    if os.path.exists(nsbl_path):
        print("unarzl nsbl.bin")
        subprocess.call([unarzl_exe, nsbl_path, os.path.join(dst, "nsbl.bin")])
    else:
        print("couldnt find kernel_boot_loader.self.seg03")
    print("-" * 80)


def extract_fs(output):
    fs_output = os.path.join(output, "fs")
    os.mkdir(fs_output)

    for partition in partitions:
        partition_in = os.path.join(output, "PUP_dec", f"{partition}.bin")
        if not os.path.exists(partition_in):
            continue
        print(f"Extract {partition}")
        partition_out = os.path.join(fs_output, partition)
        os.mkdir(partition_out)
        subprocess.call(["7z", "x", partition_in, f"-o{partition_out}"], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'))

    vs0_tarpatch = os.path.join(output, "fs", "vs0_tarpatch")
    for filename in glob.glob(os.path.join(output, "PUP_dec", "vs0_tarpatch-*.pkg.seg02")):
        print(f"tarpatch {os.path.basename(filename)}")
        subprocess.call(["7z", "x", filename, f"-o{vs0_tarpatch}"], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'))

    print("-" * 80)


def mkdir_p(path):
    os.makedirs(path, exist_ok=True)


def decrypt_selfs(in_dir, out_dir, blacklist=None):
    if not blacklist:
        blacklist = []

    for root, dirs, files in os.walk(in_dir):
        for filename in files:
            name, ext = os.path.splitext(filename)
            if (ext in [".self", ".skprx", ".suprx"] or filename == "eboot.bin") and filename not in blacklist:
                relpath = os.path.relpath(root, in_dir)
                mkdir_p(os.path.join(out_dir, relpath))

                try:
                    with open(os.path.join(root, filename), "rb") as fin:
                        with open(os.path.join(out_dir, relpath, f"{name}.elf"), "wb") as fout:
                            self2elf(fin, fout, silent=True)
                    print(f"self2elf {filename}")
                except KeyError:
                    print(f"[!] no key {filename}")


def decrypt_fs(output):
    for partition in partitions + ["vs0_tarpatch"]:
        part_in = os.path.join(output, "fs", partition)
        part_out = os.path.join(output, "fs_dec", partition)
        decrypt_selfs(part_in, part_out)
    print("-" * 80)


def decrypt_os0(output):
    os0_in = os.path.join(output, "fs", "os0")
    os0_out = os.path.join(output, "fs_dec", "os0")

    configs = ["psp2config_dolce.skprx", "psp2config_vita.skprx", "psp2config.skprx"]

    for filename in configs:
        in_path = os.path.join(os0_in, filename)
        if os.path.exists(in_path):
            print(f"Decrypt {filename}")
            with open(in_path, "rb") as fin:
                scedecrypt(fin, os0_out, silent=True)
    print("-" * 80)


def decrypt_cpup(pup_dst, output):
    CpUp = glob.glob(os.path.join(pup_dst, "*.CpUp"))
    seg = glob.glob(os.path.join(output, "devkit_cp-*.pkg.seg02"))
    for path in CpUp + seg:
        output_name = os.path.splitext(os.path.basename(path))[0]
        output_path = os.path.join(output, output_name)

        print(f"Decrypting {output_name}")
        print("-" * 80)

        tar = decrypt_unpack_cpup(path, output_path)
        if not tar:
            continue
        try:
            dst = os.path.join(output_path, "dec")
            extract_cpup(tar, dst)
        except Exception as e:
            print("Exception while extracting fsimages", e)


def extract_bootimage(filename: str, output: str):
    with open(filename, "rb") as f:
        data = f.read()

    data = data[data.find(b"SceKernelBootimage") - 4:]
    base_va = 0x81000000
    off = u32(data, 0xCC) - base_va
    num = u32(data, off)

    for x in range(num):
        entry_off = off + 8 + 12 * x

        name_off = u32(data, entry_off) - base_va
        name = c_str(data[name_off:name_off + 0x100])
        basename = name[name.rfind("/") + 1:]
        start = u32(data, entry_off + 4) - base_va
        size = u32(data, entry_off + 8)

        print(f"Writing {name}...")
        mod = data[start:start + size]
        with open(os.path.join(output, basename), "wb") as fout:
            fout.write(mod)


def extract_pup(pup, output):
    global g_typecount # reset every run
    g_typecount = defaultdict(int)
    if os.path.exists(output):
        print(f"{output} already exists, remove it first")
        return

    print(f"Extracting {pup} to {output}")

    os.mkdir(output)

    pup_dst = os.path.join(output, "PUP")
    os.mkdir(pup_dst)
    pup_extract_files(pup, pup_dst)

    pup_dec = os.path.join(output, "PUP_dec")
    os.mkdir(pup_dec)
    pup_decrypt_packages(pup_dst, pup_dec)

    decrypt_scewm(os.path.join(pup_dst, "package_scewm.wm"), pup_dec)
    decrypt_sceas(os.path.join(pup_dst, "package_sceas.as"), pup_dec)

    decrypt_cpup(pup_dst, pup_dec)

    slb2_path = os.path.join(pup_dec, "boot_slb2-00.pkg.seg02")
    if os.path.exists(slb2_path):
        slb2_dst = os.path.join(output, "SLB2")
        os.mkdir(slb2_dst)
        slb2_extract(slb2_path, slb2_dst)

        slb2_dec = os.path.join(output, "SLB2_dec")
        os.mkdir(slb2_dec)
        slb2_decrypt(slb2_dst, slb2_dec)
    else:
        print("couldnt find boot_slb2-00.pkg.seg02")

    extract_fs(output)

    kd_folder = output+"/fs_dec/os0/kd"
    extract_bootimage(kd_folder+"/bootimage.elf", kd_folder+"/bootimage")

    os.mkdir(os.path.join(output, "fs_dec"))
    decrypt_fs(output)
    decrypt_os0(output)


def main(args):
    class _args:
        PUP: pathlib.Path
        output: pathlib.Path
        keys: Optional[pathlib.Path]

    parser = argparse.ArgumentParser()
    parser.add_argument("PUP", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("-keys", type=pathlib.Path, default=pathlib.Path("./keys_external.py"), required=False)
    args: _args = parser.parse_args(args)

    use_keys(args.keys.as_posix())
    extract_pup(args.PUP.as_posix(), args.output.as_posix())


if __name__ == "__main__":
    main(sys.argv[1:])
