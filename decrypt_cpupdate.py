from typing import IO
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import tarfile
import struct
import os
from io import BytesIO

import axfs


CPUP_MAGIC = 0x43705570
TRF_MAGIC = 0x23642745

CpUp_Public = (0xA7CCAE0F501188527BF3DACCA3E231C8D8701E7B91927390701DE5E7A96327DAD87167A8F01368ADDFE490E325A290533697058FBA775766698010AFD8FD7A3FFD265E0A52FE04928BCE8B4302F4C70FFAC3C9397FD24B106271E57BDA20D2D702298F6F990ECF9B0FE04FF6CCEE170B555304232012D78E6019DAB29763829E6AF5ADA802204FA551631179CBFE6164732662E8576741949BB136456C11DE355F487211D230267DC05E699A2652AD5C6D74B0568326F4F2F5B86AD956E94404D3A65928F4EA2189567CE9989911B04808517F4C76A8B25DF1D6ABBE8595C469BFD7E870C4F00A89610C2C9B79F625A42CA2B4C6B8D37E62CE9EC61A856FD32F, 0x10001)
FsImage_Public = (0xA9697F9D9343CADE68E04F9E356E6AB6BBC7DE36A4D81B98A83BC12BE3F6DF96ED7A64389456ACA933BEBFBA4FFEF05CF45F2F886F434FBBC3A01348533070C0B7D5E9C21EFE53E95A6019DB51C12C6BAFEB94E992287963448E59606384B99F3FF3E5EB6AA08BF32A4DBA7A312520CEC2B69BB20A6D0640B117170AA2DDA1FB590AEE7ADFC4E80DFCF27FA55DDEC92C07922FDD05AB1618DCB727AA6FF70027A9410BC845E50EAFD46C0FD92FF500672DE56489C669B0AA481FFD75E99E21A8DC2F9F9E87957B46BBF63FB7DDBE8B8CA861BA349A62458E855EE78C3DD6791F92E76422144E51295B1337E15C126DF6FA0C29321BC1D7C00E3C19EEF3A3E7A5, 0x10001)


def decrypt_unpack_CpUp(filename: str, dst: str) -> tarfile.TarFile:
    os.mkdir(dst)
    dst_name = os.path.join(dst, os.path.basename(filename) + ".tar.gz")

    with open(filename, "rb") as fin:
        data = decrypt(fin)
    with open(dst_name, "wb") as fout:
        fout.write(data)
    try:
        tar = tarfile.open(fileobj=BytesIO(data), mode="r:gz")
    except tarfile.ReadError:
        print("CpUp Extraction failed likely wrong keys")
        return None
    return tar


def extract_CpUp(tar: tarfile.TarFile, dst: str):
    os.mkdir(dst)

    # need to skip some data
    fsimage0 = tar.extractfile("./fsimage0.trf")
    fsimage0.seek(0x120)
    fsimage0 = fsimage0.read()
    open(os.path.join(dst, "fsimage0.img"), "wb").write(fsimage0)
    # read axfs for fsimage0
    axfs_fsimage0 = axfs.axfs(BytesIO(fsimage0))
    tar_fsimage0 = tarfile.open(os.path.join(dst, "fsimage0.tar"), mode="w")
    axfs_fsimage0.toTar(0, tar_fsimage0)
    tar_fsimage0.close()

    # decrypt fsimage1
    fsimage1 = tar.extractfile("./fsimage1.trf")
    fsimage1 = decrypt(fsimage1)
    open(os.path.join(dst, "fsimage1.img"), "wb").write(fsimage1)
    # read axfs for fsimage1
    axfs_fsimage1 = axfs.axfs(BytesIO(fsimage1))
    tar_fsimage1 = tarfile.open(os.path.join(dst, "fsimage1.tar"), mode="w")
    axfs_fsimage1.toTar(0, tar_fsimage1)
    tar_fsimage1.close()

    # decrypt vmlinux image
    vmlinux = tar.extractfile("./vmlinux.trf")
    vmlinux = decrypt(vmlinux)
    open(os.path.join(dst, "vmlinux.img"), "wb").write(vmlinux)


def decrypt(f: IO[bytes], Silent=False):
    Encrypted = True

    Magic, = struct.unpack("<I", f.read(4))
    if Magic == CPUP_MAGIC:
        (
            cp_version,
            fmt_version,
            size,
            data_offset,
            data_size
        ) = struct.unpack("<I8xIIII", f.read(28))
        rsa = RSA.construct(CpUp_Public)

        Magic_str = int.to_bytes(Magic, 4, "big").decode("ascii")
        cp_ver_str = '.'.join([str(num) for num in int.to_bytes(cp_version, 4, "big")])
        fmt_ver_str = '.'.join([str(num) for num in int.to_bytes(fmt_version, 4, "big")])
        if not Silent:
            print("CpUp Decrypt")
            print(f"magic       : {Magic_str}\t\t(0x{Magic:08X})")
            print(f"cp version  : {cp_ver_str}\t\t(0x{cp_version:08X})")
            print(f"fmt version : {fmt_ver_str}\t\t(0x{fmt_version:08X})")
    elif Magic == TRF_MAGIC:
        (
            version,
            data_size,
            data_offset,
            size,
        ) = struct.unpack("<IIII", f.read(16))
        rsa = RSA.construct(FsImage_Public)
        if version == 0x1010100:
            Encrypted = False

        ver_str = '.'.join([str(num) for num in int.to_bytes(version, 4, "big")])
        if not Silent:
            print("Trf Decrypt")
            print(f"magic       : {Magic:08X}")
            print(f"version     : {ver_str}\t\t(0x{version:08X})")
    else:
        raise RuntimeError("Invalid CpUp or trf")

    if not Silent:
        print(f"size        : {size}\t\t(0x{size:08X})")
        print(f"data offset : {data_offset}\t\t(0x{data_offset:08X})")
        print(f"data size   : {data_size}\t\t(0x{data_size:08X})")

    # get key and iv from sig
    f.seek(-0x100, 2)
    key_data = f.read()
    sig = rsa._encrypt(int.from_bytes(key_data, "big"))
    sig = int.to_bytes(sig, 0x100, "big")[-0x34:]
    (iv, key, sha1_hash) = struct.unpack("16s16s20s", sig)

    # read file data and decrypt
    f.seek(data_offset, os.SEEK_SET)
    data = f.read((size - data_offset) - 0x100)
    if Encrypted:
        aes_key = AES.new(key, AES.MODE_CBC, iv)
        data = aes_key.decrypt(data)

    print("-" * 80)
    return data[:data_size]
