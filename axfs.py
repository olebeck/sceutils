#!/usr/bin/env python3

import pathlib
from typing import IO, Literal, Optional
from dataclasses import dataclass
from io import BytesIO
import argparse
import tarfile
import struct
import zlib
import stat
import os

PAGE_SHIFT = 12


class ENodeTypes:
    XIP = 0
    Compressed = 1
    Byte_aligned = 2


def MAJOR(dev):
    return dev >> 8


def MINOR(dev):
    return dev & 0xff


@dataclass
class axfs_super_onmedia:
    magic: bytes        # 0x48A0E4CD
    signature: bytes    # Advanced XIP FS\x00
    digest: bytes       # sha1 digest for checking data integrity (sometimes 0x0)
    cblock_size: int    # maximum size of the block being compressed
    files: int          # number of inodes/files in fs
    size: int           # total image size in bytes
    blocks: bytes       # number of nodes in fs
    mmap_size: bytes    # size of the memory mapped part of image
    strings: int        # offset to strings region descriptor
    xip: int            # offset to xip region descriptor
    byte_aligned: int   # offset to the byte aligned region desc
    compressed: int     # offset to the compressed region desc
    node_type: int      # offset to node type region desc
    node_index: int     # offset to node index region desc
    cnode_offset: int   # offset to cnode offset region desc
    cnode_index: int    # offset to cnode index region desc
    banode_offset: int  # offset to banode offset region desc
    cblock_offset: int  # offset to cblock offset region desc
    inode_file_size: int    # offset to inode file size desc
    inode_name_offset: int  # offset to inode name region desc
    inode_num_entries: int  # offset to inode num_entries region desc
    inode_mode_index: int   # offset to inode mode_index  region desc
    inode_array_index: int  # offset to inode array_index region desc
    modes: int  # offset to mode mode region desc
    uids: int   # offset to uid index mode region desc
    gids: int   # offset to gid index mode region desc
    version_major: int
    version_minor: int
    version_sub: int
    compression_type: int  # Identifies type of compression used on FS
    timestamp: int  # UNIX time_t of filesystem build time


class axfs_region_desc_onmedia:
    fsoffset: int
    size: int
    compressed_size: int
    max_index: int
    table_byte_depth: int
    incore: int


class axfs_region(axfs_region_desc_onmedia):
    data: bytes

    def __init__(self, f: IO[bytes]) -> None:
        (
            self.fsoffset, self.size,
            self.compressed_size, self.max_index,
            self.table_byte_depth, self.incore
        ) = struct.unpack(">QQQQBB", f.read(34))
        f.seek(self.fsoffset, os.SEEK_SET)
        self.data = f.read(self.size)

    def axfs_bytetable_stitch(self, index: int) -> int:
        assert index < self.max_index
        output = 0
        split = self.size // self.table_byte_depth
        for i in range(self.table_byte_depth):
            output += self.data[index + i * split] << (8 * i)
        return output


def offsetBytes(data: bytes, start: int, length: int):
    return data[start:start + length]


def loadRegion(f: IO, offset: int) -> axfs_region:
    f.seek(offset, os.SEEK_SET)
    return axfs_region(f)


class AXFS:
    def __init__(self, f: IO[bytes]):
        self.superblock = axfs_super_onmedia(*struct.unpack('>I16s40sI22Q4BQ', f.read(252)))
        assert self.superblock.signature == b'Advanced XIP FS\x00'
        assert self.superblock.magic == 0x48A0E4CD
        self.xip = loadRegion(f, self.superblock.xip)
        self.strings = loadRegion(f, self.superblock.strings)
        self.compressed = loadRegion(f, self.superblock.compressed)
        self.byte_aligned = loadRegion(f, self.superblock.byte_aligned)
        self.node_type = loadRegion(f, self.superblock.node_type)
        self.node_index = loadRegion(f, self.superblock.node_index)
        self.cnode_offset = loadRegion(f, self.superblock.cnode_offset)
        self.cnode_index = loadRegion(f, self.superblock.cnode_index)
        self.banode_offset = loadRegion(f, self.superblock.banode_offset)
        self.cblock_offset = loadRegion(f, self.superblock.cblock_offset)
        self.inode_file_size = loadRegion(f, self.superblock.inode_file_size)
        self.inode_name_offset = loadRegion(f, self.superblock.inode_name_offset)
        self.inode_num_entries = loadRegion(f, self.superblock.inode_num_entries)
        self.inode_mode_index = loadRegion(f, self.superblock.inode_mode_index)
        self.inode_array_index = loadRegion(f, self.superblock.inode_array_index)
        self.modes = loadRegion(f, self.superblock.modes)
        self.uids = loadRegion(f, self.superblock.uids)
        self.gids = loadRegion(f, self.superblock.gids)
        f.seek(0)

    def list(self, node_id: int, folder="/"):
        num_files = self.getNumEntries(node_id)
        first = self.getArrayIndex(node_id)
        for i in range(first, first + num_files):
            name = self.getName(i)
            mode = self.getMode(i)
            size = " " * 9

            if stat.S_ISREG(mode):
                size = str(self.getFileSize(i)).rjust(9)
            if stat.S_ISLNK(mode):
                link_name = self.readFileData(i).decode("utf8")
                name += ' -> ' + link_name
            if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                st_rdev = self.getFileSize(i)
                size = f"{str(MAJOR(st_rdev)).rjust(3)} {str(MINOR(st_rdev)).rjust(3)}".rjust(9)

            print(f"{stat.filemode(mode)} {size} {folder + name}")

            if stat.S_ISDIR(mode):
                self.list(i, folder + name + "/")

    def toTar(self, node_id: int, tar: tarfile.TarFile, folder=""):
        num_files = self.getNumEntries(node_id)
        first = self.getArrayIndex(node_id)
        for i in range(first, first + num_files):
            name = self.getName(i)
            mode = self.getMode(i)

            file = tarfile.TarInfo()
            file.path = folder + name
            file.uid = self.getUid(i)
            file.gid = self.getGid(i)
            file.mode = mode
            file.mtime = self.superblock.timestamp
            data = None

            if stat.S_ISDIR(mode):
                file.type = tarfile.DIRTYPE
                self.toTar(i, tar, file.path + "/")

            elif stat.S_ISLNK(mode):
                link_name = self.readFileData(i).decode("utf8")
                file.type = tarfile.SYMTYPE
                file.linkname = link_name
            elif stat.S_ISREG(mode):
                file.type = tarfile.REGTYPE
                file.size = self.getFileSize(i)
                data = self.readFileData(i)

            elif stat.S_ISCHR(mode):
                file.type = tarfile.CHRTYPE
            elif stat.S_ISBLK(mode):
                file.type = tarfile.BLKTYPE

            elif stat.S_ISSOCK(mode) or stat.S_ISFIFO(mode):
                pass
            else:
                raise Exception("unkown filetype")

            if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                st_rdev = self.getFileSize(i)  # very weird to put that in filesize...
                file.devmajor, file.devminor = MAJOR(st_rdev), MINOR(st_rdev)

            tar.addfile(file, BytesIO(data))

    def getName(self, node_id: int) -> int:
        offset = self.inode_name_offset.axfs_bytetable_stitch(node_id)
        ret = self.strings.data[offset:]
        if len(ret):
            ret = ret[:ret.index(b"\00")]
        return ret.decode("utf8")

    def getFileSize(self, node_id: int) -> int:
        return self.inode_file_size.axfs_bytetable_stitch(node_id)

    def getMode(self, node_id: int) -> int:
        mode_index = self.inode_mode_index.axfs_bytetable_stitch(node_id)
        return self.modes.axfs_bytetable_stitch(mode_index)

    def getUid(self, node_id: int) -> int:
        mode_index = self.inode_mode_index.axfs_bytetable_stitch(node_id)
        return self.uids.axfs_bytetable_stitch(mode_index)

    def getGid(self, node_id: int) -> int:
        mode_index = self.inode_mode_index.axfs_bytetable_stitch(node_id)
        return self.gids.axfs_bytetable_stitch(mode_index)

    def getNumEntries(self, node_id: int) -> int:
        return self.inode_num_entries.axfs_bytetable_stitch(node_id)

    def getArrayIndex(self, node_id: int) -> int:
        return self.inode_array_index.axfs_bytetable_stitch(node_id)

    def getNodeIndex(self, node_id: int) -> int:
        return self.node_index.axfs_bytetable_stitch(node_id)

    def getNodeType(self, node_id: int) -> int:
        return self.node_type.axfs_bytetable_stitch(node_id)

    def getByteAlignedOffset(self, node_id: int) -> int:
        return self.banode_offset.axfs_bytetable_stitch(node_id)

    def readFileData(self, node_id: int) -> bytes:
        file_size = self.getFileSize(node_id)
        array_index = self.getArrayIndex(node_id)

        length = file_size
        offset = 0
        out = bytearray()

        while length > 0:
            node_index = self.getNodeIndex(array_index)
            node_type = self.getNodeType(array_index)

            if node_type == ENodeTypes.Byte_aligned:
                src_offset = self.getByteAlignedOffset(node_index)
                block_size = min(0x1 << PAGE_SHIFT, file_size)
                out[offset:] = offsetBytes(self.byte_aligned.data, src_offset, block_size)
                length -= block_size
                offset += block_size

            elif node_type == ENodeTypes.XIP:
                out[offset:] = offsetBytes(self.xip.data, node_index << PAGE_SHIFT, 1 << PAGE_SHIFT)
                offset += 1 << PAGE_SHIFT
                length -= 1 << PAGE_SHIFT

            elif node_type == ENodeTypes.Compressed:
                cnode_offset = self.cnode_offset.axfs_bytetable_stitch(node_index)
                cnode_index = self.cnode_index.axfs_bytetable_stitch(node_index)
                src_offset = self.cblock_offset.axfs_bytetable_stitch(cnode_index)

                block_length = self.cblock_offset.axfs_bytetable_stitch(cnode_index + 1) - src_offset
                data = zlib.decompress(offsetBytes(self.compressed.data, src_offset, block_length))
                block_length = min(self.superblock.cblock_size - cnode_offset, length)
                out[offset:] = offsetBytes(data, cnode_offset, block_length)
                length -= block_length
                offset += block_length
            else:
                raise Exception("invalid nodeType")

            array_index += 1

        return bytes(out)


def main():
    class _args:
        command: Literal["list", "tar"]
        inputfile: pathlib.Path
        output: Optional[pathlib.Path]

    parser = argparse.ArgumentParser()
    parser.add_argument("command", type=str, choices=["list", "tar"])
    parser.add_argument("inputfile", help="input axfs image", type=pathlib.Path)
    parser.add_argument("output", help="output file name for tar", type=pathlib.Path, required=False)  # optional
    args: _args = parser.parse_args()

    inputfile = args.inputfile.as_posix()
    output = args.output.as_posix() if args.output else None

    with open(inputfile, "rb") as f:
        fs = AXFS(f)

    if args.command == "list":
        fs.list(0)
        return
    elif args.command == "tar":
        if not output:
            output = inputfile + ".tar"
        tar = tarfile.open(output, mode="w")
        fs.toTar(0, tar)
        tar.close()
        return


if __name__ == "__main__":
    main()
