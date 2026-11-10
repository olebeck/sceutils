#!/usr/bin/env python3

import os
import sys

from .util import u16


def main(argv = sys.argv):
    if len(argv) != 3:
        print(f"Usage: {argv[0]} idstorage-partition.bin output-directory/")
        sys.exit(1)

    with open(argv[1], "rb") as fin:
        data = fin.read()

    index_table = data[0:512]
    for index in range(256):
        leaf = u16(index_table, index * 2)
        if leaf not in [0xFFFF, 0xFFF5]:
            with open(os.path.join(argv[2], f"leaf_{leaf:04X}.bin"), "wb") as fout:
                fout.write(data[512 * index:512 * (index + 1)])
            print(f"Leaf 0x{leaf:04X}")


if __name__ == "__main__":
    main()
