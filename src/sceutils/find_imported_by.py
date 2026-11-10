# --folder = path to /fs_dec/
# --nid = the function nid you are search for

import argparse
import os
import sys

from sceutils import module_info


def main(argv = sys.argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--folder", type=str, required=True)
    parser.add_argument("-n", "--nid", type=str, required=True)
    args = parser.parse_args(argv[1:])
    nid = int(args.nid, 0)
    
    for (root, folders, files) in os.walk(args.folder):
        for file in files:
            if not file.split(".")[-1] == "elf":
                continue
            path = os.path.join(root, file)
            relpath = os.path.relpath(path, args.folder)
            with open(path, "rb") as f:
                info = module_info.read_module_info(f)
                if info is None:
                    continue
                module, imports, exports = info
            for imp in imports:
                if nid in imp.functions:
                    print(relpath)
                    break

if __name__ == "__main__":
    main()
