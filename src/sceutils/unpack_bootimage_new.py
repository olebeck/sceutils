import os
import sys

from sceutils import pup_fiction


def main(argv = sys.argv):
    if len(argv) != 3:
        print(f"Usage: {argv[0]} bootimage.skprx output-dir/")
        sys.exit(1)
    
    filename = argv[1]
    out_dir = argv[2]
    os.makedirs(out_dir, exist_ok=True)
    pup_fiction.extract_bootimage(filename, out_dir)


if __name__ == "__main__":
    main()
