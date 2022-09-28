import os
import sys
import pup_fiction


def main(argv):
    " main "
    if len(argv) != 2:
        print("Usage: unpack_bootimage_new.py bootimage.skprx output-dir/")
        return
    
    out_dir = os.path.basename(argv[1])
    os.makedirs(out_dir, exist_ok=True)
    pup_fiction.extract_bootimage(argv[1], out_dir)


if __name__ == "__main__":
    main(sys.argv[1:])
