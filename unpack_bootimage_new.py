import os
import sys
if __name__ == "__main__":
    sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import os
import sys
import sceutils.pup_fiction as pup_fiction


def main(argv):
    " main "
    if len(argv) != 2:
        print("Usage: unpack_bootimage_new.py bootimage.skprx output-dir/")
        return
    
    out_dir = argv[1]
    os.makedirs(out_dir, exist_ok=True)
    pup_fiction.extract_bootimage(argv[0], out_dir)


if __name__ == "__main__":
    main(sys.argv[1:])
