#!/bin/python3
import sys, os
sys.path.append(os.path.dirname(__file__)+"/src")

from sceutils.find_imported_by import main
if __name__ == '__main__':
    if sys.argv[0].endswith('.exe'):
        sys.argv[0] = sys.argv[0][:-4]
    sys.exit(main())
