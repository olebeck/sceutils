#!/bin/python3
import yaml
import glob
import sys, os
sys.path.append(os.path.dirname(__file__)+"/src")
import argparse
import json

from sceutils import module_info

def load_nids():
    nids = {}
    for path in glob.glob("vita-headers/db/360/**/*.yml", recursive=True):
        with open(path, "rb") as f:
            data = yaml.load(f, yaml.SafeLoader)
        for module_name, module in data["modules"].items():
            for library_name, library in module["libraries"].items():
                for name, nid in library.get("functions", {}).items():
                    nids[int(nid)] = {
                        "library_nid": library["nid"],
                        "name": name
                    }
                for name, nid in library.get("variables", {}).items():
                    nids[int(nid)] = {
                        "library_nid": library["nid"],
                        "name": name
                    }
    return nids


def main(argv = sys.argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--folder", type=str, required=True)
    args = parser.parse_args(argv[1:])

    modules = {}
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
            modules[module.module_name] = {
                "path": relpath,
                "imports": [imp.__dict__ for imp in imports],
                "exports": [imp.__dict__ for imp in exports]
            }

    nids = load_nids()

    with open("index.json", "w") as f:
        json.dump({
            "modules": modules,
            "nids": nids
        }, f, indent=2)

if __name__ == "__main__":
    main()
