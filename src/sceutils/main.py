import sys
import importlib

modules = ["axfs", "emmc_extract", "extract_idstorage", "find_imported_by", "module_info", "pup_fiction", "pup_info", "scedecrypt", "self2elf", "ud0_extract_pup", "unpack_bootimage_new"]

def print_modules():
    print("usage: sceutils [module] {options}")
    print("modules:")
    for module in modules:
        print(f"  {module}")

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in modules:
        print_modules()
        sys.exit(1)
    module_name = sys.argv[1]
    sys.argv = sys.argv[1:]
    module = importlib.import_module(f"sceutils.{module_name}", )
    module.main()

if __name__ == "__main__":
    main()
