import importlib
import sys

MODULES = [
    "axfs",
    "emmc_extract",
    "extract_idstorage",
    "find_imported_by",
    "module_info",
    "pup_fiction",
    "pup_info",
    "scedecrypt",
    "self2elf",
    "selfinfo",
    "ud0_extract_pup",
    "unpack_bootimage_new",
    "unarzl",
]


def print_modules() -> None:
    print("usage: sceutils <module> [options]")
    print()
    print("modules:")
    for module in MODULES:
        print(f"  {module}")
    print()
    print("Use 'sceutils <module> --help' for module specific options.")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)

    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print_modules()
        return 0 if len(argv) >= 2 else 1

    module_name = argv[1]

    if module_name == "unarzl":
        from unarzl.__main__ import main as unarzl_main
        return unarzl_main(argv[2:])

    if module_name not in MODULES:
        print(f"Unknown module: {module_name}")
        print()
        print_modules()
        return 1

    sys.argv = argv[1:]
    module = importlib.import_module(f"sceutils.{module_name}")
    result = module.main(sys.argv)
    return result if isinstance(result, int) else 0


if __name__ == "__main__":
    raise SystemExit(main())
