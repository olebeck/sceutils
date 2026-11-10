import argparse
import sys

from .arzl import unarzl


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="unarzl",
        description="Decompress an ARZL-compressed PlayStation Vita segment.",
    )
    parser.add_argument("input", help="input file (or - for stdin)")
    parser.add_argument("output", help="output file")
    args = parser.parse_args(argv)

    if args.input == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(args.input, "rb") as f:
            data = f.read()

    output = unarzl(data)
    with open(args.output, "wb") as f:
        f.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
