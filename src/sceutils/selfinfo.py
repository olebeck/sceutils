#!/usr/bin/env python3
"""Print every header and metadata structure contained in a SELF file."""

from __future__ import annotations

import argparse
import io
import pathlib
import sys
from typing import IO, Any

from . import keys, module_info, sceutils
from .scetypes import (
    AppInfoHeader,
    ControlType,
    ElfHeader,
    ElfPhdr,
    ElfShdr,
    SCE_MAGIC,
    SceControlInfo,
    SceControlInfoDigest256,
    SceControlInfoDRM,
    SceHeader,
    SceType,
    SceVersionInfo,
    SegmentInfo,
    SelfHeader,
    SpkgHeader,
    SrvkHeader,
)
from .self2elf import self2elf


def _read_control_infos(inf: IO[bytes], self_hdr: SelfHeader,
                        silent: bool) -> tuple[list[Any], int]:
    infos: list[Any] = []
    npdrm_type = 0
    if not self_hdr.controlinfo_offset:
        return infos, npdrm_type

    inf.seek(self_hdr.controlinfo_offset)
    hdr = None
    while hdr is None or hdr.more:
        hdr = SceControlInfo.unpack(inf)
        if not silent:
            print(hdr)
        infos.append(hdr)

        payload_size = max(hdr.size - SceControlInfo._size, 0)
        if hdr.control_type == ControlType.DIGEST_SHA256:
            digest = SceControlInfoDigest256.unpack(inf)
            infos.append(digest)
            if not silent:
                print(digest)
        elif hdr.control_type == ControlType.NPDRM_VITA:
            drm = SceControlInfoDRM.unpack(inf)
            npdrm_type = drm.npdrm_type
            infos.append(drm)
            if not silent:
                print(drm)
        else:
            if payload_size:
                infos.append(inf.read(payload_size))

    return infos, npdrm_type


def read_self_info(inf: IO[bytes], *, decrypt: bool = True,
                   klictxt: bytes = b"\0" * 16,
                   include_module_info: bool = True,
                   silent: bool = False) -> dict[str, Any]:
    """Parse a SELF/SRVK/SPKG file and return all discovered information.

    ``inf`` must be a seekable binary file object.  When ``decrypt`` is true
    the encrypted metadata is parsed as well (this requires keys to have been
    loaded with :func:`sceutils.keys.use_keys`).
    """
    info: dict[str, Any] = {}

    inf.seek(0)
    magic = inf.read(4)
    if int.from_bytes(magic, "little") != SCE_MAGIC:
        raise ValueError("not a SCE file (invalid magic)")
    inf.seek(0)
    sce = SceHeader.unpack(inf)
    info["sce"] = sce
    if not silent:
        print(sce)

    if sce.sce_type == SceType.SELF:
        inf.seek(sce._size)
        self_hdr = SelfHeader.unpack(inf)
        info["self"] = self_hdr
        if not silent:
            print(self_hdr)

        inf.seek(self_hdr.appinfo_offset)
        appinfo = AppInfoHeader.unpack(inf)
        info["appinfo"] = appinfo
        if not silent:
            print(appinfo)

        if self_hdr.sceversion_offset:
            inf.seek(self_hdr.sceversion_offset)
            verinfo = SceVersionInfo.unpack(inf)
            info["version_info"] = verinfo
            if not silent:
                print(verinfo)

        control_infos, npdrm_type = _read_control_infos(inf, self_hdr, silent)
        info["control_infos"] = control_infos
        info["npdrm_type"] = npdrm_type

        inf.seek(self_hdr.elf_offset)
        elf_hdr = ElfHeader.unpack(inf)
        info["elf_header"] = elf_hdr
        if not silent:
            print(elf_hdr)

        phdrs = []
        inf.seek(self_hdr.phdr_offset)
        for _ in range(elf_hdr.e_phnum):
            phdr = ElfPhdr.unpack(inf)
            phdrs.append(phdr)
            if not silent:
                print(phdr)
        info["phdrs"] = phdrs

        shdrs = []
        inf.seek(self_hdr.shdr_offset)
        for _ in range(elf_hdr.e_shnum):
            shdr = ElfShdr.unpack(inf)
            shdrs.append(shdr)
            if not silent:
                print(shdr)
        info["shdrs"] = shdrs

        segment_infos = []
        inf.seek(self_hdr.segment_info_offset)
        for _ in range(elf_hdr.e_phnum):
            segment_info = SegmentInfo.unpack(inf)
            segment_infos.append(segment_info)
            if not silent:
                print(segment_info)
        info["segment_infos"] = segment_infos

        if decrypt:
            try:
                segments = sceutils.get_segments(
                    inf, sce, appinfo.sys_version, appinfo.self_type,
                    npdrm_type, klictxt, silent)
                info["segments"] = segments
            except Exception as exc:  # noqa: BLE001 - metadata may be unavailable
                info["segments_error"] = exc
                if not silent:
                    print(f"Could not read encrypted metadata: {exc}")

        if include_module_info and decrypt:
            try:
                elf = io.BytesIO()
                inf.seek(0)
                self2elf(inf, elf, klictxt, silent=True)
                elf.seek(0)
                module = module_info.read_module_info(elf)
                info["module"] = module
                if module is not None and not silent:
                    _print_module_info(module)
            except Exception as exc:  # noqa: BLE001 - not all files are modules
                info["module_error"] = exc
                if not silent:
                    print(f"Module info unavailable: {exc}")

    elif sce.sce_type == SceType.SRVK:
        inf.seek(sce.header_length)
        srvk = SrvkHeader.unpack(inf)
        info["srvk"] = srvk
        if not silent:
            print(srvk)

    elif sce.sce_type == SceType.SPKG:
        inf.seek(sce.header_length)
        spkg = SpkgHeader.unpack(inf)
        info["spkg"] = spkg
        if not silent:
            print(spkg)

    else:
        if not silent:
            print(f"Unknown SCE type: {sce.sce_type}")

    return info


def _print_module_info(module) -> None:
    module_info_hdr, imports, exports = module
    print("Module Info:")
    print(f" module_name:      {module_info_hdr.module_name}")
    print(f" module_nid:       0x{module_info_hdr.module_nid:08X}")
    print(f" version:          {module_info_hdr.version}")
    print(f" attributes:       0x{module_info_hdr.attributes:04X}")
    print(f" imports ({len(imports)}):")
    for imp in imports:
        print(f"  {imp.name} (0x{imp.nid:08X}): "
              f"{len(imp.functions)} functions, {len(imp.variables)} variables")
    print(f" exports ({len(exports)}):")
    for exp in exports:
        print(f"  {exp.name} (0x{exp.nid:08X}): "
              f"{len(exp.functions)} functions, {len(exp.variables)} variables")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    parser = argparse.ArgumentParser(
        prog="sceutils selfinfo",
        description="Print all information from a SELF/SRVK/SPKG file.",
    )
    parser.add_argument("filename", type=pathlib.Path)
    parser.add_argument(
        "-K", "--keys", type=str, default="keys_external.py",
        help="keys module to load (default: keys_external.py)",
    )
    parser.add_argument(
        "--no-decrypt", action="store_true",
        help="do not decrypt/parse encrypted metadata",
    )
    parser.add_argument(
        "--no-module-info", action="store_true",
        help="do not reconstruct the ELF to print module imports/exports",
    )
    args = parser.parse_args(argv[1:])

    keys.use_keys(args.keys)

    try:
        with open(args.filename, "rb") as inf:
            read_self_info(
                inf,
                decrypt=not args.no_decrypt,
                include_module_info=not args.no_module_info,
                silent=False,
            )
    except (OSError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
