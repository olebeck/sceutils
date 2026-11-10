from __future__ import annotations

from unarzl import (
    ArlzBufferOverflowError,
    ArlzError,
    ArlzInvalidDataError,
    arzl_arm_filter,
    arzl_decode,
    arzl_decompress,
    unarzl,
)

from . import keys, module_info, scetypes, sceutils
from .axfs import AXFS
from .module_info import read_module_info
from .pup_fiction import (
    extract_bootimage,
    extract_pup,
    pup_decrypt_packages,
    pup_extract_files,
    slb2_decrypt,
    slb2_extract,
)
from .scedecrypt import scedecrypt
from .sceutils import get_key_type, get_segments, zrif_decode
from .self2elf import self2elf
from .selfinfo import read_self_info

__version__ = "0.1.0"

__all__ = [
    "AXFS",
    "ArlzError",
    "ArlzInvalidDataError",
    "ArlzBufferOverflowError",
    "arzl_decode",
    "arzl_decompress",
    "arzl_arm_filter",
    "extract_bootimage",
    "extract_pup",
    "get_key_type",
    "get_segments",
    "keys",
    "module_info",
    "pup_decrypt_packages",
    "pup_extract_files",
    "read_module_info",
    "read_self_info",
    "scetypes",
    "sceutils",
    "scedecrypt",
    "self2elf",
    "slb2_decrypt",
    "slb2_extract",
    "unarzl",
    "zrif_decode",
]
