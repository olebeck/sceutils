import binascii
import importlib
import os
import sys
from collections import defaultdict
from typing import Literal, NamedTuple

from .scetypes import SelfType

ENC_KEY: bytes
ENC_IV: bytes

XXX_KEY: bytes
XXX_IV: bytes

SCEWM_KEY: bytes
SCEWM_IV: bytes

SCEAS_KEY: bytes
SCEAS_IV: bytes

SCE_KEYS: "KeyStore"

class KeyEntry(NamedTuple):
    minver: int
    maxver: int
    keyrev: int
    key: bytes
    iv: bytes

class KeyStore:
    def __init__(self):
        self._store = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

    def register(self, keytype, scetype, keyrev, key, iv, minver=0, maxver=0xffffffffffffffff, selftype=SelfType.NONE):
        self._store[keytype][scetype][selftype].append(KeyEntry(minver, maxver, keyrev, binascii.a2b_hex(key), binascii.a2b_hex(iv)))

    def get(self, keytype, scetype, sysver=-1, keyrev=-1, selftype=SelfType.NONE):
        if keytype not in self._store:
            raise KeyError("Cannot find any keys for this key type")
        if scetype not in self._store[keytype]:
            raise KeyError("Cannot find any keys for this SCE type")
        if selftype not in self._store[keytype][scetype]:
            raise KeyError("Cannot find any keys for this SELF type")
        for item in self._store[keytype][scetype][selftype]:
            if (sysver < 0 or (sysver >= item.minver and sysver <= item.maxver)) and (keyrev < 0 or keyrev == item.keyrev):
                return (item.key, item.iv)
        print(f"{keytype=} {scetype=} {sysver=:x} {keyrev=} {selftype}")
        raise KeyError("Cannot find key/iv for this SCE file")

def use_keys(name: Literal["keys_external.py", "keys_internal.py", "keys_proto.py"] | str):
    mod_name = os.path.basename(name).split(".")[0]
    dir_ = os.path.dirname(name)
    if dir_ not in sys.path:
        sys.path.append(dir_)
    mod = importlib.import_module("sceutils."+mod_name)
    globals().update(vars(mod))
