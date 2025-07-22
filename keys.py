from typing import Literal
import os, sys, importlib
from scetypes import KeyStore

ENC_KEY: bytes
ENC_IV: bytes

XXX_KEY: bytes
XXX_IV: bytes

SCEWM_KEY: bytes
SCEWM_IV: bytes

SCEAS_KEY: bytes
SCEAS_IV: bytes

SCE_KEYS: KeyStore

def use_keys(name: Literal["keys_external.py", "keys_internal.py", "keys_proto.py"]):
    mod_name = os.path.basename(name).split(".")[0]
    dir_ = os.path.dirname(name)
    if dir_ not in sys.path:
        sys.path.append(os.path.dirname(name))
    mod = importlib.import_module(mod_name)
    globals().update(vars(mod))
