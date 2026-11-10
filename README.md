sceutils
========

Utilities for working with PlayStation Vita SCE / SELF / PUP files.

Requirements
------------

* Python 3.11+
* pycryptodomex

Installation
------------

```sh
pip install .
```

Usage
-----

### As a command line tool

```sh
sceutils --help
sceutils selfinfo file.self
sceutils self2elf -i eboot.bin -o eboot.elf -K keys_external.py
sceutils pup_fiction PSP2UPDATE.pup output keys_external.py
```

The ARZL helper is also available directly:

```sh
unarzl kernel_boot_loader.self.seg03 nsbl.bin
```

### As a library

```python
from sceutils import self2elf, read_self_info, scedecrypt, unarzl, keys

keys.use_keys("keys_external.py")

with open("eboot.bin", "rb") as inf, open("eboot.elf", "wb") as outf:
    self2elf(inf, outf)

with open("eboot.bin", "rb") as inf:
    info = read_self_info(inf)

with open("kernel_boot_loader.self.seg03", "rb") as f:
    nsbl = unarzl(f.read())
```

Modules
-------

pup_fiction
-----------
### usage:
* `sceutils pup_fiction PUP_filename output_folder keys_file`

### examples:
* `sceutils pup_fiction PSP2UPDATE.pup 368 keys_external.py`

---

self2elf
--------
### usage:
* `sceutils self2elf -i [input self] -o [output elf] -k [RIF file] [-K keys_external.py]`
* `sceutils self2elf -i [input self] -o [output elf] -z [zRIF]`

### examples:
* `sceutils self2elf -i eboot.bin -o eboot.elf -z [zRIF here] [-K keys_external.py]`
* `sceutils self2elf -i eboot.bin -o eboot.elf -k [RIF] [-K keys_external.py]`

---

selfinfo
--------
### usage:
* `sceutils selfinfo [input self] [-K keys_external.py]`

Prints the SCE header, SELF header, app info, control info, ELF headers,
segment metadata and (when possible) module imports/exports.

---

axfs
----
### usage:
* `sceutils axfs [list|tar] image_name [output_name]`

### examples:
* `sceutils axfs list fsimage.img`
* `sceutils axfs tar fsimage.img [fsimage.tar]`
