Requirements
============

ubuntu 18.04 (or bash on windows ubuntu equivalent)

python3

p7zip-full (for exfat)
gcc and make (to compile unazlr)


python3:
* pycryptodome




usage
=====

pup_fiction.py
--------------
### usage:
* `./pup_fiction.py PUP_filename output_folder keys_file`


### examples:
* `./pup_fiction.py PSP2UPDATE.pup 368 keys_external.py`

---

self2elf.py
-----------
### usage:
* `./self2elf.py -i [input self] -o [output elf] -k [RIF file] [-K keys_external.py]`
* `./self2elf.py -i [input self] -o [output elf] -z [zRIF]` 


### examples:
* `./self2elf.py -i eboot.bin -o eboot.elf -z [zRIF here] [-K keys_external.py]`
* `./self2elf.py -i eboot.bin -o eboot.elf -k [RIF] [-K keys_external.py]`

---

axfs.py
-------
### usage:
* `./axfs.py [list|tar] [image_name] [output_name]`

### examples:
* `./axfs.py list fsimage.img`
* `./axfs.py tar fsimage.img [fsimage.tar]`
