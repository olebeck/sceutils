import binascii
import struct
from collections import defaultdict
from enum import Enum
from typing import NamedTuple

SCE_MAGIC = 0x00454353


class SceSegment(NamedTuple):
    offset: int
    idx: int
    size: int
    compressed: bool
    key: bytes
    iv: bytes


class KeyEntry(NamedTuple):
    minver: int
    maxver: int
    keyrev: int
    key: bytes
    iv: bytes


class SceType(Enum):
    SELF = 1
    SRVK = 2
    SPKG = 3
    DEV = 0xC0


class SceSigType(Enum):
    ECDSA160 = 1
    RSA2048 = 5


class SelfType(Enum):
    NONE = 0
    KERNEL = 0x07
    APP = 0x08
    BOOT = 0x09
    SECURE = 0x0B
    USER = 0x0D


class KeyType(Enum):
    METADATA = 0
    NPDRM = 1


class SelfPlatform(Enum):
    PS3 = 0
    VITA = 0x40


class SkpgType(Enum):
    TYPE_0 = 0x0
    OS0 = 0x1
    TYPE_2 = 0x2
    TYPE_3 = 0x3
    PERMISSIONS_4 = 0x4
    TYPE_5 = 0x5
    TYPE_6 = 0x6
    TYPE_7 = 0x7
    SYSCON_8 = 0x8
    BOOT = 0x9
    VS0 = 0xA
    CPFW = 0xB
    MOTION_C = 0xC
    BBMC_D = 0xD
    TYPE_E = 0xE
    MOTION_F = 0xF
    TOUCH_10 = 0x10
    TOUCH_11 = 0x11
    SYSCON_12 = 0x12
    SYSCON_13 = 0x13
    SYSCON_14 = 0x14
    TYPE_15 = 0x15
    VS0_TAR_PATCH = 0x16
    SA0 = 0x17
    PD0 = 0x18
    SYSCON_19 = 0x19
    TYPE_1A = 0x1A
    PSPEMU_LIST = 0x1B


class ControlType(Enum):
    CONTROL_FLAGS = 1
    DIGEST_SHA1 = 2
    NPDRM_PS3 = 3
    DIGEST_SHA256 = 4
    NPDRM_VITA = 5
    UNK_SIG1 = 6
    UNK_HASH1 = 7


class SecureBool(Enum):
    UNUSED = 0
    NO = 1
    YES = 2


class EncryptionType(Enum):
    NONE = 1
    AES128CTR = 3


class HashType(Enum):
    NONE = 1
    HMACSHA1 = 2
    HMACSHA256 = 6


class CompressionType(Enum):
    NONE = 1
    DEFLATE = 2


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
        print(f"{keytype=} {scetype=} {sysver=} {keyrev=} {selftype}")
        raise KeyError("Cannot find key/iv for this SCE file")


class SceHeader:
    Size = 32

    def __init__(self, data):
        (
            self.magic,
            self.version,
            platform,
            self.key_revision,
            sce_type,
            self.metadata_offset,
            self.header_length,
            self.data_length
        ) = struct.unpack('<IIBBHIQQ', data)
        if self.magic != SCE_MAGIC:
            raise TypeError('Invalid SCE magic')
        if self.version != 3:
            raise TypeError('Unknown SCE version')
        self.sce_type = SceType(sce_type)
        self.platform = SelfPlatform(platform)

    def __str__(self):
        ret = ''
        ret += 'SCE Header:\n'
        ret += f' Version:          {self.version}\n'
        ret += f' Platform:         {self.platform}\n'
        ret += f' Key Revision:     0x{self.key_revision:X}\n'
        ret += f' SCE Type:         {self.sce_type}\n'
        ret += f' Metadata Offset:  0x{self.metadata_offset:X}\n'
        ret += f' Header Length:    0x{self.header_length:X}\n'
        ret += f' Data Length:      0x{self.data_length:X}'
        return ret


class SelfHeader:
    Size = 88

    def __init__(self, data):
        (
            self.file_length,
            self.field_8,
            self.self_offset,
            self.appinfo_offset,
            self.elf_offset,
            self.phdr_offset,
            self.shdr_offset,
            self.segment_info_offset,
            self.sceversion_offset,
            self.controlinfo_offset,
            self.controlinfo_length
        ) = struct.unpack('<QQQQQQQQQQQ', data)


class AppInfoHeader:
    Size = 32

    def __init__(self, data):
        (
            self.auth_id,
            self.vendor_id,
            self_type,
            self.sys_version,
            self.field_18
        ) = struct.unpack('<QIIQQ', data)
        self.self_type = SelfType(self_type)

    def __str__(self):
        ret = ''
        ret += 'App Info Header:\n'
        ret += f' Auth ID:          0x{self.auth_id:X}\n'
        ret += f' Vendor ID:        0x{self.vendor_id:X}\n'
        ret += f' SELF Type:        {self.self_type}\n'
        ret += f' Sys Version:      0x{self.sys_version:X}'
        return ret


class ElfHeader:
    Size = 52

    def __init__(self, data):
        (
            e_ident_1,
            e_ident_2,
            self.e_type,
            self.e_machine,
            self.e_version,
            self.e_entry,
            self.e_phoff,
            self.e_shoff,
            self.e_flags,
            self.e_ehsize,
            self.e_phentsize,
            self.e_phnum,
            self.e_shentsize,
            self.e_shnum,
            self.e_shstrndx
        ) = struct.unpack('<QQHHIIIIIHHHHHH', data)
        if e_ident_1 != 0x10101464C457F:
            raise TypeError('Unknown ELF e_ident')
        if self.e_machine != 0x28 and self.e_machine != 0xF00D:
            raise TypeError('Unknown ELF e_machine')
        if self.e_version != 0x1:
            raise TypeError('Unknown ELF e_version')

    def __str__(self):
        ret = ''
        ret += 'ELF Header:\n'
        ret += f' e_machine:        {"ARM" if self.e_machine == 0x28 else "MeP"}\n'
        ret += f' e_entry:          0x{self.e_entry:X}\n'
        ret += f' e_phnum:          {self.e_phnum}'
        return ret


class ElfPhdr:
    Size = 32

    def __init__(self, data):
        (
            self.p_type,
            self.p_offset,
            self.p_vaddr,
            self.p_paddr,
            self.p_filesz,
            self.p_memsz,
            self.p_flags,
            self.p_align
        ) = struct.unpack('<IIIIIIII', data)

    def __str__(self):
        ret = ''
        ret += ' ELF Segment:\n'
        ret += f'  p_type:          0x{self.p_type:X}\n'
        ret += f'  p_offset:        0x{self.p_offset:X}\n'
        ret += f'  p_vaddr:         0x{self.p_vaddr:X}\n'
        ret += f'  p_paddr:         0x{self.p_paddr:X}\n'
        ret += f'  p_filesz:        0x{self.p_filesz:X}\n'
        ret += f'  p_memsz:         0x{self.p_memsz:X}\n'
        ret += f'  p_flags:         0x{self.p_flags:X}\n'
        ret += f'  p_align:         0x{self.p_align:X}'
        return ret


class SegmentInfo:
    Size = 32

    def __init__(self, data):
        (
            self.offset,
            self.size,
            compressed,
            self.field_14,
            plaintext,
            self.field_1C
        ) = struct.unpack('<QQIIII', data)
        self.compressed = SecureBool(compressed)
        self.plaintext = SecureBool(plaintext)

    def __str__(self):
        ret = ''
        ret += ' Segment Info:\n'
        ret += f'  offset:          0x{self.offset:X}\n'
        ret += f'  size:            0x{self.size:X}\n'
        ret += f'  compressed:      {self.compressed}\n'
        ret += f'  plaintext:       {self.plaintext}'
        return ret


class MetadataInfo:
    Size = 64

    def __init__(self, data):
        (
            self.key,
            pad0, pad1,
            self.iv,
            pad2, pad3
        ) = struct.unpack('<16sQQ16sQQ', data[:64])
        if pad0 != 0 or pad1 != 0 or pad2 != 0 or pad3 != 0:
            raise TypeError('Invalid metadata info padding (decryption likely failed)')

    def __str__(self):
        ret = ''
        ret += 'Metadata Info:\n'
        ret += f' Key:              {self.key.hex()}\n'
        ret += f' IV:               {self.iv.hex()}'
        return ret


class MetadataHeader:
    Size = 32

    def __init__(self, data):
        (
            self.signature_input_length,
            self.signature_type,
            self.section_count,
            self.key_count,
            self.opt_header_size,
            self.field_18,
            self.field_1C
        ) = struct.unpack('<QIIIIII', data)

    def __str__(self):
        ret = ''
        ret += ' Metadata Header:\n'
        ret += f'  sig_input_len:   0x{self.signature_input_length:X}\n'
        ret += f'  sig_type:        {SceSigType(self.signature_type)}\n'
        ret += f'  section_count    0x{self.section_count:X}\n'
        ret += f'  key_count:       0x{self.key_count:X}\n'
        ret += f'  opt_header_size: 0x{self.opt_header_size:X}\n'
        ret += f'  field_18:        {self.field_18}\n'
        ret += f'  field_1C:        {self.field_1C}'
        return ret


class MetadataSection:
    Size = 48

    def __init__(self, data):
        (
            self.offset,
            self.size,
            self.type,
            self.seg_idx,
            hashtype,
            self.hash_idx,
            encryption,
            self.key_idx,
            self.iv_idx,
            compression
        ) = struct.unpack('<QQIiIiIiiI', data)
        self.hash = HashType(hashtype)
        self.encryption = EncryptionType(encryption)
        self.compression = CompressionType(compression)

    def __str__(self):
        ret = ''
        ret += '  Metadata Section:\n'
        ret += f'   offset:         0x{self.offset:X}\n'
        ret += f'   size:           0x{self.size:X}\n'
        ret += f'   type:           0x{self.type:X}\n'
        ret += f'   seg_idx:        0x{self.seg_idx:X}\n'
        ret += f'   hash:           {self.hash}\n'
        ret += f'   hash_idx:       0x{self.hash_idx:X}\n'
        ret += f'   encryption:     {self.encryption}\n'
        ret += f'   key_idx:        0x{self.key_idx:X}\n'
        ret += f'   iv_idx:         0x{self.iv_idx:X}\n'
        ret += f'   compression:    {self.compression}'
        return ret


class SrvkHeader:
    Size = 32

    def __init__(self, data):
        (
            self.field_0,
            self.field_4,
            self.sys_version,
            self.field_10,
            self.field_14,
            self.field_18,
            self.field_1C
        ) = struct.unpack('<IIQIIII', data)

    def __str__(self):
        ret = ''
        ret += 'SRVK Header:\n'
        ret += f' field_0:          0x{self.field_0:X}\n'
        ret += f' field_4:          0x{self.field_4:X}\n'
        ret += f' sys_version:      0x{self.sys_version:X}\n'
        ret += f' field_10:         0x{self.field_10:X}\n'
        ret += f' field_14:         0x{self.field_14:X}\n'
        ret += f' field_18:         0x{self.field_18:X}\n'
        ret += f' field_1C:         0x{self.field_1C:X}\n'
        return ret


class SpkgHeader:
    Size = 128

    def __init__(self, data):
        (
            self.field_0,
            pkg_type,
            self.flags,
            self.field_C,
            self.update_version,
            self.final_size,
            self.decrypted_size,
            self.field_28,
            self.field_30,
            self.field_34,
            self.field_38,
            self.field_3C,
            self.field_40,
            self.field_48,
            self.offset,
            self.size,
            self.part_idx,
            self.total_parts,
            self.field_70,
            self.field_78
        ) = struct.unpack('<IIIIQQQQIIIIQQQQQQQQ', data)
        self.type = SkpgType(pkg_type)

    def __str__(self):
        ret = ''
        ret += 'SPKG Header:\n'
        ret += f' field_0:          0x{self.field_0:X}\n'
        ret += f' type:             {self.type}\n'
        ret += f' flags:            0x{self.flags:X}\n'
        ret += f' field_C:          0x{self.field_C:X}\n'
        ret += f' update_version:   0x{self.update_version:X}\n'
        ret += f' final_size:       0x{self.final_size:X}\n'
        ret += f' decrypted_size:   0x{self.decrypted_size:X}\n'
        ret += f' field_28:         0x{self.field_28:X}\n'
        ret += f' field_30:         0x{self.field_30:X}\n'
        ret += f' field_34:         0x{self.field_34:X}\n'
        ret += f' field_38:         0x{self.field_38:X}\n'
        ret += f' field_3C:         0x{self.field_3C:X}\n'
        ret += f' field_40:         0x{self.field_40:X}\n'
        ret += f' field_48:         0x{self.field_48:X}\n'
        ret += f' offset:           0x{self.offset:X}\n'
        ret += f' size:             0x{self.size:X}\n'
        ret += f' part_idx:         0x{self.part_idx:X}\n'
        ret += f' total_parts:      0x{self.total_parts:X}\n'
        ret += f' field_70:         0x{self.field_70:X}\n'
        ret += f' field_78:         0x{self.field_78:X}\n'
        return ret


class SceVersionInfo:
    Size = 16

    def __init__(self, data):
        (
            self.subtype,
            self.isPresent,
            self.size
        ) = struct.unpack('<IIQ', data)

    def __str__(self):
        ret = 'SCE Version Info Header:\n'
        ret += f' subtype:          0x{self.subtype:X}\n'
        ret += f' isPresent:        0x{self.isPresent:X}\n'
        ret += f' size:             0x{self.size:X}\n'
        return ret


class SceControlInfo:
    Size = 16

    def __init__(self, data):
        (
            control_type,
            self.size,
            self.more
        ) = struct.unpack('<IIQ', data)
        self.type = ControlType(control_type)

    def __str__(self):
        ret = 'SCE Control Info Header:\n'
        ret += f' type:          {self.type}\n'
        ret += f' size:          0x{self.size:X}\n'
        ret += f' more:          0x{self.more:X}\n'
        return ret


class SceControlInfoDigest256:
    Size = 64

    def __init__(self, data):
        (
            self.sce_hash,
            self.file_hash,
            self.filler1,
            self.filler2,
            self.sdk_version
        ) = struct.unpack("<20s32sIII", data[:64])

    def __str__(self):
        ret = 'SCE Control Info Digest256:\n'
        ret += f' SCE Hash:         {self.sce_hash.hex()}\n'
        ret += f' File Hash:        {self.file_hash.hex()}\n'
        ret += f' SDK version:      0x{self.sdk_version:X}\n'
        return ret


class SceControlInfoDRM:
    Size = 0x100

    def __init__(self, data):
        self.content_id = data[0x10:0x40]
        self.digest1 = data[0x40:0x50]
        self.hash1 = data[0x50:0x70]
        self.hash2 = data[0x70:0x90]
        self.sig1r = data[0x90:0xAC]
        self.sig1s = data[0xAC:0xC8]
        self.sig2r = data[0xC8:0xE4]
        self.sig2s = data[0xE4:0x100]
        (
            self.magic,
            self.sig_offset,
            self.size,
            self.npdrm_type,
            self.field_C,
        ) = struct.unpack("<IHHII", data[0:0x10])

    def __str__(self):
        ret = 'SCE DRM Info:\n'
        ret += f' Magic:             0x{self.magic:X}\n'
        ret += f' Sig Offset:        0x{self.sig_offset:X}\n'
        ret += f' Size:              0x{self.size:X}\n'
        ret += f' NPDRM Type:        0x{self.npdrm_type:X}\n'
        ret += f' Content ID:        {self.content_id}\n'
        ret += f' Type Digest:       {self.digest1.hex()}\n'
        ret += f' ECDSA224 Sig R:    {self.sig2r.hex()}\n'
        ret += f' ECDSA224 Sig S:    {self.sig2s.hex()}\n'
        return ret


class SceRIF:
    Size = 0x98

    def __init__(self, data):
        self.content_id = data[0x10:0x40]
        self.actidx = data[0x40:0x50]
        self.klicense = data[0x50:0x60]
        self.dates = data[0x60:0x70]
        self.filler = data[0x70:0x78]
        self.sig1r = data[0x78:0x8C]
        self.sig1s = data[0x8C:0x98]
        (
            self.majver,
            self.minver,
            self.style,
            self.riftype,
            self.cid
        ) = struct.unpack(">HHHHQ", data[0:0x10])

    def __str__(self):
        ret = 'SCE RIF Info:\n'
        ret += f' Maj Ver:           0x{self.majver:X}\n'
        ret += f' Min Ver:           0x{self.minver:X}\n'
        ret += f' Style:             0x{self.style:X}\n'
        ret += f' RifType:           0x{self.riftype:X}\n'
        ret += f' CID:               0x{self.cid:X}\n'
        ret += f' Content ID:        {self.content_id}\n'
        ret += f' KLicensee:         {self.klicense.hex()}\n'
        ret += f' ECDSA160 Sig R:    {self.sig1r.hex()}\n'
        ret += f' ECDSA160 Sig S:    {self.sig1s.hex()}\n'
        return ret
