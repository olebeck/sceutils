import binascii
import struct
from collections import defaultdict
from enum import Enum
from typing import NamedTuple, IO, ClassVar, Type, TypeVar
from util import c_str

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
    VITASDK = 0xC0


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
        print(f"{keytype=} {scetype=} {sysver=:x} {keyrev=} {selftype}")
        raise KeyError("Cannot find key/iv for this SCE file")

T = TypeVar('T', bound='Struct')

class Struct:
    _format: ClassVar[str] = ""   # Format string for struct

    @classmethod
    def field_names(cls):
        return [k for k in cls.__annotations__.keys() if k[0] != "_"]

    @classmethod
    def Size(self):
        return self.struct_size()

    def __init__(self, **kwargs):
        for field in self.field_names():
            setattr(self, field, kwargs.get(field))
    
    @classmethod
    def struct_size(cls) -> int:
        return struct.calcsize("="+cls._format)
    
    @classmethod
    def unpack(cls: Type[T], data: bytes | IO[bytes], endian="<") -> T:
        if hasattr(data, 'read'):
            data = data.read(cls.struct_size())
        
        if len(data) < cls.struct_size():
            raise ValueError(f"Not enough data to unpack {cls.__name__}: need {cls.struct_size()}, got {len(data)}")
        
        values = struct.unpack(endian + cls._format, data)
        kwargs = {name: value for name, value in zip(cls.field_names(), values)}
        instance = cls(**kwargs)
        instance._initialize()
        return instance
    
    def pack(self, endian="<") -> bytes:
        values = tuple(getattr(self, name) for name in self.field_names())
        return struct.pack(endian + self._format, *values)

    def _initialize(self):
        return
    
    def __str__(self) -> str:
        lines = [f"{self.__class__.__name__}:"]
        for name in self.field_names():
            value = getattr(self, name)
            if isinstance(value, int):
                lines.append(f" {name}: 0x{value:X}")
            else:
                lines.append(f" {name}: {value}")
        return "\n".join(lines)
    
class SceHeader(Struct):
    _format = "IIBBHIQQ"

    magic: int
    version: int
    platform: SelfPlatform
    key_revision: int
    sce_type: SceType
    metadata_offset: int
    header_length: int
    data_length: int
    
    def _initialize(self):
        if self.magic != SCE_MAGIC:
            raise TypeError('Invalid SCE magic')
        if self.version != 3:
            raise TypeError('Unknown SCE version')
        self.sce_type = SceType(self.sce_type)
        self.platform = SelfPlatform(self.platform)
    
    def __str__(self):
        ret = 'SCE Header:\n'
        ret += f' Version: {self.version}\n'
        ret += f' Platform: {self.platform}\n'
        ret += f' Key Revision: 0x{self.key_revision:X}\n'
        ret += f' SCE Type: {self.sce_type}\n'
        ret += f' Metadata Offset: 0x{self.metadata_offset:X}\n'
        ret += f' Header Length: 0x{self.header_length:X}\n'
        ret += f' Data Length: 0x{self.data_length:X}'
        return ret


class SelfHeader(Struct):
    _format = "QQQQQQQQQQQ"
    file_length: int
    field_8: int
    self_offset: int
    appinfo_offset: int
    elf_offset: int
    phdr_offset: int
    shdr_offset: int
    segment_info_offset: int
    sceversion_offset: int
    controlinfo_offset: int
    controlinfo_length: int


class AppInfoHeader(Struct):
    _format = "QIIQQ"
    auth_id: int
    vendor_id: int
    self_type: int
    sys_version: int
    field_18: int

    def _initialize(self):
        self.self_type = SelfType(self.self_type)

    def __str__(self):
        ret = ''
        ret += 'App Info Header:\n'
        ret += f' Auth ID:          0x{self.auth_id:X}\n'
        ret += f' Vendor ID:        0x{self.vendor_id:X}\n'
        ret += f' SELF Type:        {self.self_type}\n'
        ret += f' Sys Version:      0x{self.sys_version:X}'
        return ret


class ElfHeader(Struct):
    _format = "QQHHIIIIIHHHHHH"
    e_ident_1: int
    e_ident_2: int
    e_type: int
    e_machine: int
    e_version: int
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_flags: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int

    def _initialize(self):
        if self.e_ident_1 != 0x10101464C457F:
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
        ret += f' e_phoff:          0x{self.e_phoff:X}\n'
        ret += f' e_phnum:          {self.e_phnum}\n'
        ret += f' e_shoff:          0x{self.e_shoff:X}\n'
        ret += f' e_shnum:          {self.e_shnum}'
        return ret


class ElfPhdr(Struct):
    _format = "IIIIIIII"
    p_type: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_flags: int
    p_align: int

    def __str__(self):
        ret = ''
        ret += 'ELF Segment:\n'
        ret += f' p_type:          0x{self.p_type:X}\n'
        ret += f' p_offset:        0x{self.p_offset:X}\n'
        ret += f' p_vaddr:         0x{self.p_vaddr:X}\n'
        ret += f' p_paddr:         0x{self.p_paddr:X}\n'
        ret += f' p_filesz:        0x{self.p_filesz:X}\n'
        ret += f' p_memsz:         0x{self.p_memsz:X}\n'
        ret += f' p_flags:         0x{self.p_flags:X}\n'
        ret += f' p_align:         0x{self.p_align:X}'
        return ret

class ElfShdr(Struct):
    _format = "IIIIIIIIII"
    sh_name: int
    sh_type: int
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_info: int
    sh_addralign: int
    sh_entsize: int

    def __str__(self):
        ret = ''
        ret += 'ELF Section:\n'
        ret += f' sh_name:           0x{self.sh_name:X}\n'
        ret += f' sh_type:           0x{self.sh_type:X}\n'
        ret += f' sh_flags:          0x{self.sh_flags:X}\n'
        ret += f' sh_addr:           0x{self.sh_addr:X}\n'
        ret += f' sh_offset:         0x{self.sh_offset:X}\n'
        ret += f' sh_size:           0x{self.sh_size:X}\n'
        ret += f' sh_link:           0x{self.sh_link:X}\n'
        ret += f' sh_info:           0x{self.sh_info:X}\n'
        ret += f' sh_addralign:      0x{self.sh_addralign:X}\n'
        ret += f' sh_entsize:        0x{self.sh_entsize:X}\n'
        return ret


class SegmentInfo(Struct):
    _format = "QQIIII"
    offset: int
    size: int
    compressed: int
    field_14: int
    plaintext: int
    field_1C: int

    def _initialize(self):
        self.compressed = SecureBool(self.compressed)
        self.plaintext = SecureBool(self.plaintext)

    def __str__(self):
        ret = ''
        ret += ' Segment Info:\n'
        ret += f'  offset:          0x{self.offset:X}\n'
        ret += f'  size:            0x{self.size:X}\n'
        ret += f'  compressed:      {self.compressed}\n'
        ret += f'  plaintext:       {self.plaintext}'
        return ret


class MetadataInfo(Struct):
    _format = "16sQQ16sQQ"
    key: bytes
    pad0: int
    pad1: int
    iv: bytes
    pad2: int
    pad3: int

    def _initialize(self):
        if self.pad0 != 0 or self.pad1 != 0 or self.pad2 != 0 or self.pad3 != 0:
            raise TypeError('Invalid metadata info padding (decryption likely failed)')

    def __str__(self):
        ret = ''
        ret += 'Metadata Info:\n'
        ret += f' Key:              {self.key.hex()}\n'
        ret += f' IV:               {self.iv.hex()}'
        return ret


class MetadataHeader(Struct):
    _format = "QIIIIII"
    signature_input_length: int
    signature_type: int
    section_count: int
    key_count: int
    opt_header_size: int
    field_18: int
    field_1C: int

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


class MetadataSection(Struct):
    _format = "QQIiIiIiiI"
    offset: int
    size: int
    type: int
    seg_idx: int
    hashtype: int
    hash_idx: int
    encryption: int
    key_idx: int
    iv_idx: int
    compression: int

    def _initialize(self):
        self.hashtype = HashType(self.hashtype)
        self.encryption = EncryptionType(self.encryption)
        self.compression = CompressionType(self.compression)

    def __str__(self):
        ret = ''
        ret += '  Metadata Section:\n'
        ret += f'   offset:         0x{self.offset:X}\n'
        ret += f'   size:           0x{self.size:X}\n'
        ret += f'   type:           0x{self.type:X}\n'
        ret += f'   seg_idx:        0x{self.seg_idx:X}\n'
        ret += f'   hashtype:       {self.hashtype}\n'
        ret += f'   hash_idx:       0x{self.hash_idx:X}\n'
        ret += f'   encryption:     {self.encryption}\n'
        ret += f'   key_idx:        0x{self.key_idx:X}\n'
        ret += f'   iv_idx:         0x{self.iv_idx:X}\n'
        ret += f'   compression:    {self.compression}'
        return ret


class SrvkHeader(Struct):
    _format = "IIQIIII"
    field_0: int
    field_4: int
    sys_version: int
    field_10: int
    field_14: int
    field_18: int
    field_1C: int

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


class SpkgHeader(Struct):
    _format = "IIIIQQQQIIIIQQQQQQQQ"
    field_0: int
    pkg_type: int
    flags: int
    field_C: int
    update_version: int
    final_size: int
    decrypted_size: int
    field_28: int
    field_30: int
    field_34: int
    field_38: int
    field_3C: int
    field_40: int
    field_48: int
    offset: int
    size: int
    part_idx: int
    total_parts: int
    field_70: int
    field_78: int

    def _initialize(self):
        self.pkg_type = SkpgType(self.pkg_type)

    def __str__(self):
        ret = ''
        ret += 'SPKG Header:\n'
        ret += f' field_0:          0x{self.field_0:X}\n'
        ret += f' type:             {self.pkg_type}\n'
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


class SceVersionInfo(Struct):
    _format = "IIQ"
    subtype: int
    is_present: int
    size: int
    Size = 16

    def __str__(self):
        ret = 'SCE Version Info Header:\n'
        ret += f' subtype:          0x{self.subtype:X}\n'
        ret += f' isPresent:        0x{self.is_present:X}\n'
        ret += f' size:             0x{self.size:X}\n'
        return ret


class SceControlInfo(Struct):
    _format = "IIQ"
    control_type: ControlType
    size: int
    more: int
    Size = 16

    def _initialize(self):
        self.control_type = ControlType(self.control_type)

    def __str__(self):
        ret = 'SCE Control Info Header:\n'
        ret += f' control_type:  {self.control_type}\n'
        ret += f' size:          0x{self.size:X}\n'
        ret += f' more:          0x{self.more:X}\n'
        return ret


class SceControlInfoDigest256(Struct):
    _format = "20s32sIII"
    sce_hash: bytes
    file_hash: bytes
    filler1: int
    filler2: int
    sdk_version: int

    def __str__(self):
        ret = 'SCE Control Info Digest256:\n'
        ret += f' SCE Hash:         {self.sce_hash.hex()}\n'
        ret += f' File Hash:        {self.file_hash.hex()}\n'
        ret += f' SDK version:      0x{self.sdk_version:X}\n'
        return ret


class SceControlInfoDRM(Struct):
    _format = "IHHII48s16s32s32s28s28s28s28s"
    magic: int
    sig_offset: int
    size: int
    npdrm_type: int
    field_C: int
    content_id: bytes
    digest1: bytes
    hash1: bytes
    hash2: bytes
    sig1r: bytes
    sig1s: bytes
    sig2r: bytes
    sig2s: bytes

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


class SceRIF(Struct):
    _format = "HHHHQ48s16s16s16sQ20s20s"
    majver: int
    minver: int
    style: int
    riftype: int
    cid: int
    content_id: bytes
    actidx: bytes
    klicense: bytes
    dates: bytes
    filler: int
    sig1r: bytes
    sig1s: bytes

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


class SceModuleInfo(Struct):
    _format = "hh27sbIIIIIIIIIIIIIII"
    attributes: int
    version: int
    module_name: str
    type: int
    gp_value: int
    exportsStart: int
    exportsEnd: int
    importsTop: int
    importsEnd: int
    module_nid: int
    tlsStart: int
    tlsFileSize: int
    tlsMemSize: int
    module_start: int
    module_stop: int
    exidx_top: int
    exidx_end: int
    extab_start: int
    extab_end: int

    def _initialize(self):
        self.module_name = c_str(self.module_name)

class SceModuleImports(Struct):
    _format = "hhhhhhIIIIIIIIII"
    size: int
    version: int
    attribute: int
    num_functions: int
    num_vars: int
    num_tls_vars: int
    reserved1: int
    library_nid: int
    library_name: int
    reserved2: int
    func_nid_table: int
    func_entry_table: int
    var_nid_table: int
    var_entry_table: int
    tls_nid_table: int
    tls_entry_table: int

class SceModuleImports2(Struct):
    _format = "hhhhhIIIIII"
    size: int
    version: int
    attribute: int
    num_functions: int
    num_vars: int
    library_nid: int
    library_name: int
    func_nid_table: int
    func_entry_table: int
    var_nid_table: int
    var_entry_table: int

class SceModuleLibaryExports(Struct):
    _format = "bbhhhhhbbbbIIII"
    size: int
    pad: int
    version: int
    attr: int
    nfunc: int
    nvar: int
    ntlsvar: int
    hashinfo: int
    hashinfotls: int
    pad2: int
    nidaltsets: int
    libname_nid: int
    libname_ptr: int
    nidtable: int
    addrtable: int
