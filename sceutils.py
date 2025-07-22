from Cryptodome.Cipher import AES
import zlib
import binascii
from scetypes import SceHeader, SceType, KeyType, SelfType, SceSegment, SelfHeader, AppInfoHeader, MetadataInfo, MetadataHeader, MetadataSection, SrvkHeader, SpkgHeader, CompressionType, EncryptionType
from binascii import b2a_hex
from typing import IO
import keys

def zrif_decode(data: str):
    zrif_dict = list(zlib.decompress(binascii.a2b_base64(b"eNpjYBgFo2AU0AsYAIElGt8MRJiDCAsw3xhEmIAIU4N4AwNdRxcXZ3+/EJCAkW6Ac7C7ARwYgviuQAaIdoPSzlDaBUo7QmknIM3ACIZM78+u7kx3VWYEAGJ9HV0=")))
    d = zlib.decompressobj(wbits=10, zdict=bytes(zrif_dict))
    raw = binascii.a2b_base64(data)
    out = d.decompress(raw)
    out += d.flush()
    return out


def print_metadata_keyvault(keys):
    print(' Metadata Vault:')
    for i, key in enumerate(keys):
        print(f'  {i:#0{4}x}:      {b2a_hex(key)}')


def get_segments(inf: IO[bytes], sce_hdr: SceHeader, sysver=-1, self_type=SelfType.NONE, keytype=0, klictxt=b"\0"*16, silent=False, use_spkg2=False) -> dict[int, SceSegment]:
    inf.seek(sce_hdr.metadata_offset + 48)
    dat = inf.read(sce_hdr.header_length - sce_hdr.metadata_offset - 48)
    sce_type = sce_hdr.sce_type if not use_spkg2 else (sce_hdr.sce_type, 2)
    (key, iv) = keys.SCE_KEYS.get(KeyType.METADATA, sce_type, sysver, sce_hdr.key_revision, self_type)
    hdr_dec = AES.new(key, AES.MODE_CBC, iv)
    if self_type == SelfType.APP:
        keytype = 0
        if sce_hdr.key_revision >= 2:
            keytype = 1
        (np_key, np_iv) = keys.SCE_KEYS.get(KeyType.NPDRM, sce_type, sysver, keytype, self_type)
        npdrm_dec = AES.new(np_key, AES.MODE_CBC, np_iv)
        predec = npdrm_dec.decrypt(klictxt)
        npdrm_dec2 = AES.new(predec, AES.MODE_CBC, np_iv)
        dec_in = npdrm_dec2.decrypt(dat[0:MetadataInfo.Size()])
    else:
        dec_in = dat[0:MetadataInfo.Size()]

    dec = hdr_dec.decrypt(dec_in)
    metadata_info = MetadataInfo.unpack(dec)
    if not silent:
        print(metadata_info)
    contents_dec = AES.new(metadata_info.key, AES.MODE_CBC, metadata_info.iv)
    dec = contents_dec.decrypt(dat[MetadataInfo.Size():])
    metadata_hdr = MetadataHeader.unpack(dec[0:MetadataHeader.Size()])
    if not silent:
        print(metadata_hdr)
    segs = {}
    start = MetadataHeader.Size() + metadata_hdr.section_count * MetadataSection.Size()
    vault = [dec[start + 16 * x:start + 16 * (x + 1)] for x in range(metadata_hdr.key_count)]
    if not silent:
        print_metadata_keyvault(vault)
    for i in range(metadata_hdr.section_count):
        dat = dec[MetadataHeader.Size() + i * MetadataSection.Size():]
        metsec = MetadataSection.unpack(dat[:MetadataSection.Size()])
        if not silent:
            print(metsec)
        if metsec.encryption == EncryptionType.AES128CTR:
            segs[i] = SceSegment(metsec.offset, metsec.seg_idx, metsec.size, metsec.compression == CompressionType.DEFLATE, vault[metsec.key_idx], vault[metsec.iv_idx])
    return segs


def get_key_type(inf, sce_hdr, silent=False):
    if sce_hdr.sce_type == SceType.SELF:
        inf.seek(32)
        self_hdr = SelfHeader.unpack(inf)
        inf.seek(self_hdr.appinfo_offset)
        appinfo_hdr = AppInfoHeader.unpack(inf)
        if not silent:
            print(appinfo_hdr)
        return (appinfo_hdr.sys_version, appinfo_hdr.self_type), False
    elif sce_hdr.sce_type == SceType.SRVK:
        inf.seek(sce_hdr.header_length)
        srvk = SrvkHeader.unpack(inf)
        if not silent:
            print(srvk)
        return (srvk.sys_version, SelfType.NONE), False
    elif sce_hdr.sce_type == SceType.SPKG:
        inf.seek(sce_hdr.header_length)
        spkg = SpkgHeader.unpack(inf)
        if not silent:
            print(spkg)
        return (spkg.update_version << 16, SelfType.NONE), spkg.field_48 == 0x40
    else:
        print(f'Unknown system version for type {sce_hdr.sce_types}')
        return -1
