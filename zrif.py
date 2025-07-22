import zlib
import binascii

zrif_dict = list(zlib.decompress(binascii.a2b_base64(b"eNpjYBgFo2AU0AsYAIElGt8MRJiDCAsw3xhEmIAIU4N4AwNdRxcXZ3+/EJCAkW6Ac7C7ARwYgviuQAaIdoPSzlDaBUo7QmknIM3ACIZM78+u7kx3VWYEAGJ9HV0=")))

def zrif_decode(data: str):
    d = zlib.decompressobj(wbits=10, zdict=bytes(zrif_dict))
    raw = binascii.a2b_base64(data)
    out = d.decompress(raw)
    out += d.flush()
    return out
