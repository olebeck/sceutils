import binascii
from scetypes import KeyType, KeyStore, SceType, SelfType

ENC_KEY = binascii.a2b_hex('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
ENC_IV =  binascii.a2b_hex('AF5F2CB04AC1751ABF51CEF1C8096210')
XXX_KEY = binascii.a2b_hex('992EF70868DE1B219EC3618FA79DAEC39067FE5638116C29FC0FF7E2A58FBD9E')
XXX_IV =  binascii.a2b_hex('00000000000000000000000000000000')

SCEWM_KEY = binascii.a2b_hex("BFD5EA9F91AE9AF23565E534C4823B72")
SCEWM_IV =  binascii.a2b_hex("CE16937E97A3349F143C8FB6AA219528")

SCEAS_KEY = binascii.a2b_hex("6B0AF9E48DD54E4BBD9F2FDA1063082A")
SCEAS_IV =  binascii.a2b_hex("001B362DA54268E97000B83B90118E54")

SCE_KEYS = KeyStore()
SCE_KEYS.register(
    KeyType.METADATA,
    SceType.SPKG, 
    0, 
    'FA88E5B5CBB49603DF689F139045E7C3C9C7E33B5923DF54E4C5FE5298B4FD32', 
    '5EAA69AB35E737EC22C721A916E00263', 
    0x00000000000, 
    0xFFF00000000, 
    SelfType.NONE
)

SCE_KEYS.register(
    KeyType.METADATA,
    SceType.SELF, 
    1, 
    'B982589B568CDD4055433747DF19644A8D1B479B17CA44ECE5E82694550FEC74', 
    'BECEDF96543939032CC4DD7D95E47720', 
    0x00000000000, 
    0xFFF00000000, 
    SelfType.SECURE
)

SCE_KEYS.register(
    KeyType.METADATA,
    SceType.SELF, 
    1, 
    '9EE16CA4AADD77F53BEE0F4AE3D45326D009806D2DE9942CE0836E43DC5DD1CE', 
    'CFBA84A87EE29C9A521CA20691485E45', 
    0x00000000000, 
    0xFFF00000000, 
    SelfType.BOOT
)

SCE_KEYS.register(
    KeyType.METADATA,
    SceType.SRVK, 
    0, 
    'A603AA68753CEE3E186C81900A862DCDB13505D39FC59C62BBFAD94C526B8A06', 
    '352F596CFB513A148B95F9D78E57E755', 
    0x00000000000, 
    0xFFF00000000, 
    SelfType.NONE
)

SCE_KEYS.register(
    KeyType.METADATA,
    SceType.SELF, 
    1, 
    '61E7E786BB6F67570A71FC92E73885439CD16B96BC7C37C200EF11D3446FCF69', 
    '99E8B68EE784FDAFC3294B8E55F0C529', 
    0x00000000000, 
    0xFFF00000000, 
    SelfType.KERNEL
)

SCE_KEYS.register(
    KeyType.METADATA,
    SceType.SELF, 
    0, 
    'DA3BE69B77B3A857EA4F6CDC73C0AB0590C0A95E145B8D55D2D3A6447C247F46', 
    'A0385383AB31497E3AFB7CCDDB30CA5A', 
    0x00000000000, 
    0xFFF00000000, 
    SelfType.USER
)

SCE_KEYS.register(
    KeyType.METADATA,
    SceType.SELF, 
    1, 
    '8D355E70736EF7AA508D640D8D382B19D9C8747C4A8273A6D5707F227F49592E', 
    'BEB4819878915F3025978538693B3EBB', 
    0x00000000000, 
    0xFFF00000000, 
    SelfType.USER
)

SCE_KEYS.register(
    KeyType.METADATA,
    SceType.SELF,
    0,
    'AAA508FA5E85EAEE597ED2B27804D22287CFADF1DF32EDC7A7C58E8C9AA8BB36',
    'CD1BD3A59200CC67A3B804808DC2AE73',
    0x00000000000, 
    0x16920000000, 
    SelfType.APP
)

SCE_KEYS.register(
    KeyType.METADATA,
    SceType.SELF,
    1,
    '4181B2DF5F5D94D3C80B7D86EACF1928533A49BA58EDE2B43CDEE7E572568BD4',
    'B1678C0543B6C1997B63A6F4F3C8FD33',
    0x00000000000, 
    0xFFFFFFFFFFFFFFFFFFFFFF, 
    SelfType.APP
)

SCE_KEYS.register(
    KeyType.NPDRM,
    SceType.SELF,
    0,
    'C10368BF3D2943BC6E5BD05E46A9A7B6',
    '00000000000000000000000000000000',
    0x00000000000, 
    0xFFFFFFFFFFFFFFFFFFFFFF, 
    SelfType.APP
)

SCE_KEYS.register(
    KeyType.NPDRM,
    SceType.SELF,
    1,
    '00000000000000000000000000000000',
    '00000000000000000000000000000000',
    0x00000000000, 
    0xFFFFFFFFFFFFFFFFFFFFFF, 
    SelfType.APP
)