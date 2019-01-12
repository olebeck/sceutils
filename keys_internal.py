from scetypes import *

ENC_KEY = binascii.a2b_hex('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
ENC_IV =  binascii.a2b_hex('AF5F2CB04AC1751ABF51CEF1C8096210')


SCE_KEYS = KeyStore()
SCE_KEYS.register(
    KeyType.METADATA,
    SceType.SPKG, 
    0, 
    '23F1D525244266E6DA7A52DA9446318301EE8CC58D54901AE94D93010F7DEE6B', 
    '3721F7C05DE5F55ECC39BDDB4A6C585D', 
    0x00000000000, 
    0xFFF00000000, 
    SelfType.NONE
)

SCE_KEYS.register(
    KeyType.METADATA,
    SceType.SELF, 
    0, 
    'AED9D76EE1E29290002BFF32D4B0656EEE40FBDA4F8B55BE5BE0ED83530F27D2', 
    'DB50912F2416B54F7F36227169ECE500', 
    0x00000000000, 
    0x10000000000, 
    SelfType.SECURE
)

SCE_KEYS.register(
    KeyType.METADATA,
    SceType.SELF, 
    0, 
    '9D3F28DE30DED1D503DB6FA762A571C422A88D0F361899EF36D357059C72EC43', 
    '30E43CFB57D418A5A0D32A9939D23501', 
    0x00000000000, 
    0x10000000000, 
    SelfType.BOOT
)

SCE_KEYS.register(
    KeyType.METADATA,
    SceType.SRVK, 
    0, 
    'EAB14F9BE15EAEC1603BE63C9FCDE4099D601FB0E9FC4DF250B8DEC635987A1C', 
    '30B9E61707993B635D0E182446DB0B8D', 
    0x00000000000, 
    0x10000000000, 
    SelfType.NONE
)

SCE_KEYS.register(
    KeyType.METADATA,
    SceType.SELF, 
    0, 
    '74F6D2A1D2A093AE32B83337E0AE4AD2E6D93B034F5BF3B68DB77131883310D4', 
    '926AB55BDADC45DBB610E90E56A0368C', 
    0x00000000000, 
    0x10000000000, 
    SelfType.KERNEL
)

SCE_KEYS.register(
    KeyType.METADATA,
    SceType.SELF, 
    0, 
    '322D706CB6EBEA14DEF7BFE45F812971347DC95CD7697C16A71EA4B2A1E12C0D', 
    '31FA2E606031EDF39665B5616E9F937D', 
    0x00000000000, 
    0x10000000000, 
    SelfType.USER
)