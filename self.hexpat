import std.mem;

struct SceHeader {
    u32 magic;
    u32 version;
    u8 platform;
    u8 key_revision;
    u16 sce_type;
    u32 metadata_offset;
    u64 header_length;
    u64 data_length;
};

struct SelfHeader {
    u64 file_length;
    u64 field_8;
    u64 self_offset;
    u64 appinfo_offset;
    u64 elf_offset;
    u64 phdr_offset;
    u64 shdr_offset;
    u64 segment_info_offset;
    u64 sceversion_offset;
    u64 controlinfo_offset;
    u64 controlinfo_length;
};

struct AppInfoHeader {
    u64 auth_id;
    u32 vendor_id;
    u32 self_type;
    u64 sys_version;
    u64 field_18;
};

struct SceVersionInfo {
    u32 subtype;
    u32 is_present;
    u64 size;
};

struct ElfHeader {
    u64 e_ident_1;
    u64 e_ident_2;
    u16 e_type;
    u16 e_machine;
    u32 e_version;
    u32 e_entry;
    u32 e_phoff;
    u32 e_shoff;
    u32 e_flags;
    u16 e_ehsize;
    u16 e_phentsize;
    u16 e_phnum;
    u16 e_shentsize;
    u16 e_shnum;
    u16 e_shstrndx;
};

struct ElfPhdr {
    u32 p_type;
    u32 p_offset;
    u32 p_vaddr;
    u32 p_paddr;
    u32 p_filesz;
    u32 p_memsz;
    u32 p_flags;
    u32 p_align;
};

struct ElfShdr {
    u32 sh_name;
    u32 sh_type;
    u32 sh_flags;
    u32 sh_addr;
    u32 sh_offset;
    u32 sh_size;
    u32 sh_link;
    u32 sh_info;
    u32 sh_addralign;
    u32 sh_entsize;
    
    if(sh_size < 0x100000)
    char data[sh_size] @ sh_offset + parent.sce.header_length;
   
    u32 name_offset = std::mem::read_unsigned(parent.self.shdr_offset + parent.elf_hdr.e_shstrndx * 0x28 + 4*4, 4) + parent.sce.header_length;
    char name[] @ name_offset + sh_name;
};

struct SegmentInfo {
    u64 offset;
    u64 size;
    u32 compressed;
    u32 field_14;
    u32 plaintext;
    u32 field_1c;
};

struct Self {
    SceHeader sce;
    SelfHeader self;
    AppInfoHeader appinfo @self.appinfo_offset;
    SceVersionInfo versioninfo @self.sceversion_offset;
    
    ElfHeader elf_hdr @self.elf_offset;
    ElfPhdr phdrs[elf_hdr.e_phnum] @self.phdr_offset;
    ElfShdr shdrs[elf_hdr.e_shnum] @self.shdr_offset;
    SegmentInfo segment_infos[elf_hdr.e_phnum] @self.segment_info_offset;
};

Self self @0x0;