
import os
import sys
if __name__ == "__main__":
    sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..')))

import sys, json
from scetypes import ElfHeader, ElfPhdr, SceModuleInfo, SceModuleImports, SceModuleImports2
from util import c_str

if __name__ == "__main__":
    with open(sys.argv[1], "rb") as fin:
        ehdr = ElfHeader.unpack(fin)
        segment_num = (ehdr.e_entry >> 30) & 0x3
        info_offset = ehdr.e_entry & 0x3fffffff
        fin.seek(ehdr.e_phoff + ElfPhdr.Size() * segment_num)
        phdr = ElfPhdr.unpack(fin)
        fin.seek(phdr.p_offset + info_offset)
        module_info = SceModuleInfo.unpack(fin)

        import_list = []
        fin.seek(phdr.p_offset + module_info.importsTop)
        imports_off = module_info.importsTop
        while imports_off < module_info.importsEnd:
            fin.seek(phdr.p_offset+imports_off)
            size = int.from_bytes(fin.read(2), "little")
            fin.seek(-2, 1)
            if size == 0x24:
                imports = SceModuleImports2.unpack(fin)
            elif size == 0x34:
                imports = SceModuleImports.unpack(fin)
            else:
                raise Exception(f"imports wrong size {size}")
            imports_off += size

            nids = []
            entry_table_offset = imports.func_entry_table - phdr.p_vaddr
            nid_table_offset = imports.func_nid_table - phdr.p_vaddr
            fin.seek(phdr.p_offset+entry_table_offset)
            entry_data = fin.read(imports.num_functions * 4)
            fin.seek(phdr.p_offset+nid_table_offset)
            nids_data = fin.read(imports.num_functions * 4)
            for i in range(imports.num_functions):
                nid = int.from_bytes(nids_data[i*4:(i+1)*4], "little")
                func = int.from_bytes(entry_data[i*4:(i+1)*4], "little")
                nids.append(hex(nid))
            
            fin.seek(phdr.p_offset + imports.library_name - phdr.p_vaddr)
            library_name = c_str(fin.read(32))
            import_list.append({
                "name": library_name,
                "version": imports.version,
                "nid": hex(imports.library_nid),
                "funcs": nids,
            })

        info = {
            "module_name": module_info.module_name,
            "module_nid": hex(module_info.module_nid),
            "imports": import_list
        }

        print(json.dumps(info, indent=2))
