import json
import sys
from dataclasses import dataclass

from .scetypes import (ElfHeader, ElfPhdr, SceModuleImports,
                               SceModuleImports2, SceModuleInfo, SceModuleLibaryExports)
from .util import c_str


@dataclass
class LibraryImport:
    name: str
    nid: int
    functions: list[int]
    variables: list[int]

@dataclass
class LibraryExport:
    name: str
    nid: int
    functions: list[int]
    variables: list[int]

def read_module_info(fin) -> tuple[SceModuleInfo, list[LibraryImport], list[LibraryExport]] | None:
    ehdr = ElfHeader.unpack(fin)
    if ehdr.e_machine == 0xf00d:
        return None
    segment_num = (ehdr.e_entry >> 30) & 0x3
    info_offset = ehdr.e_entry & 0x3fffffff
    fin.seek(ehdr.e_phoff + ElfPhdr._size * segment_num)
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
        
        library_name = hex(imports.library_nid)
        if imports.library_name > phdr.p_vaddr:
            fin.seek(phdr.p_offset + imports.library_name - phdr.p_vaddr)
            library_name = c_str(fin.read(32))
        
        functions = []
        variables = []
        for (entry_table, nid_table, num, arr) in (
            (imports.func_entry_table, imports.func_nid_table, imports.num_functions, functions),
            (imports.var_entry_table, imports.var_nid_table, imports.num_vars, variables)
        ):
            if entry_table == 0:
                continue
            entry_table_offset = entry_table - phdr.p_vaddr
            nid_table_offset = nid_table - phdr.p_vaddr
            fin.seek(phdr.p_offset+entry_table_offset)
            entry_data = fin.read(num * 4)
            fin.seek(phdr.p_offset+nid_table_offset)
            nids_data = fin.read(num * 4)
            for i in range(num):
                nid = int.from_bytes(nids_data[i*4:(i+1)*4], "little")
                addr = int.from_bytes(entry_data[i*4:(i+1)*4], "little")
                arr.append(nid)
        import_list.append(LibraryImport(library_name, imports.library_nid, functions, variables))

    export_list = []
    fin.seek(phdr.p_offset + module_info.exportsStart)
    exports_off = module_info.exportsStart
    while exports_off < module_info.exportsEnd:
        fin.seek(phdr.p_offset+exports_off)
        size = int.from_bytes(fin.read(1), "little")
        fin.seek(-1, 1)
        if size == 0x20:
            exports = SceModuleLibaryExports.unpack(fin)
        else:
            raise Exception(f"imports wrong size {size}")
        exports_off += size

        if exports.libname_nid == 0:
            continue

        library_name = hex(exports.libname_nid)
        if exports.libname_ptr > phdr.p_vaddr:
            fin.seek(phdr.p_offset + exports.libname_ptr - phdr.p_vaddr)
            library_name = c_str(fin.read(32))

        functions = []
        variables = []

        entry_table_offset = exports.addrtable - phdr.p_vaddr
        nid_table_offset = exports.nidtable - phdr.p_vaddr
        fin.seek(phdr.p_offset+entry_table_offset)
        num_nids = exports.nfunc + exports.nvar + exports.ntlsvar
        entry_data = fin.read(num_nids * 4)
        fin.seek(phdr.p_offset+nid_table_offset)
        nids_data = fin.read(num_nids * 4)

        for i in range(exports.nfunc):
            nid = int.from_bytes(nids_data[i*4:(i+1)*4], "little")
            addr = int.from_bytes(entry_data[i*4:(i+1)*4], "little")
            functions.append(nid)

        for i in range(exports.nfunc, exports.nfunc+exports.nvar):
            nid = int.from_bytes(nids_data[i*4:(i+1)*4], "little")
            addr = int.from_bytes(entry_data[i*4:(i+1)*4], "little")
            variables.append(nid)

        export_list.append(LibraryExport(library_name, exports.libname_nid, functions, variables))
    return module_info, import_list, export_list

def main(argv = sys.argv):
    if len(argv) < 2:
        print(f"Usage: {argv[0]} (filename)")
        sys.exit(1)
    with open(argv[1], "rb") as fin:
        info = read_module_info(fin)
        if info is None:
            print("f00d binary")
            return
        module_info, imports, exports = info
    info = {
        "module_name": module_info.module_name,
        "module_nid": hex(module_info.module_nid),
        "imports": imports
    }
    print(json.dumps(info, indent=2))

if __name__ == "__main__":
    main()
