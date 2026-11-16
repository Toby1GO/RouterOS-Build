"""Locate the existing x86 loader import patch by ELF structure; reject unknown layouts."""
import io
import struct
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

def patch_loader(original, work):
    elf = ELFFile(io.BytesIO(original))
    if elf.elfclass != 32 or not elf.little_endian or elf.header.e_machine != 'EM_386' or elf.header.e_type != 'ET_EXEC':
        raise ValueError('Unsupported loader ELF architecture or type')
    syms = elf.get_section_by_name('.dynsym')
    slots = [r.entry.r_offset for r in elf.get_section_by_name('.rel.plt').iter_relocations()
             if syms.get_symbol(r.entry.r_info_sym).name == 'memcmp']
    if len(slots) != 1:
        raise ValueError('Unexpected memcmp relocation')
    loads = [s for s in elf.iter_segments() if s.header.p_type == 'PT_LOAD']
    if not any(s.header.p_flags & 2 and s.header.p_vaddr <= slots[0] and slots[0] + 4 <= s.header.p_vaddr + s.header.p_memsz for s in loads):
        raise ValueError('Import slot is not writable')
    if not any(s.header.p_flags & 1 and s.header.p_vaddr <= elf.header.e_entry < s.header.p_vaddr + s.header.p_memsz for s in loads):
        raise ValueError('Entry is not executable')
    file_offset = (len(original) + 4095) & ~4095
    address = (max(s.header.p_vaddr + s.header.p_memsz for s in loads) + 4095) & ~4095
    notes = [i for i, s in enumerate(elf.iter_segments()) if s.header.p_type == 'PT_NOTE']
    if len(notes) != 1 or elf.header.e_phentsize != 32:
        raise ValueError('No unique reusable PT_NOTE header')
    note_index = notes[0]
    # Preserve all original registers/flags, redirect this loader's imported memcmp,
    # then resume the untouched original ELF entry. No native OS calls are added.
    code = (b'\x9c\x60\xc7\x05' + struct.pack('<II', slots[0], address + 32)
            + b'\x61\x9d\x68' + struct.pack('<I', elf.header.e_entry) + b'\xc3')
    code = code.ljust(32, b'\x90') + b'\x31\xc0\xc3'
    note = elf.get_segment(note_index)
    if note.header.p_type != 'PT_NOTE':
        raise ValueError('Expected replaceable PT_NOTE')
    # PT_GNU_PROPERTY and the existing section record still retain GNU properties.
    if not any(s.header.p_type == 'PT_GNU_PROPERTY' for s in elf.iter_segments()):
        raise ValueError('Expected independently preserved GNU properties')
    for segment in elf.iter_segments():
        if segment.header.p_type == 'PT_LOAD':
            assert segment.header.p_vaddr + segment.header.p_memsz <= address
    output = bytearray(original.ljust(file_offset, b'\0')) + code
    struct.pack_into('<I', output, 24, address)
    struct.pack_into('<IIIIIIII', output, elf.header.e_phoff + note_index * elf.header.e_phentsize,
                     1, file_offset, address, address, len(code), len(code), 5, 4096)
    for section in elf.iter_sections():
        if section.header.sh_type != 'SHT_NOBITS':
            off, size = section.header.sh_offset, section.header.sh_size
            assert output[off:off+size] == original[off:off+size]
    (work / 'loader.patched').write_bytes(output)
    (work / 'loader.entry.asm').write_text('\n'.join(
        f'{ins.address:08x}: {ins.bytes.hex():24s} {ins.mnemonic} {ins.op_str}'
        for ins in Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, address)), encoding='utf-8')
    return bytes(output)
