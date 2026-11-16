"""Emulate the loader entry trampoline without executing RouterOS natively."""
import io
from pathlib import Path
import struct
import sys
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EFLAGS, UC_X86_REG_EIP
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from loader_patch import patch_loader


def check(original, work):
    data = patch_loader(original, work)
    elf, old = ELFFile(io.BytesIO(data)), ELFFile(io.BytesIO(original))
    syms = elf.get_section_by_name('.dynsym')
    slot = next(r.entry.r_offset for r in elf.get_section_by_name('.rel.plt').iter_relocations() if syms.get_symbol(r.entry.r_info_sym).name == 'memcmp')
    for flags in (0x202, 0x246, 0x293):
        u = Uc(UC_ARCH_X86, UC_MODE_32)
        loads = [s for s in elf.iter_segments() if s.header.p_type == 'PT_LOAD']
        base = min(s.header.p_vaddr for s in loads) & ~4095
        end = (max(s.header.p_vaddr+s.header.p_memsz for s in loads)+4095) & ~4095
        u.mem_map(base, end-base)
        u.mem_map(0x100000, 0x10000)
        for seg in loads:
            u.mem_write(seg.header.p_vaddr, seg.data())
        regs = {UC_X86_REG_EAX:0x123, UC_X86_REG_EBX:0x234, UC_X86_REG_ECX:0x345, UC_X86_REG_EDX:0x456, UC_X86_REG_ESI:0x567, UC_X86_REG_EDI:0x678, UC_X86_REG_EBP:0x789, UC_X86_REG_ESP:0x108000}
        for reg,val in regs.items():
            u.reg_write(reg,val)
        u.reg_write(UC_X86_REG_EFLAGS,flags)
        u.emu_start(elf.header.e_entry,old.header.e_entry,count=20)
        assert u.reg_read(UC_X86_REG_EIP) == old.header.e_entry
        assert all(u.reg_read(r) == v for r,v in regs.items())
        assert u.reg_read(UC_X86_REG_EFLAGS) == flags
        comparator = struct.unpack('<I',u.mem_read(slot,4))[0]
        assert comparator == elf.header.e_entry+32
        u.mem_write(0x108000,struct.pack('<IIII',0x100000,0x100100,0x100200,4))
        u.mem_write(0x100100,b'AAAA')
        u.mem_write(0x100200,b'BBBB')
        u.emu_start(comparator,0x100000,count=5)
        assert u.reg_read(UC_X86_REG_EAX) == 0
    print('PASS: loader register/flags/stack preservation, original entry, comparator (3 cases)')


if __name__ == '__main__':
    check(Path(sys.argv[1]).read_bytes(), Path(sys.argv[1]).resolve().parent)
