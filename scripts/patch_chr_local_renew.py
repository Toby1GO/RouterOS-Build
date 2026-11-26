"""Version-pinned offline CHR renewal experiment; retains original signature checks."""
import hashlib
import contextlib
import io
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from elftools.elf.elffile import ELFFile
from keystone import Ks, KS_ARCH_X86, KS_MODE_32
from chr_certificate import verify_chr
from chr_profiles import profile_for, plt_imports
from patch import replace_key

BASE = 0x8058000
OFFSET = 0xf000
HOOK = 0x8051824
CERT = BASE + 0x800
EMPTY = BASE + 0x900
BAD_LOGIN = BASE + 0x910
BAD_DISK = BASE + 0x950


def patch_keyman(original, certificate, public, version='7.25.1'):
    profile = profile_for(version)
    # Normalize only the configured public key, so validation is independent of
    # the builder's signing key without accepting arbitrary code changes.
    official_public = bytes.fromhex('8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32')
    with contextlib.redirect_stdout(io.StringIO()):
        normalized = replace_key(public, official_public, original, 'keyman')
    if hashlib.sha256(normalized).hexdigest() != profile['keyman_sha256']:
        raise ValueError(f'Unrecognized {version} keyman or mismatched license public key')
    info = verify_chr(certificate, public)
    if (info['system_id'], info['deadline_raw'], info['level']) != ('AAAAAAAAAAA', 0xffffffff, 3):
        raise ValueError('Expected signed permanent CHR level 3 certificate with zero identity')
    elf = ELFFile(io.BytesIO(original))
    imports = plt_imports(elf)
    def offset(address):
        for seg in elf.iter_segments():
            if seg.header.p_type == 'PT_LOAD' and seg.header.p_vaddr <= address < seg.header.p_vaddr + seg.header.p_filesz:
                return seg.header.p_offset + address - seg.header.p_vaddr
        raise ValueError('Unmapped address')
    if original[offset(HOOK):offset(HOOK)+5] != bytes.fromhex('5589e55756'):
        raise ValueError('Unexpected renew prologue')
    if original[offset(0x8051ff7):offset(0x8051ff7)+2] != bytes.fromhex('741f'):
        raise ValueError('Unexpected permanent renewal guard')
    if elf.get_segment(7).header.p_type != 'PT_NOTE' or elf.get_segment(8).header.p_type != 'PT_GNU_PROPERTY':
        raise ValueError('Unexpected ELF headers')
    for seg in elf.iter_segments():
        if seg.header.p_type == 'PT_LOAD' and seg.header.p_vaddr + seg.header.p_memsz > BASE:
            raise ValueError('New code overlaps existing mapping')
    # Internal ABI: eax=context, edx=account string*, ecx=password string*.
    # RouterOS strings point to {uint32 length; char text[]}. Check lengths first.
    # Every unsuccessful path returns false; no HTTP operation is dispatched.
    source = f'''
        push ebp
        mov ebp, esp
        push edi
        push esi
        push ebx
        sub esp, 0x42c
        mov ebx, eax
        mov edx, [edx]
        mov ecx, [ecx]
        cmp dword ptr [edx], 6
        jne bad_login
        cmp dword ptr [ecx], 6
        jne bad_login
        cmp dword ptr [edx+4], 0x6c756f6c
        jne bad_login
        cmp word ptr [edx+8], 0x6e61
        jne bad_login
        cmp dword ptr [ecx+4], 0x6c756f6c
        jne bad_login
        cmp word ptr [ecx+8], 0x6e61
        jne bad_login
        call 0x804e47a
        mov edi, eax
        lea esi, [ebp-0x218]
        mov edx, esi
        call 0x804ff74
        test al, al
        jz bad_disk
        mov eax, esi
        call 0x804d9fb
        test al, al
        jz bad_disk
        mov eax, edi
        mov edx, esi
        mov ecx, {CERT}
        call 0x80511c0
        test eax, eax
        jnz bad_disk
        mov eax, edi
        mov edx, esi
        call 0x8050141
        test al, al
        jz bad_disk
        mov eax, edi
        lea edx, [ebp-0x418]
        call 0x804ff74
        test al, al
        jz bad_disk
        sub esp, 4
        push 512
        lea eax, [ebp-0x418]
        push eax
        push esi
        call {imports['memcmp']}
        add esp, 16
        test eax, eax
        jnz bad_disk
        sub esp, 8
        push {EMPTY}
        lea eax, [ebx+{profile['status_offset']}]
        push eax
        call {imports['_ZN6string6assignEPKc']}
        add esp, 16
        sub esp, 8
        push {EMPTY}
        lea eax, [ebx+{profile['error_offset']}]
        push eax
        call {imports['_ZN6string6assignEPKc']}
        add esp, 16
        mov eax, ebx
        xor edx, edx
        call 0x8052ef0
        sub esp, 12
        lea esi, [ebp-0x438]
        push esi
        call {imports['_ZN2nv7messageC1Ev']}
        add esp, 16
        sub esp, 12
        push esi
        push 0
        push 0
        push -1
        push ebx
        call {imports['_ZN2nv7Handler12notifyChangeEjbPvRKNS_7messageE']}
        add esp, 32
        sub esp, 12
        push esi
        call {imports['_ZN2nv7messageD1Ev']}
        add esp, 16
        mov eax, 1
        jmp finish
    bad_login:
        mov esi, {BAD_LOGIN}
        jmp failure
    bad_disk:
        mov esi, {BAD_DISK}
    failure:
        sub esp, 8
        push {EMPTY}
        lea eax, [ebx+{profile['status_offset']}]
        push eax
        call {imports['_ZN6string6assignEPKc']}
        add esp, 16
        sub esp, 8
        push esi
        lea eax, [ebx+{profile['error_offset']}]
        push eax
        call {imports['_ZN6string6assignEPKc']}
        add esp, 16
        xor eax, eax
    finish:
        lea esp, [ebp-12]
        pop ebx
        pop esi
        pop edi
        pop ebp
        ret
    '''
    code = bytes(Ks(KS_ARCH_X86, KS_MODE_32).asm(source, addr=BASE)[0])
    assert len(code) < 0x800 and len(original) <= OFFSET
    added = bytearray(code.ljust(0x980, b'\0'))
    for address, content in [(CERT, certificate.encode('ascii') + b'\0'),
                             (BAD_LOGIN, b'ERROR: invalid local account or password\0'),
                             (BAD_DISK, b'ERROR: local CHR license could not be saved\0')]:
        start = address - BASE
        added[start:start+len(content)] = content
    output = bytearray(original.ljust(OFFSET, b'\0')) + added
    output[offset(HOOK):offset(HOOK)+5] = b'\xe9' + struct.pack('<i', BASE-HOOK-5)
    # The transport is now offline and idempotent, including after first activation.
    output[offset(0x8051ff7)] = 0xeb
    struct.pack_into('<IIIIIIII', output, elf.header.e_phoff + 7*elf.header.e_phentsize,
                     1, OFFSET, BASE, BASE, len(added), len(added), 5, 4096)
    return bytes(output), source
