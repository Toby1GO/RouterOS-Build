"""Exercise native offline hook and original parser/verifier in Unicorn.

Disk I/O and notification APIs are mocked; this is not a whole-device boot test.
"""
import io
import hashlib
import json
import struct
import sys
from pathlib import Path
from patch_chr_local_renew import ROOT, BASE, HOOK, CERT
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import *


def exercise(data, account='loulan', password='loulan', fault=None, disk=None):
    elf = ELFFile(io.BytesIO(data))
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    u.mem_map(0x8048000, 0x20000)
    for seg in elf.iter_segments():
        if seg.header.p_type == 'PT_LOAD':
            u.mem_write(seg.header.p_vaddr, seg.data())
    u.mem_map(0x100000, 0x200000)
    original = bytearray(disk or BASE_DISK)
    if fault == 'not_chr': original[0x150] &= 0xfe
    stored = bytearray(original)
    calls = []
    state = {'status': '', 'error': ''}
    def write_string(address, value):
        u.mem_write(address, struct.pack('<I', address+16))
        u.mem_write(address+16, struct.pack('<I',len(value))+value.encode()+b'\0')
    write_string(0x201000, account)
    write_string(0x202000, password)
    u.mem_write(0x203000, b'/dev/test\0')
    u.reg_write(UC_X86_REG_EAX, 0x200000)
    u.reg_write(UC_X86_REG_EDX, 0x201000)
    u.reg_write(UC_X86_REG_ECX, 0x202000)
    u.reg_write(UC_X86_REG_ESP, 0x1ffffc)
    u.mem_write(0x1ffffc, struct.pack('<I', 0x210000))
    for reg, value in [(UC_X86_REG_EBX,0x1234),(UC_X86_REG_ESI,0x5678),(UC_X86_REG_EDI,0x9abc),(UC_X86_REG_EBP,0xdef0)]:
        u.reg_write(reg,value)
    sy = elf.get_section_by_name('.dynsym'); plt = elf.get_section_by_name('.plt')
    imports = {plt.header.sh_addr+16*(i+1):sy.get_symbol(r.entry.r_info_sym).name
               for i,r in enumerate(elf.get_section_by_name('.rel.plt').iter_relocations())}
    def cstring(p):
        out = bytearray()
        while True:
            b = u.mem_read(p+len(out),1)[0]
            if not b: return bytes(out)
            out.append(b)
            if len(out)>10000: raise ValueError('Unbounded string')
    def hook(uc, address, size, user):
        sp = uc.reg_read(UC_X86_REG_ESP)
        eax=uc.reg_read(UC_X86_REG_EAX);edx=uc.reg_read(UC_X86_REG_EDX)
        if address == 0x804e47a:
            value = 0x203000
        elif address == 0x804ff74:
            calls.append('read')
            value = int(fault != 'read')
            content = bytes(stored)
            if fault == 'readback' and 'write' in calls: content = bytes(original)
            if value: uc.mem_write(edx, content)
        elif address == 0x8050141:
            calls.append('write'); value = int(fault != 'write')
            if value: stored[:] = uc.mem_read(edx,512)
        elif address == 0x8052ef0:
            calls.append('refresh'); value=0
        elif address in imports:
            name=imports[address]
            a,b,n = struct.unpack('<III',uc.mem_read(sp+4,12))
            if 'HTTPFetch' in name: raise AssertionError('Network operation reached')
            if name in ('memcmp','strncmp'):
                left=bytes(uc.mem_read(a,n));right=bytes(uc.mem_read(b,n))
                if name=='strncmp': left=left.split(b'\0')[0];right=right.split(b'\0')[0]
                value=(left>right)-(left<right)
            elif name=='memcpy': uc.mem_write(a,bytes(uc.mem_read(b,n)));value=a
            elif name=='memset': uc.mem_write(a,bytes([b&255])*n);value=a
            elif name=='strlen': value=len(cstring(a))
            elif name=='isupper': value=int(65<=a<=90)
            elif name=='islower': value=int(97<=a<=122)
            elif name=='_ZN6string6assignEPKc':
                state['status' if a==0x200654 else 'error']=cstring(b).decode();value=a
            elif name in ('_ZN2nv7messageC1Ev','_ZN2nv7messageD1Ev'): value=a
            elif name=='_ZN2nv7Handler12notifyChangeEjbPvRKNS_7messageE': calls.append('notify');value=0
            else: raise AssertionError(f'Unexpected import {name}')
        else: return
        ret=struct.unpack('<I',uc.mem_read(sp,4))[0]
        uc.reg_write(UC_X86_REG_EAX,value&0xffffffff)
        uc.reg_write(UC_X86_REG_ESP,sp+4)
        uc.reg_write(UC_X86_REG_EIP,ret)
    u.hook_add(UC_HOOK_CODE,hook)
    if fault=='signature':
        text=cstring(CERT);body=text.index(b'\n')+1
        replacement=b'A' if text[body+30:body+31]!=b'A' else b'B'
        u.mem_write(CERT+body+30,replacement)
    u.emu_start(HOOK,0x210000,count=20000000)
    assert u.reg_read(UC_X86_REG_EIP)==0x210000
    assert u.reg_read(UC_X86_REG_ESP)==0x200000
    for reg,value in [(UC_X86_REG_EBX,0x1234),(UC_X86_REG_ESI,0x5678),(UC_X86_REG_EDI,0x9abc),(UC_X86_REG_EBP,0xdef0)]:
        assert u.reg_read(reg)==value
    accepted=u.reg_read(UC_X86_REG_EAX)==1
    if accepted:
        assert stored[:0x110]==original[:0x110] and stored[0x150:]==original[0x150:]
        assert calls==['read','write','read','refresh','notify']
        assert not state['error'] and not state['status']
    return dict(accepted=accepted,calls=calls,**state),bytes(stored)


def check_identity(data,disk):
    # Execute the original CHR identity/level/deadline validator, not Python logic.
    elf=ELFFile(io.BytesIO(data));u=Uc(UC_ARCH_X86,UC_MODE_32)
    u.mem_map(0x8048000,0x20000);u.mem_map(0x100000,0x200000)
    for seg in elf.iter_segments():
        if seg.header.p_type=='PT_LOAD':u.mem_write(seg.header.p_vaddr,seg.data())
    u.mem_write(0x200000,disk)
    u.reg_write(UC_X86_REG_EAX,0x200000)
    u.reg_write(UC_X86_REG_EDX,0x12345678)
    u.reg_write(UC_X86_REG_ECX,0x90abcdef)
    u.reg_write(UC_X86_REG_ESP,0x1ff000)
    u.mem_write(0x1ff000,struct.pack('<III',0x210000,0x202000,0x202004))
    def compare(uc,address,size,user):
        sp=uc.reg_read(UC_X86_REG_ESP);ret,a,b,n=struct.unpack('<IIII',uc.mem_read(sp,16))
        l=bytes(uc.mem_read(a,n));r=bytes(uc.mem_read(b,n))
        uc.reg_write(UC_X86_REG_EAX,((l>r)-(l<r))&0xffffffff)
        uc.reg_write(UC_X86_REG_ESP,sp+4);uc.reg_write(UC_X86_REG_EIP,ret)
    u.hook_add(UC_HOOK_CODE,compare,begin=0x804b050,end=0x804b050)
    u.emu_start(0x804f96a,0x210000,count=20000000)
    assert u.reg_read(UC_X86_REG_EIP)==0x210000
    assert u.reg_read(UC_X86_REG_EAX)&255==1
    level,deadline=struct.unpack('<II',u.mem_read(0x202000,8))
    assert (level,deadline)==(3,0xffffffff)
    return dict(accepted=True,level=level,deadline_raw=deadline)


def run_checks(data, baseline):
    global BASE_DISK
    BASE_DISK = baseline[:512]
    cases={}
    cases['correct'],disk=exercise(data)
    assert cases['correct']['accepted']
    cases['repeat'],_=exercise(data,disk=disk)
    assert cases['repeat']['accepted']
    for name,kw in [('wrong_password',dict(password='wrong')),('wrong_account',dict(account='other')),
                    ('empty',dict(account='',password='')),('prefix',dict(account='loulanx')),
                    ('case_sensitive',dict(account='Loulan'))]:
        result,_=exercise(data,**kw);assert not result['accepted'] and not result['calls'];cases[name]=result
    for fault in ('not_chr','read','write','readback','signature'):
        result,_=exercise(data,fault=fault);assert not result['accepted'] and 'refresh' not in result['calls'];cases[fault]=result
    cases['original_identity_validator']=check_identity(data,disk)
    return dict(cases=cases,network_calls=0,storage_and_notification_apis_mocked=True,
                keyman_sha256=hashlib.sha256(data).hexdigest())
