"""CHR boot filesystem construction and allocated ext-file replacement."""
import io
import struct
from dissect.extfs import ExtFS
from dissect.util.stream import RangeStream
from img import Fat16Image

def partitions(data):
    header=data[512:1024]
    if header[:8]!=b'EFI PART':raise ValueError('Expected GPT')
    start,count,size=struct.unpack_from('<QII',header,72)
    for i in range(count):
        entry=data[start*512+i*size:start*512+(i+1)*size]
        if entry[:16]==bytes(16):continue
        first,last=struct.unpack_from('<QQ',entry,32)
        yield entry[56:].decode('utf-16-le').rstrip('\0'),first*512,(last-first+1)*512


def fat16_boot(kernel, size, start_lba):
    sector, spc, reserved, fats, root_entries = 512, 2, 1, 2, 512
    total = size//sector
    fat_sectors = 1
    while True:
        clusters = (total-reserved-fats*fat_sectors-32)//spc
        required = ((clusters+2)*2+511)//512
        if required <= fat_sectors: break
        fat_sectors = required
    assert 4085 <= clusters < 65525
    data_start = (reserved+fats*fat_sectors+32)*sector
    root_start = (reserved+fats*fat_sectors)*sector
    volume = bytearray(size)
    volume[:11] = b'\xeb\x3c\x90MSDOS5.0'
    struct.pack_into('<HBHBHHBHHHII', volume, 11, sector, spc, reserved, fats,
                     root_entries, total if total<65536 else 0, 0xf8, fat_sectors,
                     63, 255, start_lba, total if total>=65536 else 0)
    volume[36:39] = b'\x80\0\x29'
    struct.pack_into('<I',volume,39,0x72510003)
    volume[43:54] = b'BOOT       '
    volume[54:62] = b'FAT16   '
    volume[510:512] = b'\x55\xaa'
    fat = bytearray(fat_sectors*sector)
    struct.pack_into('<HHHH', fat, 0, 0xfff8, 0xffff, 0xffff, 0xffff)
    count = (len(kernel)+sector*spc-1)//(sector*spc)
    assert count+2<=clusters
    for i in range(count):struct.pack_into('<H',fat,(i+4)*2,0xffff if i==count-1 else i+5)
    for i in range(fats):volume[(reserved+i*fat_sectors)*sector:(reserved+(i+1)*fat_sectors)*sector] = fat
    def entry(name, attr, cluster, length=0):
        row=bytearray(32);row[:11]=name;row[11]=attr
        struct.pack_into('<H',row,24,0x5d6e)  # 2026-11-14
        struct.pack_into('<HI',row,26,cluster,length)
        return row
    volume[root_start:root_start+32] = entry(b'BOOT       ',8,0)
    volume[root_start+32:root_start+64] = entry(b'EFI        ',16,2)
    for cluster,parent,child in [(2,0,entry(b'BOOT       ',16,3)),(3,2,entry(b'BOOTX64 EFI',32,4,len(kernel)))]:
        pos=data_start+(cluster-2)*sector*spc
        volume[pos:pos+96] = entry(b'.          ',16,cluster)+entry(b'..         ',16,parent)+child
    pos=data_start+2*sector*spc
    volume[pos:pos+len(kernel)] = kernel
    parsed=Fat16Image(volume)
    assert len(parsed.files)==1 and parsed.files[0]['path']=='EFI/BOOT/BOOTX64.EFI'
    assert parsed.read(parsed.files[0])==kernel
    return volume


def replace_ext_file(image, offset, length, path, blob):
    fs=ExtFS(RangeStream(io.BytesIO(image),offset,length))
    if fs.sb.s_feature_ro_compat & (0x400|0x10):
        raise ValueError("Unsupported ext filesystem checksums")
    node=fs.get(path);old=node.open().read()
    assert len(blob)<=len(old)
    payload=blob+bytes(len(old)-len(blob));cursor=0;allowed=[]
    for block,count in node.dataruns():
        assert block is not None
        n=min(count*fs.block_size,len(payload)-cursor)
        if not n:break
        pos=offset+block*fs.block_size
        image[pos:pos+n]=payload[cursor:cursor+n];allowed.append((pos,n));cursor+=n
    assert cursor==len(payload)
    group,index=divmod(node.inum-1,fs.sb.s_inodes_per_group)
    desc=fs._read_group_desc(group)
    inode=offset+desc.bg_inode_table_lo*fs.block_size+index*fs.sb.s_inode_size
    assert struct.unpack_from('<I',image,inode+4)[0]==len(old)
    if len(blob)!=len(old):
        struct.pack_into('<I',image,inode+4,len(blob));allowed.append((inode+4,4))
    readback=ExtFS(RangeStream(io.BytesIO(image),offset,length))
    assert readback.get(path).open().read()==blob
    return allowed

