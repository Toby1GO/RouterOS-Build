"""Update root files in the RouterOS FAT16 installer without relocating boot areas."""
import struct
from img import Fat16Image, replace_file_bytes

def update_root_file(image, name, payload):
    fs = Fat16Image(image)
    target = next(f for f in fs.files if f['path'] == name)
    old = [(start-fs.data_offset)//fs.cluster_size+2 for start, size in target['spans']]
    need = (len(payload)+fs.cluster_size-1)//fs.cluster_size
    selected = old[:need]
    if len(selected) < need:
        for cluster in range(2, fs.cluster_count+2):
            if struct.unpack_from('<H',fs.fat,cluster*2)[0] == 0:
                selected.append(cluster)
                if len(selected) == need:
                    break
    if len(selected) != need:
        raise ValueError('Insufficient FAT space')
    fats = image[16]
    fat_bytes = struct.unpack_from('<H',image,22)[0]*fs.sector
    for index in range(fats):
        for cluster in old[need:]:
            struct.pack_into('<H',image,fs.fat_offset+index*fat_bytes+cluster*2,0)
        for index2, cluster in enumerate(selected):
            nxt = selected[index2+1] if index2+1<len(selected) else 0xffff
            struct.pack_into('<H',image,fs.fat_offset+index*fat_bytes+cluster*2,nxt)
    spans = fs.extents(selected,len(payload))
    replace_file_bytes(image,spans,0,payload)
    for pos in range(fs.root_offset,fs.data_offset,32):
        raw = image[pos:pos+32]
        if raw[0] == 0: break
        n = raw[:8].decode('ascii',errors='replace').rstrip()
        ext = raw[8:11].decode('ascii',errors='replace').rstrip()
        if n + ('.'+ext if ext else '') == name:
            struct.pack_into('<H',image,pos+26,selected[0])
            struct.pack_into('<I',image,pos+28,len(payload))
            break
    else:
        raise ValueError('Root entry not found')
    checked = Fat16Image(image)
    assert checked.read(next(f for f in checked.files if f['path']==name)) == payload

