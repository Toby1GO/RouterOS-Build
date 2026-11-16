"""Build CHR local-renew disks with actual legacy/ext2 and UEFI/FAT16 boot partitions."""
import argparse, hashlib, io, json, os, subprocess, sys, tarfile, zipfile, zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from build_routeros import download, version, squash_tool, verify_official
from signing import read_keys, hex_key
from chr_certificate import generate_chr
from patch_chr_local_renew import patch_keyman
from check_chr_local_renew import run_checks
from chr_layout import partitions, replace_ext_file, fat16_boot
from dissect.extfs import ExtFS
from dissect.util.stream import RangeStream
from npk import NovaPackage, NpkPartID, NpkFileContainer


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--version',required=True)
    p.add_argument('--source-dir',type=Path,default=ROOT/'downloads')
    p.add_argument('--work-dir',type=Path,default=ROOT/'build/routeros')
    p.add_argument('--output-dir',type=Path,default=ROOT/'publish')
    p.add_argument('--keys',type=Path,default=ROOT/'.private/signing.env')
    a=p.parse_args();ver=version(a.version)
    # The renew hook uses inspected internal ABI addresses; do not apply to unknown versions.
    if ver!='7.25.1':raise ValueError('CHR local Renew currently supports 7.25.1 only; adapt and validate the keyman hook for this version before publishing CHR')
    work=a.work_dir.resolve()/ver;out=a.output_dir.resolve();src=a.source_dir.resolve()
    src.mkdir(parents=True,exist_ok=True)
    chrwork=work/'chr';chrwork.mkdir(exist_ok=True)
    disk=src/f'chr-{ver}.img'
    if not disk.exists():
        archive=src/f'chr-{ver}.img.zip'
        download(f'https://download.mikrotik.com/routeros/{ver}/{archive.name}',archive)
        with zipfile.ZipFile(archive) as z:
            names=[n for n in z.namelist() if Path(n).name==disk.name]
            if len(names)!=1:raise ValueError('Missing CHR source image')
            disk.write_bytes(z.read(names[0]))
    base=disk.read_bytes()
    if hashlib.sha256(base).hexdigest()!='42ce7e8bbcd07d3054bc1c7309540ef621e4bbead90b19defab34fccbba123af':raise ValueError('Unrecognized official CHR baseline')
    parts=list(partitions(base))
    if [x[0] for x in parts]!=['RouterOS Boot','RouterOS']:raise ValueError('Unexpected CHR partitions')
    _,bo,bs=parts[0];_,so,ss=parts[1]
    official=ExtFS(RangeStream(io.BytesIO(base),so,ss)).get('/var/pdb/system/image').open().read()
    if not verify_official(NovaPackage(official[8:])):raise ValueError('Official CHR package signature failed')
    values=read_keys(a.keys) if a.keys.exists() else os.environ
    keys={n:hex_key(values[n]) for n in ('CUSTOM_LICENSE_PRIVATE_KEY','CUSTOM_LICENSE_PUBLIC_KEY','CUSTOM_NPK_SIGN_PRIVATE_KEY','CUSTOM_NPK_SIGN_PUBLIC_KEY')}
    cert=generate_chr('AAAAAAAAAAA',keys['CUSTOM_LICENSE_PRIVATE_KEY'],0xffffffff,3)
    with tarfile.open(work/'readback.tar') as source:
        keyman=source.extractfile('./nova/bin/keyman').read()
    patched,_=patch_keyman(keyman,cert,keys['CUSTOM_LICENSE_PUBLIC_KEY'])
    for name in ('CUSTOM_LICENSE_PRIVATE_KEY','CUSTOM_NPK_SIGN_PRIVATE_KEY'):
        if keys[name] in patched or keys[name].hex().encode() in patched:raise ValueError('Unexpected private key in firmware')
    emulation=run_checks(patched,base)
    with tarfile.open(work/'readback.tar') as source,tarfile.open(chrwork/'system.tar','w') as target:
        for member in source:
            if not member.isfile():target.addfile(member);continue
            blob=source.extractfile(member).read()
            if member.name=='./nova/bin/keyman':blob=patched
            member.size=len(blob);target.addfile(member,io.BytesIO(blob))
    with (chrwork/'system.tar').open('rb') as inp:
        subprocess.run([squash_tool('tar2sqfs'),'-c','xz','-b','262144','-e','-s','-q','-f',str(chrwork/'system.sfs')],stdin=inp,check=True)
    with (chrwork/'readback.tar').open('wb') as handle:
        subprocess.run([squash_tool('sqfs2tar'),'--root-becomes','.','--no-skip',str(chrwork/'system.sfs')],stdout=handle,check=True)
    with tarfile.open(chrwork/'system.tar') as before,tarfile.open(chrwork/'readback.tar') as after:
        aa={m.name:m for m in before};bb={m.name:m for m in after}
        assert aa.keys()==bb.keys()
        for name,m in aa.items():
            for field in ('mode','uid','gid','mtime','type','linkname','devmajor','devminor'):assert getattr(m,field)==getattr(bb[name],field)
            if m.isfile():assert before.extractfile(name).read()==after.extractfile(name).read()
    pkg=NovaPackage.load(out/f'routeros-{ver}.npk')
    pkg[NpkPartID.SQUASHFS].data=(chrwork/'system.sfs').read_bytes()
    pkg.sign(keys['CUSTOM_LICENSE_PRIVATE_KEY'],keys['CUSTOM_NPK_SIGN_PRIVATE_KEY'],signature_only=True)
    pkg.save(chrwork/'system.npk');blob=(chrwork/'system.npk').read_bytes()
    assert NovaPackage(blob[8:]).verify(keys['CUSTOM_LICENSE_PUBLIC_KEY'],keys['CUSTOM_NPK_SIGN_PUBLIC_KEY'])
    kernel=next(x.data for x in NpkFileContainer.unserialize_from(pkg[NpkPartID.FILE_CONTAINER].data) if x.name==b'boot/EFI/BOOT/BOOTX64.EFI')
    assert zlib.crc32(kernel)==0xffffffff
    oldkernel=ExtFS(RangeStream(io.BytesIO(base),bo,bs)).get('/EFI/BOOT/BOOTX64.EFI').open().read()
    assert len(oldkernel)==len(kernel)
    legacy=bytearray(base)
    allowed=replace_ext_file(legacy,so,ss,'/var/pdb/system/image',blob)
    allowed+=replace_ext_file(legacy,bo,bs,'/EFI/BOOT/BOOTX64.EFI',kernel)
    restored=bytearray(legacy)
    for pos,n in allowed:restored[pos:pos+n]=base[pos:pos+n]
    assert restored==base
    uefi=bytearray(legacy);uefi[bo:bo+bs]=fat16_boot(kernel,bs,bo//512)
    assert uefi[:bo]==legacy[:bo] and uefi[bo+bs:]==legacy[bo+bs:]
    records={}
    for mode,image in [('legacy-bios',legacy),('uefi',uefi)]:
        path=out/f'chr-{ver}-{mode}.img'
        if path.exists():raise ValueError('CHR output already exists')
        path.write_bytes(image);assert path.read_bytes()==image
        records[mode]={'sha256':hashlib.sha256(image).hexdigest(),'boot_filesystem':'FAT16' if mode=='uefi' else 'ext2','runtime_verified':False}
    (out/'chr-build.json').write_text(json.dumps({'version':ver,'local_renew':'loulan/loulan','level':'p-unlimited','private_key_embedded':False,'variants':records,'system_partition_identical':True,'emulation':emulation},indent=2),encoding='utf-8')
    print('CHR legacy/UEFI disks verified; local Renew emulation passed')

if __name__=='__main__':main()
