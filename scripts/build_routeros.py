"""Download official x86 RouterOS, patch, verify, and emit release assets."""
import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import pycdlib
from license import read_keys, hex_key, public_from_private
from npk import NovaPackage, NpkPartID, NpkFileContainer
from patch import replace_key, patch_kernel
from img import Fat16Image
from image_layout import update_root_file
from loader_patch import patch_loader
from mikro import mikro_eddsa_verify

OFFICIAL_LICENSE = bytes.fromhex('8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32')
OFFICIAL_NPK = bytes.fromhex('C293CED638A2A33C681FC8DE98EE26C54EADC5390C2DFCE197D35C83C416CF59')


def verify_official(package):
    # Official v7 EdDSA signs the SHA256 digest. The local KCDSA verifier is
    # designed for custom signatures and does not accept all vendor signatures.
    sig = package[NpkPartID.SIGNATURE].data
    return (len(sig) == 132 and sig[:20] == package.get_digest(hashlib.sha1())
            and mikro_eddsa_verify(package.get_digest(hashlib.sha256()), sig[68:132], OFFICIAL_NPK))


def version(value):
    if not re.fullmatch(r'7\.\d+(?:\.\d+)?(?:(?:beta|rc)\d+)?', value):
        raise ValueError('Expected RouterOS 7 version, e.g. 7.25.1')
    return value


def resolve_version(value, channel):
    if value:
        return version(value)
    with urllib.request.urlopen('https://upgrade.mikrotik.com/routeros/upgrade.json', timeout=60) as response:
        data = json.load(response)
    return version(data['upgradePaths']['NEWESTa7.' + channel]['version'])


def download(url, path):
    if path.exists():
        return
    with urllib.request.urlopen(url, timeout=120) as source, path.with_suffix(path.suffix+'.part').open('wb') as target:
        shutil.copyfileobj(source, target)
    path.with_suffix(path.suffix+'.part').replace(path)


def iso_files(path):
    iso = pycdlib.PyCdlib()
    iso.open(str(path))
    files, offsets = {}, {}
    try:
        for parent, _, names in iso.walk(rr_path='/'):
            for name in names:
                key = parent.rstrip('/') + '/' + name
                buffer = io.BytesIO()
                iso.get_file_from_iso_fp(buffer, rr_path=key)
                files[key] = buffer.getvalue()
                offsets[key] = iso.get_record(rr_path=key).extent_location()
    finally:
        iso.close()
    return files, offsets


def squash_tool(name):
    found = shutil.which(name)
    if found:
        return found
    bundled = ROOT/'.local-tools/analysis-tools/squashfs/squashfs-tools-ng-1.3.2-mingw64/bin'/f'{name}.exe'
    if bundled.exists():
        return str(bundled)
    raise RuntimeError(f'Missing {name}; install squashfs-tools-ng')


def patch_filesystem(blob, pairs, work):
    (work/'source.sfs').write_bytes(blob)
    with (work/'source.tar').open('wb') as out:
        subprocess.run([squash_tool('sqfs2tar'), '--root-becomes', '.', '--no-skip', str(work/'source.sfs')], stdout=out, check=True)
    changes = {}
    required = {'nova/bin/loader', 'nova/bin/keyman', 'nova/bin/mode'}
    with tarfile.open(work/'source.tar') as source, tarfile.open(work/'patched.tar', 'w') as target:
        for member in source:
            if not member.isfile():
                target.addfile(member)
                continue
            original = source.extractfile(member).read()
            name = member.name.removeprefix('./')
            patched = original
            if name == 'nova/bin/loader':
                patched = patch_loader(original, work)
            else:
                for old, new in pairs.items():
                    patched = replace_key(old, new, patched, name)
                # Keep custom builds from installing incompatible official updates.
                patched = patched.replace(b'upgrade.mikrotik.com', b'no-updatesx.invalid.')
            if name in required:
                if original == patched:
                    raise ValueError(f'Required patch was not applied: {name}')
                required.remove(name)
            if patched != original:
                changes[member.name] = patched
            member = copy.copy(member)
            member.size = len(patched)
            target.addfile(member, io.BytesIO(patched))
    if required:
        raise ValueError(f'Missing required binaries: {sorted(required)}')
    with (work/'patched.tar').open('rb') as inp:
        subprocess.run([squash_tool('tar2sqfs'), '-c', 'xz', '-b', '262144', '-e', '-s', '-q', '-f', str(work/'patched.sfs')], stdin=inp, check=True)
    with (work/'readback.tar').open('wb') as out:
        subprocess.run([squash_tool('sqfs2tar'), '--root-becomes', '.', '--no-skip', str(work/'patched.sfs')], stdout=out, check=True)
    with tarfile.open(work/'source.tar') as before, tarfile.open(work/'readback.tar') as after:
        a, b = {m.name: m for m in before}, {m.name: m for m in after}
        if a.keys() != b.keys():
            raise ValueError('Filesystem inventory changed')
        for name, item in a.items():
            for field in ('mode','uid','gid','mtime','type','linkname','devmajor','devminor'):
                if getattr(item, field) != getattr(b[name], field):
                    raise ValueError(f'Filesystem metadata changed: {name}/{field}')
            if item.isfile() and after.extractfile(name).read() != changes.get(name, before.extractfile(name).read()):
                raise ValueError(f'Filesystem readback mismatch: {name}')
    return (work/'patched.sfs').read_bytes(), sorted(changes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='')
    parser.add_argument('--channel', choices=['stable','long-term','testing','development'], default='stable')
    parser.add_argument('--resolve-only', action='store_true')
    parser.add_argument('--keys', type=Path, default=ROOT/'.private/signing.env')
    parser.add_argument('--source-dir', type=Path, default=ROOT/'downloads')
    parser.add_argument('--output-dir', type=Path, default=ROOT/'publish')
    parser.add_argument('--work-dir', type=Path, default=ROOT/'build/routeros')
    args = parser.parse_args()
    ver = resolve_version(args.version, args.channel)
    if args.resolve_only:
        print(ver)
        return
    key_names = ('CUSTOM_LICENSE_PRIVATE_KEY','CUSTOM_LICENSE_PUBLIC_KEY','CUSTOM_NPK_SIGN_PRIVATE_KEY','CUSTOM_NPK_SIGN_PUBLIC_KEY')
    values = read_keys(args.keys) if args.keys.exists() else os.environ
    keys = {name: hex_key(values[name]) for name in key_names}
    if public_from_private(keys[key_names[0]]) != keys[key_names[1]]:
        raise ValueError('License key pair mismatch')
    pairs = {OFFICIAL_LICENSE: keys[key_names[1]], OFFICIAL_NPK: keys[key_names[3]]}
    out, work, src = args.output_dir.resolve(), args.work_dir.resolve()/ver, args.source_dir.resolve()
    for folder in (out, work, src):
        folder.mkdir(parents=True, exist_ok=True)
    output_iso, output_img = out/f'mikrotik-{ver}-custom.iso', out/f'install-image-{ver}-custom.img'
    if output_iso.exists() or output_img.exists():
        raise ValueError('Output already exists; choose a fresh output directory')
    source_iso, source_img = src/f'mikrotik-{ver}.iso', src/f'install-image-{ver}.img'
    download(f'https://download.mikrotik.com/routeros/{ver}/{source_iso.name}', source_iso)
    if not source_img.exists():
        import zipfile
        archive = src/f'install-image-{ver}.zip'
        download(f'https://download.mikrotik.com/routeros/{ver}/{archive.name}', archive)
        with zipfile.ZipFile(archive) as zipped:
            matches = [n for n in zipped.namelist() if Path(n).name == source_img.name]
            if len(matches) != 1:
                raise ValueError('Missing or ambiguous installer image')
            with zipped.open(matches[0]) as inp, source_img.open('xb') as handle:
                shutil.copyfileobj(inp, handle)
    files, positions = iso_files(source_iso)
    replacements, packages = {}, {}
    kernel = files['/isolinux/linux']
    new_kernel = bytes(patch_kernel(kernel, pairs))
    if new_kernel == kernel or len(new_kernel) != len(kernel) or zlib.crc32(new_kernel) != 0xffffffff:
        raise ValueError('Kernel patch/size/CRC check failed')
    changes = []
    for path, blob in files.items():
        if not path.endswith('.npk'):
            continue
        package = NovaPackage(blob[8:])
        if not verify_official(package):
            raise ValueError(f'Official NPK signature check failed: {path}')
        info = package[NpkPartID.NAME_INFO].data
        if info.version != ver or info.name in packages:
            raise ValueError('Unexpected package identity')
        if info.name == 'system':
            container = NpkFileContainer.unserialize_from(package[NpkPartID.FILE_CONTAINER].data)
            kernels = [item for item in container if item.name == b'boot/EFI/BOOT/BOOTX64.EFI']
            if len(kernels) != 1 or kernels[0].data != kernel:
                raise ValueError('Installed and installer kernels differ')
            kernels[0].data = new_kernel
            package[NpkPartID.FILE_CONTAINER].data = container.serialize()
            package[NpkPartID.SQUASHFS].data, changes = patch_filesystem(package[NpkPartID.SQUASHFS].data, pairs, work)
        package.sign(keys[key_names[0]], keys[key_names[2]], signature_only=True)
        target = out/Path(path).name
        package.save(target)
        if not NovaPackage.load(target).verify(keys[key_names[1]], keys[key_names[3]]):
            raise ValueError('NPK signature verification failed')
        packages[info.name] = target.read_bytes()
        replacements[path] = packages[info.name]
    if 'system' not in packages:
        raise ValueError('System package missing')
    replacements['/isolinux/linux'] = new_kernel
    if files['/efiboot.img'].count(kernel) != 1:
        raise ValueError('Unsupported EFI kernel layout')
    replacements['/efiboot.img'] = files['/efiboot.img'].replace(kernel, new_kernel)
    for path, blob in replacements.items():
        if (len(blob)+2047)//2048 > (len(files[path])+2047)//2048:
            raise ValueError(f'Insufficient ISO allocation: {path}')
    shutil.copyfile(source_iso, output_iso)
    with pycdlib.InPlaceEditor(str(output_iso)) as editor:
        for path, blob in replacements.items():
            if len(blob) != len(files[path]):
                editor.modify_file(io.BytesIO(blob), len(blob), rr_path=path)
    with output_iso.open('r+b') as handle:
        for path, blob in replacements.items():
            if len(blob) == len(files[path]):
                handle.seek(positions[path]*2048)
                handle.write(blob)
    checked, offsets = iso_files(output_iso)
    if offsets != positions or checked.keys() != files.keys():
        raise ValueError('ISO layout changed')
    for path, blob in checked.items():
        if blob != replacements.get(path, files[path]):
            raise ValueError(f'ISO readback mismatch: {path}')
    original = source_img.read_bytes()
    fs, image = Fat16Image(original), bytearray(original)
    image_changes = {'LINUX':new_kernel}
    for entry in fs.files:
        if entry['path'].endswith('.NPK'):
            package = NovaPackage(fs.read(entry)[8:])
            if not verify_official(package):
                raise ValueError('Official IMG package signature check failed')
            info = package[NpkPartID.NAME_INFO].data
            if info.version != ver:
                raise ValueError('IMG package version mismatch')
            image_changes[entry['path']] = packages[info.name]
    for name, blob in image_changes.items():
        update_root_file(image, name, blob)
    if image[:fs.fat_offset] != original[:fs.fat_offset] or image[fs.volume_size:] != original[fs.volume_size:]:
        raise ValueError('IMG boot/trailing area changed')
    output_img.write_bytes(image)
    actual = Fat16Image(output_img.read_bytes())
    before = {entry['path']: fs.read(entry) for entry in fs.files}
    after = {entry['path']: actual.read(entry) for entry in actual.files}
    if before.keys() != after.keys() or any(blob != image_changes.get(name,before[name]) for name,blob in after.items()):
        raise ValueError('IMG readback mismatch')
    report = {'version':ver,'architecture':'x86','runtime_verified':False,'source_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (source_iso,source_img)},'filesystem_changes':changes,'npks_verified':len(packages),'iso_img_readback_verified':True,'note':'Static checks passed; new versions still require boot and activation testing.'}
    (out/'build.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    artifacts = sorted(p for p in out.iterdir() if p.is_file() and p.name != 'SHA256SUMS')
    (out/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in artifacts),encoding='ascii')
    print(json.dumps(report,indent=2))


if __name__ == '__main__':
    main()
