"""Inspect or re-sign NPKs inside an unpartitioned FAT16 installer IMG.

Signature-only operation: does not patch boot code or trusted public keys.
Partitioned CHR disks and other filesystem types are deliberately unsupported.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from license import read_keys, hex_key, DEFAULT_KEYS
from npk import NovaPackage


class Fat16Image:
    def __init__(self, data):
        self.data = data
        if len(data) < 512 or data[510:512] != b'\x55\xaa':
            raise ValueError('Not a supported FAT16 installer image: missing boot signature')
        if data[54:62] != b'FAT16   ':
            raise ValueError('Only unpartitioned FAT16 installers are supported; this may be a CHR disk')
        self.sector = struct.unpack_from('<H', data, 11)[0]
        self.sectors_per_cluster = data[13]
        reserved = struct.unpack_from('<H', data, 14)[0]
        fats = data[16]
        root_entries = struct.unpack_from('<H', data, 17)[0]
        sectors = struct.unpack_from('<H', data, 19)[0] or struct.unpack_from('<I', data, 32)[0]
        fat_sectors = struct.unpack_from('<H', data, 22)[0]
        if (self.sector not in (512, 1024, 2048, 4096) or
                self.sectors_per_cluster not in (1, 2, 4, 8, 16, 32, 64, 128) or
                not reserved or fats not in (1, 2) or not root_entries or not fat_sectors):
            raise ValueError('Unsupported FAT16 geometry')
        self.cluster_size = self.sector * self.sectors_per_cluster
        self.volume_size = sectors * self.sector
        self.fat_offset = reserved * self.sector
        fat_bytes = fat_sectors * self.sector
        self.root_offset = self.fat_offset + fats * fat_bytes
        root_sectors = (root_entries * 32 + self.sector - 1) // self.sector
        self.data_offset = self.root_offset + root_sectors * self.sector
        self.cluster_count = (self.volume_size - self.data_offset) // self.cluster_size
        if (self.volume_size > len(data) or not 4085 <= self.cluster_count < 65525 or
                (self.cluster_count + 2) * 2 > fat_bytes):
            raise ValueError('Invalid or truncated FAT16 volume')
        self.fat = data[self.fat_offset:self.fat_offset + fat_bytes]
        for copy_index in range(1, fats):
            start = self.fat_offset + copy_index * fat_bytes
            if data[start:start + fat_bytes] != self.fat:
                raise ValueError('FAT copies disagree')
        self.files = []
        self.owners = {}
        self.directories = set()
        self.walk(data[self.root_offset:self.root_offset + root_entries * 32], '')

    def chain(self, first, owner):
        clusters = []
        seen = set()
        current = first
        while current < 0xfff8:
            if current < 2 or current >= self.cluster_count + 2 or current >= 0xfff0 or current in seen:
                raise ValueError(f'Invalid or cyclic cluster chain: {owner}')
            if current in self.owners:
                raise ValueError(f'Cross-linked files: {owner} and {self.owners[current]}')
            seen.add(current)
            self.owners[current] = owner
            clusters.append(current)
            current = struct.unpack_from('<H', self.fat, current * 2)[0]
        return clusters

    def extents(self, clusters, size):
        if size > len(clusters) * self.cluster_size:
            raise ValueError('File exceeds its allocated clusters')
        spans = []
        for cluster in clusters:
            if not size:
                break
            start = self.data_offset + (cluster - 2) * self.cluster_size
            length = min(self.cluster_size, size)
            spans.append((start, length))
            size -= length
        return spans

    def walk(self, directory, prefix):
        if len(prefix.split('/')) > 32:
            raise ValueError('Directory nesting exceeds safety limit')
        for offset in range(0, len(directory), 32):
            entry = directory[offset:offset + 32]
            if len(entry) != 32 or entry[0] == 0:
                break
            if entry[0] == 0xe5 or entry[11] == 0x0f or entry[11] & 8:
                continue
            base = entry[:8].decode('ascii', errors='replace').rstrip()
            extension = entry[8:11].decode('ascii', errors='replace').rstrip()
            if base in ('.', '..'):
                continue
            name = prefix + base + ('.' + extension if extension else '')
            first = struct.unpack_from('<H', entry, 26)[0]
            size = struct.unpack_from('<I', entry, 28)[0]
            is_directory = bool(entry[11] & 16)
            if first == 0 and size == 0 and not is_directory:
                clusters = []
            else:
                clusters = self.chain(first, name)
            if is_directory:
                spans = self.extents(clusters, len(clusters) * self.cluster_size)
                self.walk(b''.join(self.data[s:s+n] for s, n in spans), name + '/')
            else:
                self.files.append(dict(path=name, size=size, spans=self.extents(clusters, size)))

    def read(self, entry):
        return b''.join(self.data[start:start+size] for start, size in entry['spans'])


def npk_signature_ranges(blob):
    if len(blob) < 8 or struct.unpack_from('<II', blob) != (NovaPackage.NPK_MAGIC, len(blob)-8):
        raise ValueError('Invalid embedded NPK header')
    ranges = []
    offset = 8
    while offset < len(blob):
        if offset + 6 > len(blob):
            raise ValueError('Truncated NPK part header')
        kind, size = struct.unpack_from('<HI', blob, offset)
        offset += 6
        if offset + size > len(blob):
            raise ValueError('Truncated NPK part')
        if kind == 9:
            if size != 132:
                raise ValueError('Only 132-byte NPK signatures are supported')
            ranges.append((offset, size))
        offset += size
    if not ranges:
        raise ValueError('NPK has no signatures')
    return ranges


def replace_file_bytes(image, spans, offset, replacement):
    consumed = 0
    for start, length in spans:
        if offset >= length:
            offset -= length
            continue
        amount = min(length-offset, len(replacement)-consumed)
        image[start+offset:start+offset+amount] = replacement[consumed:consumed+amount]
        consumed += amount
        offset = 0
        if consumed == len(replacement):
            return
    raise ValueError('Replacement exceeds embedded file')


def resign(data, keys):
    source = Fat16Image(data)
    output = bytearray(data)
    results = []
    private = hex_key(keys['CUSTOM_LICENSE_PRIVATE_KEY'])
    npk_private = hex_key(keys['CUSTOM_NPK_SIGN_PRIVATE_KEY'])
    public = hex_key(keys['CUSTOM_LICENSE_PUBLIC_KEY'])
    npk_public = hex_key(keys['CUSTOM_NPK_SIGN_PUBLIC_KEY'])
    for entry in source.files:
        if not entry['path'].lower().endswith('.npk'):
            continue
        blob = source.read(entry)
        ranges = npk_signature_ranges(blob)
        package = NovaPackage(blob[8:])
        package.sign(private, npk_private, signature_only=True)
        if not package.verify(public, npk_public):
            raise ValueError('Signing keys do not match verification keys')
        # Copy signature slots only: never reserialize filesystem data or boot sectors.
        owners = package._packages or [package]
        signatures = [part.data for owner in owners for part in owner._parts if part.id.value == 9]
        if len(signatures) != len(ranges):
            raise ValueError('Unsupported nested signature layout')
        expected = bytearray(blob)
        for (offset, size), signature in zip(ranges, signatures):
            if len(signature) != size:
                raise ValueError('Signature length changed')
            replace_file_bytes(output, entry['spans'], offset, signature)
            expected[offset:offset+size] = signature
        reread = b''.join(output[start:start+size] for start, size in entry['spans'])
        if reread != expected or not NovaPackage(reread[8:]).verify(public, npk_public):
            raise ValueError('Embedded NPK read-back verification failed')
        results.append(dict(path=entry['path'], size=len(blob), signatures=len(ranges), verified=True))
    if not results:
        raise ValueError('No NPK packages found')
    return output, results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    inspect = commands.add_parser('inspect', help='Read filesystem and file inventory')
    inspect.add_argument('input', type=Path)
    sign = commands.add_parser('resign', help='Replace embedded NPK signatures only; not a boot-ready patch')
    sign.add_argument('input', type=Path)
    sign.add_argument('output', type=Path)
    sign.add_argument('--signature-only', action='store_true', required=True)
    sign.add_argument('--keys-file', type=Path, default=DEFAULT_KEYS)
    args = parser.parse_args()
    try:
        if args.command == 'resign' and args.output.exists():
            raise ValueError('Output already exists; choose a new file to preserve existing images')
        data = args.input.read_bytes()
        source_hash = hashlib.sha256(data).hexdigest()
        fs = Fat16Image(data)
        report = dict(input=str(args.input), sha256=source_hash, image_size=len(data),
                      filesystem='FAT16', volume_size=fs.volume_size,
                      trailing_bytes=len(data)-fs.volume_size,
                      files=[dict(path=e['path'], size=e['size']) for e in fs.files])
        if args.command == 'resign':
            output, packages = resign(data, read_keys(args.keys_file))
            with args.output.open('xb') as handle:
                handle.write(output)
            with args.output.open('rb') as handle:
                actual_hash = hashlib.file_digest(handle, 'sha256').hexdigest()
            if actual_hash != hashlib.sha256(output).hexdigest():
                raise ValueError('Output file hash verification failed')
            report.update(output=str(args.output), output_sha256=actual_hash, packages=packages,
                          mode='signature-only', boot_and_trusted_public_keys_modified=False)
            print('NPK signatures verified. Trusted public keys and boot files were NOT patched.')
        print(json.dumps(report, indent=2))
    except (OSError, ValueError, KeyError, struct.error, AssertionError) as error:
        parser.exit(2, f'Error: {error}\n')


if __name__ == '__main__':
    main()
