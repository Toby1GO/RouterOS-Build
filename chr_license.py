"""Experimental CHR System-ID calculation and manually signed license text."""
import argparse
import json
import re
import struct
from pathlib import Path
from mikro import mikro_sha256, mikro_base64_encode, mikro_base64_decode, mikro_encode, mikro_decode, mikro_kcdsa_sign, mikro_kcdsa_verify
from license import DEFAULT_KEYS, HEADER, FOOTER, read_keys, hex_key, public_from_private, canonical_license_private


def decode_system_id(value):
    # Case-sensitive 64-bit value, encoded least-significant sextet first.
    if not re.fullmatch(r'[A-Za-z0-9+/]{11}', value):
        raise ValueError('CHR System ID must contain exactly 11 case-sensitive base64 characters')
    data = mikro_base64_decode(value)
    if len(data) != 8 or mikro_base64_encode(data) != value:
        raise ValueError('Noncanonical CHR System ID (unused high bits must be zero)')
    return data


def derive_system_id(uuid, mbr):
    if not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', uuid):
        raise ValueError('Expected a canonical SMBIOS product_uuid string')
    if len(mbr) != 512 or mbr[510:512] != b'\x55\xaa':
        raise ValueError('Expected a complete signed 512-byte MBR sector')
    compact = uuid.replace('-', '')
    uuid_bytes = struct.pack('<8H', *(int(compact[i:i+4], 16) for i in range(0, 32, 4)))
    digest = mikro_sha256(uuid_bytes + mbr[0x100:0x110])
    return mikro_base64_encode(digest[:8])


def generate_chr(system_id, private, deadline, level):
    identity = decode_system_id(system_id)
    if not 0 <= deadline <= 0xffffffff or level not in (1, 2, 3):
        raise ValueError('Expected uint32 deadline and CHR level 1, 2 or 3')
    payload = identity + struct.pack('<I', deadline) + bytes([level]) + bytes(3)
    signature = mikro_kcdsa_sign(payload, canonical_license_private(private))
    if not mikro_kcdsa_verify(payload, signature, public_from_private(private)):
        raise ValueError('Signature self-check failed')
    body = mikro_base64_encode(mikro_encode(payload) + signature, True)
    return '\n'.join([HEADER, body[:44], body[44:], FOOTER]) + '\n'


def verify_chr(text, public):
    body = ''.join(text.replace(HEADER, '').replace(FOOTER, '').split())
    if not re.fullmatch(r'[A-Za-z0-9+/]{86}==', body):
        raise ValueError('Invalid license text')
    raw = mikro_base64_decode(body)
    if len(raw) != 64 or mikro_base64_encode(raw, True) != body:
        raise ValueError('Invalid license encoding')
    payload = mikro_decode(raw[:16])
    if not mikro_kcdsa_verify(payload, raw[16:], public):
        raise ValueError('Invalid signature')
    return dict(system_id=mikro_base64_encode(payload[:8]), deadline_raw=struct.unpack_from('<I', payload, 8)[0],
                level=payload[12], signature_valid=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    identity = sub.add_parser('system-id')
    identity.add_argument('--uuid', required=True)
    identity.add_argument('--disk', type=Path, required=True, help='Raw IMG, not a VMDK descriptor')
    gen = sub.add_parser('generate')
    gen.add_argument('system_id')
    gen.add_argument('--keys-file', type=Path, default=DEFAULT_KEYS)
    gen.add_argument('--level', type=int, choices=[1, 2, 3], default=3)
    gen.add_argument('--deadline', type=lambda s: int(s, 0), default=0xf4865700,
                     help='Raw 32-bit field; historical reference default 0xf4865700, not a verified perpetual guarantee')
    gen.add_argument('--output', type=Path, required=True)
    check = sub.add_parser('verify')
    check.add_argument('file', type=Path)
    check.add_argument('--keys-file', type=Path, default=DEFAULT_KEYS)
    args = parser.parse_args()
    try:
        if args.command == 'system-id':
            with args.disk.open('rb') as f: mbr = f.read(512)
            print(derive_system_id(args.uuid, mbr))
        elif args.command == 'generate':
            keys = read_keys(args.keys_file)
            private = hex_key(keys['CUSTOM_LICENSE_PRIVATE_KEY'])
            if public_from_private(private) != hex_key(keys['CUSTOM_LICENSE_PUBLIC_KEY']):
                raise ValueError('License key pair mismatch')
            text = generate_chr(args.system_id, private, args.deadline, args.level)
            with args.output.open('x', encoding='ascii') as f: f.write(text)
            print(f'Saved {args.output}; cryptographic self-check passed. CHR activation requires device testing.')
        else:
            public = hex_key(read_keys(args.keys_file)['CUSTOM_LICENSE_PUBLIC_KEY'])
            print(json.dumps(verify_chr(args.file.read_text(encoding='utf-8-sig'), public), indent=2))
    except (OSError, ValueError, KeyError) as error:
        parser.exit(2, f'Error: {error}\n')


if __name__ == '__main__': main()
