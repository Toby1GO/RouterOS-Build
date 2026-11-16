"""Generate and verify Software-ID licenses for a matching custom RouterOS build.

Wire-format reference: https://github.com/loskiq/MikroTikPatch/blob/main/license.py
Uses this repository's existing crypto primitives. This is not a CHR System-ID tool.
"""
import argparse
import json
import re
from pathlib import Path

from mikro import (
    SOFTWARE_ID_CHARACTER_TABLE, mikro_softwareid_decode, mikro_softwareid_encode,
    mikro_encode, mikro_decode, mikro_base64_encode, mikro_base64_decode,
    mikro_kcdsa_sign, mikro_kcdsa_verify,
)
from toyecc import ECPrivateKey, getcurvebyname

HEADER = '-----BEGIN MIKROTIK SOFTWARE KEY------------'
FOOTER = '-----END MIKROTIK SOFTWARE KEY--------------'
DEFAULT_KEYS = Path(__file__).resolve().parent / '.private' / 'signing.env'


def read_keys(path):
    values = {}
    for line in Path(path).read_text(encoding='utf-8-sig').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        name, separator, value = line.partition('=')
        if not separator:
            raise ValueError('Invalid key file: expected NAME=HEX')
        values[name.strip()] = value.strip()
    return values


def hex_key(value):
    if not re.fullmatch(r'[0-9a-fA-F]{64}', value):
        raise ValueError('Key must contain exactly 64 hexadecimal characters')
    return bytes.fromhex(value)


def public_from_private(private):
    scalar = int.from_bytes(private, 'little')
    curve = getcurvebyname('Curve25519')
    if scalar % curve.n == 0:
        raise ValueError('Invalid zero private scalar')
    return int(ECPrivateKey(scalar, curve).pubkey.point.x).to_bytes(32, 'little')


def canonical_license_private(private):
    """Use the even-y point selected by the RouterOS 7.25.1 x-only verifier.

    The project Python verifier tries both y roots and can conceal a mismatched
    signing direction. Negating the scalar retains the identical public x value.
    This does not rotate or overwrite the user's stored private key.
    """
    curve = getcurvebyname('Curve25519')
    scalar = int.from_bytes(private, 'little') % curve.n
    if scalar == 0:
        raise ValueError('Invalid zero private scalar')
    point = ECPrivateKey(scalar, curve).pubkey.point
    if int(point.y) & 1:
        scalar = curve.n - scalar
    canonical = scalar.to_bytes(32, 'little')
    if public_from_private(canonical) != public_from_private(private):
        raise ValueError('License key normalization changed public key')
    return canonical


def normalize_id(value):
    value = value.strip().upper()
    if not re.fullmatch(r'[A-Z0-9]{4}-?[A-Z0-9]{4}', value):
        raise ValueError('Expected RouterOS Software ID in XXXX-XXXX format, not a CHR System ID')
    compact = value.replace('-', '')
    if any(ord(c) not in SOFTWARE_ID_CHARACTER_TABLE for c in compact):
        raise ValueError('Software ID contains an unsupported character')
    return compact[:4] + '-' + compact[4:]


def generate(software_id, private, version=7):
    software_id = normalize_id(software_id)
    if version not in (6, 7):
        raise ValueError('RouterOS version must be 6 or 7')
    public = public_from_private(private)
    # Historical RouterOS format: 6-byte ID, version byte, feature byte, 8 reserved bytes.
    # 0x16 follows the public reference; device-level acceptance requires runtime validation.
    payload = mikro_softwareid_decode(software_id).to_bytes(6, 'little') + bytes([version, 0x16]) + bytes(8)
    signature = mikro_kcdsa_sign(payload, canonical_license_private(private))
    if not mikro_kcdsa_verify(payload, signature, public):
        raise ValueError('Generated signature failed self-verification')
    encoded = mikro_base64_encode(mikro_encode(payload) + signature, True)
    return '\n'.join([HEADER, encoded[:44], encoded[44:], FOOTER]) + '\n'


def verify(text, public):
    body = ''.join(text.replace(HEADER, '').replace(FOOTER, '').split())
    if not re.fullmatch(r'[A-Za-z0-9+/]{86}==', body):
        raise ValueError('Invalid license encoding')
    raw = mikro_base64_decode(body)
    if len(raw) != 64 or mikro_base64_encode(raw, True) != body:
        raise ValueError('Invalid license length or noncanonical encoding')
    payload = mikro_decode(raw[:16])
    if not mikro_kcdsa_verify(payload, raw[16:], public):
        raise ValueError('License signature is invalid for this public key')
    identity = int.from_bytes(payload[:6], 'little')
    if identity >= len(SOFTWARE_ID_CHARACTER_TABLE) ** 8:
        raise ValueError('Software ID exceeds the supported format')
    return dict(software_id=mikro_softwareid_encode(identity), version=payload[6],
                features=payload[7], signature_valid=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    gen = commands.add_parser('licgenros', help='Generate a RouterOS Software-ID license')
    gen.add_argument('software_id')
    gen.add_argument('private_key', nargs='?', help='Optional 64-character hex license private key')
    gen.add_argument('--keys-file', type=Path, default=DEFAULT_KEYS)
    gen.add_argument('--version', type=int, choices=[6, 7], default=7)
    gen.add_argument('--output', type=Path, help='Save license; refuse to overwrite an existing file')
    check = commands.add_parser('verify', help='Verify a license file and display its Software ID')
    check.add_argument('license_file', type=Path)
    check.add_argument('--keys-file', type=Path, default=DEFAULT_KEYS)
    check.add_argument('--public-key', help='Optional 64-character hex license public key')
    args = parser.parse_args()
    try:
        if args.command == 'licgenros':
            if args.private_key is not None:
                private = hex_key(args.private_key)
            else:
                keys = read_keys(args.keys_file)
                private = hex_key(keys['CUSTOM_LICENSE_PRIVATE_KEY'])
                if public_from_private(private) != hex_key(keys['CUSTOM_LICENSE_PUBLIC_KEY']):
                    raise ValueError('License public/private keys in key file do not match')
            result = generate(args.software_id, private, args.version)
            if args.output:
                with args.output.open('x', encoding='ascii') as handle:
                    handle.write(result)
                print(f'License saved to {args.output}; signature self-check passed.')
            else:
                print(result, end='')
        else:
            public = hex_key(args.public_key) if args.public_key else hex_key(read_keys(args.keys_file)['CUSTOM_LICENSE_PUBLIC_KEY'])
            print(json.dumps(verify(args.license_file.read_text(encoding='utf-8-sig'), public), indent=2))
    except (ValueError, KeyError, OSError, OverflowError) as error:
        # Never include a private-key argument in diagnostic messages.
        parser.exit(2, f'Error: {error}\n')


if __name__ == '__main__':
    main()
