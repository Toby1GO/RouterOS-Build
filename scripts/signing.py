"""Firmware build signing helpers; no desktop activation interface."""
import re
from pathlib import Path
from toyecc import ECPrivateKey, getcurvebyname
DEFAULT_KEYS = Path(__file__).resolve().parents[1] / '.private' / 'signing.env'

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


