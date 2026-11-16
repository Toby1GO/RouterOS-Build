"""Build-time certificate for the CHR local-renew firmware patch."""
import re, struct
from signing import canonical_license_private, public_from_private
from mikro import mikro_base64_decode, mikro_base64_encode, mikro_decode, mikro_encode, mikro_kcdsa_sign, mikro_kcdsa_verify
HEADER="-----BEGIN MIKROTIK SOFTWARE KEY------------"
FOOTER="-----END MIKROTIK SOFTWARE KEY--------------"

def decode_system_id(value):
    # Case-sensitive 64-bit value, encoded least-significant sextet first.
    if not re.fullmatch(r'[A-Za-z0-9+/]{11}', value):
        raise ValueError('CHR System ID must contain exactly 11 case-sensitive base64 characters')
    data = mikro_base64_decode(value)
    if len(data) != 8 or mikro_base64_encode(data) != value:
        raise ValueError('Noncanonical CHR System ID (unused high bits must be zero)')
    return data


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

