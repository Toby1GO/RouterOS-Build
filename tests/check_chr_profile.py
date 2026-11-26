"""Check the CHR profile against official build input and reject unsafe variants.

Run after build_routeros.py:
  python tests/check_chr_profile.py VERSION --work-dir build/routeros
The ordinary CHR build separately runs all native renewal emulation cases.
"""
import argparse
import contextlib
import io
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT)]
from build_routeros import OFFICIAL_LICENSE
from chr_certificate import generate_chr
from chr_profiles import PROFILES, profile_for
from patch import replace_key
from patch_chr_local_renew import patch_keyman
from signing import public_from_private


def rejected(action):
    try:
        action()
    except ValueError:
        return
    raise AssertionError('Unsafe input was accepted')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('version')
    p.add_argument('--work-dir', type=Path, default=ROOT / 'build/routeros')
    a = p.parse_args()
    with tarfile.open(a.work_dir / a.version / 'source.tar') as source:
        original = source.extractfile('./nova/bin/keyman').read()
    # Disposable test key, deliberately unrelated to the user's build keys.
    private = bytes.fromhex('ab' * 32)
    public = public_from_private(private)
    cert = generate_chr('AAAAAAAAAAA', private, 0xffffffff, 3)
    with contextlib.redirect_stdout(io.StringIO()):
        custom = replace_key(OFFICIAL_LICENSE, public, original, 'keyman')
    patched, _ = patch_keyman(custom, cert, public, a.version)
    assert patched != custom
    tampered = bytearray(custom)
    tampered[0x4000] ^= 1
    rejected(lambda: patch_keyman(bytes(tampered), cert, public, a.version))
    wrong_public = public_from_private(bytes.fromhex('cd' * 32))
    rejected(lambda: patch_keyman(custom, cert, wrong_public, a.version))
    for other in PROFILES:
        if other != a.version:
            rejected(lambda: patch_keyman(custom, cert, public, other))
    rejected(lambda: profile_for('7.999.999'))
    print(f'{a.version}: independent signing key accepted; tampering, wrong key, '
          'wrong profile and unknown release rejected')


if __name__ == '__main__':
    main()
