"""Build standalone Windows releases with the existing license key pair."""
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from license import read_keys, hex_key, public_from_private


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='RouterOSKeygen-v3')
    args = parser.parse_args()
    if not args.name or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in args.name):
        parser.error('Name must contain only letters, digits, hyphens or underscores')
    root = Path(__file__).resolve().parent
    keys = read_keys(root / '.private' / 'signing.env')
    names = ('CUSTOM_LICENSE_PRIVATE_KEY', 'CUSTOM_LICENSE_PUBLIC_KEY')
    private, public = (hex_key(keys[name]) for name in names)
    if public_from_private(private) != public:
        raise ValueError('License public/private keys do not match')
    staging = root / 'build' / 'license-gui' / 'embedded'
    staging.mkdir(parents=True, exist_ok=True)
    resource = staging / 'signing.env'
    try:
        # Do not bundle unrelated package-signing secrets from the source file.
        resource.write_text(''.join(f'{name}={keys[name]}\n' for name in names), encoding='utf-8')
        common = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean',
                  '--windowed', '--noupx', '--collect-submodules', 'toyecc',
                  '--add-data', f'{resource};resources',
                  '--specpath', str(root / 'build' / 'license-gui')]
        for mode in ('onefile', 'onedir'):
            dest = root if mode == 'onefile' else root / 'dist' / 'portable'
            command = common + [f'--{mode}', '--name', args.name,
                                '--distpath', str(dest), '--workpath', str(root / 'build' / 'license-gui' / mode),
                                str(root / 'license_gui_launcher.py')]
            subprocess.run(command, cwd=root, check=True)
        shutil.copy2(root / 'README-portable.md', root / 'dist' / 'portable' / args.name / '使用说明.md')
        shutil.make_archive(str(root / f'{args.name}-portable'), 'zip',
                            root / 'dist' / 'portable', args.name)
    finally:
        resource.unlink(missing_ok=True)
    print(f'Built {args.name}.exe and {args.name}-portable.zip')


if __name__ == '__main__':
    main()
