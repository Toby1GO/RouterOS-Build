"""Resolve only the official current RouterOS 7 stable release."""
import json
import re
import urllib.request


def version(value):
    if not re.fullmatch(r'7\.\d+(?:\.\d+)?', value):
        raise ValueError('Only stable RouterOS 7 versions are allowed; beta/rc are not supported')
    return value


def resolve_version(value=''):
    if value:
        version(value)
    with urllib.request.urlopen('https://upgrade.mikrotik.com/routeros/upgrade.json', timeout=60) as response:
        data = json.load(response)
    stable = version(data['upgradePaths']['NEWESTa7.stable']['version'])
    if value and value != stable:
        raise ValueError(f'Only the official current stable release is allowed: {stable}; requested {value}')
    return stable
