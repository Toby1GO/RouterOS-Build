"""Reviewed CHR binary layouts. Unknown releases must be inspected first."""
PROFILES = {
    '7.25.1': {
        'disk_sha256': '42ce7e8bbcd07d3054bc1c7309540ef621e4bbead90b19defab34fccbba123af',
        'keyman_sha256': '6d81e5da8f13f48c5c87c57140ed9dc30ebba33ca35e000189be89198f4c86af',
        'status_offset': 0x654,
        'error_offset': 0x658,
    },
    '7.25.2': {
        'disk_sha256': '18ccb9a61c92a220a1f55f6077f7da3601f02b45eadf9c255b6038ac0e6b322b',
        'keyman_sha256': 'b96291ca4290d6f67fc10fab2d7adb8777a0d1e8e7d8450fef427fdcd01fc1cf',
        'status_offset': 0x674,
        'error_offset': 0x678,
    },
}


def profile_for(version):
    if version not in PROFILES:
        raise ValueError(f'CHR local Renew has no validated profile for {version}; '
                         f'supported versions: {", ".join(PROFILES)}')
    return PROFILES[version]


def plt_imports(elf):
    symbols = elf.get_section_by_name('.dynsym')
    base = elf.get_section_by_name('.plt').header.sh_addr
    return {symbols.get_symbol(r.entry.r_info_sym).name: base + 16 * (i + 1)
            for i, r in enumerate(elf.get_section_by_name('.rel.plt').iter_relocations())}
