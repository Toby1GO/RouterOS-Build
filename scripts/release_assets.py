"""Prepare verified virtual disks and a concise download table for GitHub Releases."""
import argparse,hashlib,json,os,subprocess,zipfile
from pathlib import Path
from datetime import datetime,timezone


def zipped(source):
    target=source.with_suffix(source.suffix+'.zip')
    with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:z.write(source,source.name)
    with zipfile.ZipFile(target) as z:
        if z.testzip() is not None:raise ValueError('ZIP integrity failure')
    source.unlink()
    return target


def main():
    p=argparse.ArgumentParser();p.add_argument('--version',required=True);p.add_argument('--output-dir',type=Path,default=Path('publish'));p.add_argument('--channel',default='stable');a=p.parse_args()
    out=a.output_dir;ver=a.version
    # Stable human-facing file names; the release tag distinguishes rebuilds.
    (out/f'mikrotik-{ver}-custom.iso').rename(out/f'mikrotik-{ver}.iso')
    zipped(out/f'install-image-{ver}-custom.img').rename(out/f'install-image-{ver}.img.zip')
    extras=sorted(p for p in out.glob('*.npk') if p.name!=f'routeros-{ver}.npk')
    with zipfile.ZipFile(out/f'all-packages-x86-{ver}.zip','w',zipfile.ZIP_DEFLATED) as z:
        for item in extras:z.write(item,item.name)
    for item in extras:item.unlink()
    formats=[('qcow2','qcow2'),('vmdk','vmdk'),('vdi','vdi'),('vhd','vpc'),('vhdx','vhdx')]
    for mode in ('uefi','legacy-bios'):
        raw=out/f'chr-{ver}-{mode}.img'
        for ext,fmt in formats:
            if (mode == 'uefi' and ext == 'vhd') or (mode == 'legacy-bios' and ext == 'vhdx'):
                continue
            target=raw.with_suffix('.'+ext)
            command=['qemu-img','convert','-f','raw','-O',fmt]
            if fmt=='vpc':command+=['-o','force_size=on']
            subprocess.run(command+[str(raw),str(target)],check=True)
            subprocess.run(['qemu-img','compare','-f','raw','-F',fmt,str(raw),str(target)],check=True)
            zipped(target)
        zipped(raw)
    tag=f'routeros-{ver}-{os.environ["GITHUB_RUN_ID"]}-{os.environ["GITHUB_RUN_ATTEMPT"]}'
    base=f'https://github.com/{os.environ["GITHUB_REPOSITORY"]}/releases/download/{tag}/'
    def link(name):
        if not (out/name).is_file():raise ValueError('Release table points to missing asset: '+name)
        return f'[{name}]({base}{name})'
    text=f'''架构：`x86 / x86_64`  ·  版本：`{ver}`
构建时间：{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

### RouterOS 安装与升级

| 用途 | 下载 |
| --- | --- |
| 已安装 RouterOS：主系统包 | {link(f'routeros-{ver}.npk')} |
| 额外功能包合集 | {link(f'all-packages-x86-{ver}.zip')} |
| 从光盘安装 / 虚拟机安装 | {link(f'mikrotik-{ver}.iso')} |
| 写盘安装镜像（不是 CHR） | {link(f'install-image-{ver}.img.zip')} |

### CHR 虚拟机系统盘

直接导入对应平台的磁盘；固件选择要与下载列一致。

| 平台 / 格式 | UEFI | Legacy BIOS |
| --- | --- | --- |
'''
    for label,ext in [('通用 Raw 磁盘','img'),('QEMU / KVM / PVE','qcow2'),('VMware','vmdk'),('VirtualBox','vdi'),('Hyper-V 第一代','vhd'),('Hyper-V 第二代','vhdx')]:
        text+=f'| {label} | {link(f"chr-{ver}-uefi.{ext}.zip")} | {link(f"chr-{ver}-legacy-bios.{ext}.zip")} |\n' if ext not in ('vhd','vhdx') else (f'| {label} | — | {link(f"chr-{ver}-legacy-bios.{ext}.zip")} |\n' if ext=='vhd' else f'| {label} | {link(f"chr-{ver}-uefi.{ext}.zip")} | — |\n')
    text+='''
CHR 本地 Renew：账号 `loulan`，密码 `loulan`，等级 `p-unlimited`。UEFI 请关闭 Secure Boot。

<details>
<summary>校验与构建说明</summary>

固件签名、镜像读回、本地 Renew 指令模拟及虚拟磁盘格式转换校验通过。新构建尚未做整机启动测试。
CHR 本地 Renew 补丁当前适配 7.25.1，其他版本须适配后才能发布。
Windows 激活工具仅保留在本地，不随仓库或 Release 发布。

'''
    # Remove stale pre-packaging hashes before producing the final manifest.
    sums=out/'SHA256SUMS';sums.unlink(missing_ok=True)
    sums.write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in sorted(out.iterdir()) if p.is_file()),encoding='ascii')
    text+=f'{link("SHA256SUMS")} · {link("build.json")} · {link("chr-build.json")}\n\n</details>\n'
    (out/'RELEASE.md').write_text(text,encoding='utf-8')

if __name__=='__main__':main()
