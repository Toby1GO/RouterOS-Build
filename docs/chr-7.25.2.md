# CHR 7.25.2 Renew 适配

旧工作流自动选择最新 stable，但 CHR 构建只允许 7.25.1，因此选择
7.25.2 后会被构建脚本拒绝。不能直接删除版本和哈希限制：新版 keyman
的状态字段由 0x654/0x658 移至 0x674/0x678，notifyChange 的 PLT 地址
由 0x804b780 移至 0x804b790。此次核对的内部 Renew、读写盘、证书解析、
身份检查和刷新函数入口保持原地址。

## 修改

- `scripts/chr_profiles.py` 保存每个版本的官方镜像哈希、keyman 指纹和字段偏移。
- keyman 验证时仅将构建公钥还原为官方公钥再计算完整文件指纹，避免绑定某一套私有签名密钥；其他字节变化仍会被拒绝。
- 外部函数地址通过 ELF 重定位符号解析，避免沿用旧版 PLT 序号。
- 模拟器检查实际访问的状态和错误字段，写错地址立即失败。
- Actions 在解析版本时拒绝未知 CHR 版本，并增加独立测试密钥、篡改、错误密钥和错误版本的检查。

## 本地验证（2026-11-26）

- 官方 CHR 系统包签名通过，版本为 7.25.2。
- 7.25.1 和 7.25.2 各通过 13 项本地 Renew 模拟检查，包括成功、重复、错误账号/密码、磁盘读写错误、读回不一致、错误签名及原始身份/等级/期限检查。
- 7.25.2 独立测试签名密钥通过；篡改、错误密钥、错误版本配置和未知版本被拒绝。
- 完整构建 ISO、安装 IMG、12 个 NPK、Legacy 和 UEFI CHR，签名、文件系统和读回检查通过。
- 8 种 CHR 磁盘转换与原始磁盘比较一致，ZIP 打包通过；loader 模拟和 actionlint 通过。
- 无网卡 QEMU TCG 虚拟机：Legacy 和 UEFI 均成功启动 7.25.2，由 free 执行本地 Renew 后成为 p-unlimited。
- Legacy 和 UEFI 重启后均保留 p-unlimited，重复 Renew 返回 done；Legacy 错误密码被拒绝。测试虚拟机均已关闭。

本地验证产物位于 `build/renew-adaptation-output/`，模拟报告位于
`build/renew-7.25.1-verification.json` 和 `build/renew-7.25.2-verification.json`，
虚拟机串口记录位于 `build/renew-vm-7.25.2/`。这些构建和测试数据不提交到 Git。

没有验证 WinBox、VMware 或实际转发吞吐量。GitHub CLI 当前未登录，未读取远端失败日志或重跑 Actions。
本地 Renew 是自定义固件机制，不是 MikroTik 官方授权；未来版本仍需单独核对和测试。
