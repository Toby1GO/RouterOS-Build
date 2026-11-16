# 清理记录（2026-11-16）

已删除可重新构建的 `.diag-build`、`dist`、解压版 `RouterOSKeygen-v3` 和缓存。
原便携 ZIP 保留在 `releases-local/`。权限异常的旧诊断临时目录也已完成清理。

原始镜像、输入/输出 NPK 移到 `.local-archive/originals/`。
已测试版本镜像移到 `.local-archive/7.25.1/`。
历史分析与实验脚本移到 `.local-archive/analysis/`，作为记录保留；其中的旧绝对路径和相对路径不再是当前构建入口。
旧上游工作流移到 `.local-archive/upstream-workflows/`；未使用的 busybox、keygen、安装辅助脚本等移到 `.local-archive/upstream-extras/`。
本地 SquashFS 与 Python 分析依赖移到 `.local-tools/analysis-tools/`。

当前仓库只跟踪源码、依赖声明、说明和两个手动工作流。所有密钥、登录配置、旧镜像、分析产物、EXE、ZIP、构建缓存均排除在 Git 外。
现有 `.private/signing.env` 和设备授权文件保留原位，未旋转密钥。

验证：7.25.1 官方源包 EdDSA 验签；12 个自有签名 NPK；SquashFS 文件和元数据读回；ISO 布局及文件读回；安装 IMG 文件读回；内核 CRC；loader 入口寄存器、标志和栈的三个模拟场景。
新构建未进行整机启动测试。旧第七版的用户实测记录仅作为历史材料，不代替新构建实测。

进一步删除可重新生成的 TAR、SquashFS、NPK 和 vmlinux 中间文件约 1200.3 MiB，以及 build 缓存约 1081.2 MiB，共约 2.23 GiB。删除清单位于本地 `.local-archive/deleted-generated-files.json`。

云端验证：固件 Actions 43821177264 成功，发布 routeros-7.25.1-43821177264-1；Windows Actions 43821543594 成功，便携 ZIP 自检通过。仓库可见性已核实为 PRIVATE。

## 后续调整

按用户要求，Windows GUI、编译配置、激活 CLI 和 Windows Actions 已从当前仓库跟踪移除，本地文件保留；GitHub 上的 Windows Artifact 与两次运行记录已删除。现有 Git 历史未重写。固件所需密钥读取、签名及 CHR 内置证书逻辑改为 scripts 内部模块。

CHR 沿用 loulan/loulan 本地 Renew；7.25.1 的 Legacy/UEFI 实际启动分区、模拟校验和多格式转换已接入工作流。未知版本停止，不能直接沿用固定内部地址。
