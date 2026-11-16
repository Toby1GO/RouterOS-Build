# 清理记录（2026-11-16）

已删除可重新构建的 `.diag-build`、`dist`、解压版 `RouterOSKeygen-v3` 和缓存。
原便携 ZIP 保留在 `releases-local/`。少数 Windows 临时目录权限异常，保留并忽略，不影响源码和构建。

原始镜像、输入/输出 NPK 移到 `.local-archive/originals/`。
已测试版本镜像移到 `.local-archive/7.25.1/`。
历史分析与实验脚本移到 `.local-archive/analysis/`，作为记录保留；其中的旧绝对路径和相对路径不再是当前构建入口。
旧上游工作流移到 `.local-archive/upstream-workflows/`；未使用的 busybox、keygen、安装辅助脚本等移到 `.local-archive/upstream-extras/`。
本地 SquashFS 与 Python 分析依赖移到 `.local-tools/analysis-tools/`。

当前仓库只跟踪源码、依赖声明、说明和两个手动工作流。所有密钥、登录配置、旧镜像、分析产物、EXE、ZIP、构建缓存均排除在 Git 外。
现有 `.private/signing.env` 和设备授权文件保留原位，未旋转密钥。

验证：7.25.1 官方源包 EdDSA 验签；12 个自有签名 NPK；SquashFS 文件和元数据读回；ISO 布局及文件读回；安装 IMG 文件读回；内核 CRC；loader 入口寄存器、标志和栈的三个模拟场景。
新构建未进行整机启动测试。旧第七版的用户实测记录仅作为历史材料，不代替新构建实测。
