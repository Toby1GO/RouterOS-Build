# Windows 便携版

推荐使用 RouterOSKeygen-v3-portable.zip：解压整个文件夹，再运行其中的
RouterOSKeygen-v3.exe。复制到其他电脑时请复制整个文件夹，保留 _internal。
目标平台为 Windows 10/11 x64；无需另外安装 Python。

包含 Python 3.14 运行时、Python 标准库、Tkinter/Tcl/Tk、VC 运行库、
本项目的 license/chr_license/mikro/sha256/toyecc，以及现有许可证公私钥。
pyasn1 仅供 toyecc 的可选 ASN.1 功能使用，本程序的生成流程不需要它。

打开程序后选择类型、输入 ID、点击 Generate 并复制完整授权文本。
默认使用内置许可证密钥；EXE 同目录的 signing.env 或 .private/signing.env
可覆盖内置密钥，也可以在界面中选择文件。内置的是许可证密钥对，不包含
源 signing.env 中其他用途的密钥。持有此发布包的人可以提取内置私钥。

本工具适用于与这些自有密钥匹配的自定义镜像。CHR 仍为实验功能；
签名自检通过不等于已验证设备实际激活成功。

单文件 EXE 和便携文件夹版包含相同功能。单文件 EXE 需要创建临时解压
目录；本机测试发现加载器可能报 Could not create temporary directory。
遇到这种情况请使用便携文件夹版。未提供代码签名证书，本次打包不会自动
消除 Windows 安全信誉提示。

程序进入 Python 后的启动错误日志位于：
%LOCALAPPDATA%\RouterOSKeygen\startup-error.log。
Windows 拦截或加载器在 Python 启动之前失败时，不会生成该日志。

可用 PowerShell 手动自检（自检报告不包含密钥或生成的授权文本）：

```powershell
$p = Start-Process .\RouterOSKeygen-v3.exe -ArgumentList '--self-test', 'self-test.json' -Wait -PassThru
$p.ExitCode
Get-Content .\self-test.json
```

重新编译：在项目内保留 .private/signing.env，安装 requirements-build.txt
中的构建依赖，然后运行 .\build_license_gui.ps1。构建器先校验密钥配对，
再生成单文件 EXE 和便携 ZIP；原有密钥文件不会被修改。
