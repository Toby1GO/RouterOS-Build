# RouterOS 私有构建

手动运行 GitHub Actions，从 MikroTik 官方下载 RouterOS 7 x86，生成使用现有自有密钥的 ISO、安装 IMG 和 NPK，再发布到本私有仓库的 Release。

## 一键构建

1. 打开 Actions → **Build and release RouterOS** → **Run workflow**。
2. `version` 填版本号（例如 `7.25.1`）；留空时读取所选官方频道最新版本，默认 stable。
3. 保持 `release` 勾选。任务全部成功后，在 Releases 下载镜像、NPK、`build.json` 和 `SHA256SUMS`。
4. 这是 x86 安装镜像，IMG 不是 CHR 系统盘。读取安装后的 Software ID，使用原有匹配密钥的生成器手动生成授权。

每次构建使用唯一 Release 标签，不覆盖旧版本。没有定时任务，只有手动触发。
工作流会验证官方源包签名、自有签名、SquashFS 内容和元数据、ISO 布局、IMG 读回和内核 CRC。
新版 ELF、内核或镜像布局不兼容时停止，不发布失败输出。自动静态校验不能代替新版本的启动、登录和激活测试。
已在本地用官方 7.25.1 完成端到端构建；新的结构定位实现仍需目标设备启动验证。

## Windows 生成器

Actions → **Build Windows key generator** 可构建并自检便携 ZIP，从该次运行的 Artifacts 下载。
完整解压后运行 EXE，不需要额外安装 Python。该包包含许可证私钥，可被提取；只提供给可信使用者。
本地现成便携包保存在 `releases-local/`，不进入 Git 历史。参见 [便携版说明](README-portable.md)。

## 密钥

仓库需要四个 Actions Secrets（本次初始化会从本地现有密钥配置）：

- `CUSTOM_LICENSE_PRIVATE_KEY`
- `CUSTOM_LICENSE_PUBLIC_KEY`
- `CUSTOM_NPK_SIGN_PRIVATE_KEY`
- `CUSTOM_NPK_SIGN_PUBLIC_KEY`

每个值为 64 位十六进制文本。保留现有密钥以匹配已安装镜像，不要随意更换。
`.private/signing.env`、CLI 登录配置、设备授权文件都被忽略，不提交到 Git。
固件 Release 只包含公钥；Windows 生成器 Artifact 则内置许可证私钥。

## 本地构建

推荐 Ubuntu 24.04、Python 3.12：

```bash
sudo apt-get install squashfs-tools-ng
python -m pip install -r requirements.txt
python scripts/build_routeros.py --version 7.25.1
```

默认从 `.private/signing.env` 读取密钥，也支持同名环境变量。
原始文件缓存于 `downloads/`，中间文件在 `build/routeros/`，发布产物在 `publish/`。
重复构建时使用新的 `--output-dir`，避免覆盖旧输出。
Windows 构建生成器：`python -m pip install -r requirements-build.txt`，然后运行 `./build_license_gui.ps1`。

## 项目结构与来源

- `scripts/`：官方下载、结构定位、镜像构建、结果校验。
- 根目录 Python 文件：NPK、密码算法、授权生成器和现有底层工具。
- `toyecc/`：上游椭圆曲线实现，保留其许可证头。
- `docs/`：清理记录和已验证版本的说明。
- `.local-archive/`、`analysis/`、`releases-local/`：仅本地保留的历史数据，不上传。

基于 [elseif/MikroTikPatch](https://github.com/elseif/MikroTikPatch) 和本地后续修改。
根项目保留原 LICENSE；toyecc 文件头另有 GPLv3 条款，详见源文件。
原 loader 修补逻辑会让 loader 的导入 memcmp 返回相等，影响该导入入口的所有比较；本构建继承此既有行为。
