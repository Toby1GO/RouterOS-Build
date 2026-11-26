# RouterOS 私有构建

Actions → **Build and release RouterOS** → **Run workflow**，版本留空获取官方最新 **stable**，保持 `release` 勾选。
工作流仅构建和发布 stable；没有开发版、测试版或 long-term 频道选项。手动填写版本时必须等于官方当前 stable（beta/rc 及其他版本会被拒绝）；打包发布前再次校验频道。
完成后到 Releases，按下载表选择安装镜像或 CHR 磁盘。Windows 激活器及其编译文件仅保留本地，不再上传。

## 下载选择

| 使用方式 | 文件 |
| --- | --- |
| 安装普通 x86 RouterOS | mikrotik-版本.iso |
| 写盘安装普通 RouterOS | install-image-版本.img.zip（不是 CHR） |
| 升级已安装的自定义 RouterOS | routeros-版本.npk |
| 额外功能包 | all-packages-x86-版本.zip |
| CHR 通用磁盘 | chr-版本-uefi.img.zip / chr-版本-legacy-bios.img.zip |
| PVE / QEMU / KVM | 对应 CHR qcow2.zip |
| VMware | 对应 CHR vmdk.zip |
| VirtualBox | 对应 CHR vdi.zip |
| Hyper-V 第一代 / 第二代 | Legacy vhd.zip / UEFI vhdx.zip |

CHR 两版系统分区相同，启动分区分别为 ext2（Legacy）和 FAT16（UEFI），不是简单改名。
UEFI 需要关闭 Secure Boot。本地 Renew 沿用账号 `loulan`、密码 `loulan`、等级 `p-unlimited`。

**CHR 本地 Renew 已适配 7.25.1、7.25.2。** 每个版本使用独立的镜像哈希、keyman 校验和状态字段配置，导入函数按符号解析。未知版本在工作流版本解析阶段停止，必须适配并验证后才可发布；不能保证任意未来版本直接修补成功。
普通 x86 部分按 ELF 结构定位，仍会拒绝不兼容的内核或镜像布局。所有构建需要通过签名、文件系统、镜像读回、指令模拟和磁盘格式比较检查才发布。静态校验不能代替新构建的整机启动测试。
没有定时任务；每次手动运行生成独立 Release，不覆盖旧产物。

## 构建密钥

使用仓库现有四个 Actions Secrets：`CUSTOM_LICENSE_PRIVATE_KEY`、`CUSTOM_LICENSE_PUBLIC_KEY`、`CUSTOM_NPK_SIGN_PRIVATE_KEY`、`CUSTOM_NPK_SIGN_PUBLIC_KEY`。
本地 `.private/` 始终忽略。固件内只有公钥和已签好的 CHR 证书，不内置签名私钥。
保留现有密钥，不要随意旋转，以免与已安装镜像不匹配。

## 本地构建

Ubuntu 24.04、Python 3.12：

```bash
sudo apt-get install squashfs-tools-ng qemu-utils
python -m pip install -r requirements.txt
python scripts/build_routeros.py --version 7.25.2
python scripts/build_chr.py --version 7.25.2
```

默认从 `.private/signing.env` 读取密钥，也可使用同名环境变量。
源码：`scripts/` 和根目录底层 NPK/密码模块；原始文件：`downloads/`；中间产物：`build/`；发布输出：`publish/`。
本地激活程序、历史镜像、分析记录和工具位于忽略目录中，不会上传。

基于 [elseif/MikroTikPatch](https://github.com/elseif/MikroTikPatch) 和本地修改；保留原 LICENSE 及 toyecc 的 GPLv3 文件头。
现有 loader 补丁使其导入 memcmp 返回相等，沿用已有行为。
