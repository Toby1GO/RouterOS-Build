# 第七版许可证被拒绝：生成器兼容性修复

## 用户反馈与输入

第七版能够安装、正常登录，但文件导入后重启，Paste 提示无效 key。测试虚拟机已被删除，无法核对当时实际 Software ID 和安装后状态。

本地 device-r7.key 解码为 Software ID DJ21-EIQP、版本字段 7、features 22。原 Python 验签通过。该事实不能证明 ID 与已删除的虚拟机一致。

## 复现方式

从第七版实际 SquashFS 提取 nova/bin/keyman，在 Unicorn CPU 模拟器内执行其 0x0804f70e 许可证校验函数，保持真实的解码、哈希和曲线运算指令。唯一触发的外部比较调用使用真实字节比较语义模拟，没有强制相等。未原生执行 ELF，未访问宿主磁盘设备，也未启动虚拟机。

检测到：

- keyman 实际载入的是用户自有公钥，公钥替换正确。
- keyman 解码的 16 字节 payload 与 Python 一致。
- keyman 中间哈希与 Python 一致。
- 旧文件到达最终 16 字节比较时不相等，实际二进制校验返回失败。

## 修复点

项目 mikro_kcdsa_verify 由公钥 x 坐标恢复曲线点时尝试两个 y 根，因此 Python 自检会接受两种签名方向。该版本 keyman 的对应算法只接受其中一种。对当前用户密钥，将私钥标量 s 换成 n-s 后，公钥 x 坐标不变，但二进制校验由拒绝变为接受。

license.py 增加 canonical_license_private，在生成许可证时将签名点规范到偶数 y 方向。用户存储的私钥和公钥文件不变，不需要重新构建第七版 ISO；没有修改系统验签条件，也没有修改 NPK 重签名函数。

这解释了为什么只用同一个 Python 模块签名再验签会漏掉问题。此前“本地验签通过”的证据不充分。

## 验证

- 旧文件 device-r7.key：第七版二进制校验拒绝。
- 新文件 device-r7-fixed.key：第七版二进制校验接受，payload 不变。
- 相同真实密钥方向对照：原方向连续三次拒绝，反向连续三次接受。
- 8 组额外代表性测试密钥（包含奇/偶两种原点方向）规范化后全部通过对应公钥的二进制校验。
- 新文件被篡改后拒绝，使用原官方公钥的二进制也拒绝。
- 额外的小标量边界探测中，s=1 / 公钥 x=9 仍未通过二进制校验；没有宣称覆盖任意输入标量或全部 RouterOS 版本。

证据：binary-verification.json、normalization-cases.json。复现函数位于 analysis/check_r7_license_binary.py。

## 使用与边界

device-r7-fixed.key 仍对应 DJ21-EIQP。如果重新创建虚拟机后 ID 不同，不应直接导入该文件；使用实际新 Software ID 运行：

```powershell
python license.py licgenros 实际SoftwareID --output device-new.key
```

继续使用原 .private/signing.env。输出文件必须尚不存在。第七版 ISO 不变。

CPU 模拟只证明许可证的密码学校验函数接受新签名，不验证实际设备 ID 匹配、导入流程、写盘、版本/功能字段完整语义或重启后授权状态。需要用户重新安装第七版后进行实际导入验收，不能将本次修复标记为整机授权已通过。
