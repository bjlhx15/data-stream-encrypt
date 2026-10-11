# FCS4 文件加密工具 — 安装、使用与运维说明

## 1. 功能与文件格式

FCS4 是基于 Python 的流式文件/目录打包加密工具。流程：

`文件/目录 → tar 流 → zstd/gzip/无压缩 → AES-256-GCM 分块加密 → encrypted.bin`

- 每个加密包独立生成 32 字节随机 AES 密钥（DEK）。
- 每个被授权的 RSA 公钥分别以 RSA-3072-OAEP-SHA256 封装同一 DEK；最多 64 个不同公钥。
- 授权表通过由 DEK 派生的 HMAC-SHA256 校验；数据块通过 AES-GCM 校验。
- `rotate` 可增加或替换接收者授权，不重新加密数据；**会完整复制密文**。
- 新文件头标识 `FCS4`，支持读取/轮换此前 `FCS3` 格式。**不支持 FCS1/FCS2**。
- 默认 zstd 压缩级别 6、AES 分块 1 MiB。

**安全边界**：私钥或 AES 密钥泄露、旧文件副本留存、运行环境被控制，均可能导致明文泄露。`rotate --replace` 仅撤销新文件中的封装记录，不会撤销已泄露密钥或已保存的旧文件。私钥丢失且无其他授权私钥时，数据无法恢复。此工具尚未经第三方安全审计。

## 2. 环境要求

- Python 3.10 或更新版本（建议使用虚拟环境）。
- macOS / Linux；Windows 的基本功能可能可用，但权限和文件系统语义未完整测试。
- `cryptography`：必需；`zstandard`：使用 zstd 压缩/解压时必需。
- 大文件加密建议使用足够空间的 SSD/NVMe。轮换时需要存放一份新文件；解密时需要存放完整明文及临时目录。

### macOS / Linux 安装

```bash
# 将 stream_encrypt.py、requirements.txt 放到该目录
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python stream_encrypt.py --help
```

如使用 macOS Homebrew：`brew install python`。Linux 可使用发行版包管理器安装 Python3、venv、pip。

## 3. 快速开始

### 3.1 生成 RSA 密钥对

```bash
python stream_encrypt.py keygen --private alice_private.pem --public alice_public.pem
python stream_encrypt.py keygen --private bob_private.pem --public bob_public.pem
```

程序交互式提示设置私钥口令（至少 12 字符）。私钥为加密 PEM 文件，不要上传到共享仓库。建议将私钥置于权限受控目录，另行做加密备份。

### 3.2 默认加密：zstd -6

```bash
python stream_encrypt.py encrypt ./mydata --public alice_public.pem -o mydata.fcs4
```

加密多个输入文件/目录：

```bash
python stream_encrypt.py encrypt ./mydata ./config.json --public alice_public.pem -o bundle.fcs4
```

### 3.3 多公钥授权

```bash
python stream_encrypt.py encrypt ./mydata \
  --public alice_public.pem \
  --public bob_public.pem \
  -o shared.fcs4
```

### 3.4 指定压缩算法和级别

```bash
# zstd -3：更侧重速度
python stream_encrypt.py encrypt ./mydata --public alice_public.pem --compression zstd --compression-level 3 -o fast.fcs4

# zstd -9：更侧重压缩率
python stream_encrypt.py encrypt ./mydata --public alice_public.pem --compression zstd --compression-level 9 -o compact.fcs4

# gzip -9：不依赖 zstandard 包
python stream_encrypt.py encrypt ./mydata --public alice_public.pem --compression gzip --compression-level 9 -o gzip.fcs4

# none：只打包不压缩，仍使用 AES-GCM 加密
python stream_encrypt.py encrypt ./mydata --public alice_public.pem --compression none -o raw.fcs4

# 指定加密分块大小 4 MiB
python stream_encrypt.py encrypt ./mydata --public alice_public.pem --chunk-mib 4 -o chunks4.fcs4
```

合法范围：`zstd 1..22`、`gzip 1..9`、`none 0`；不传 `--compression-level` 时分别默认 `6`、`9`、`0`。

### 3.5 解密

```bash
python stream_encrypt.py decrypt shared.fcs4 --private alice_private.pem -o ./restored
```

解密自动识别 FCS4 中的压缩算法，解密目录 **必须尚不存在**。文件解压会先写入目标目录旁的临时目录，完整性校验通过后才重命名到最终目录。

### 3.6 查看授权接收者

```bash
python stream_encrypt.py recipients shared.fcs4
```

输出每个公钥的 SHA-256 指纹（Key ID），**不是姓名**；该命令只读取授权表，不能验证整个数据密文的完整性。

## 4. 密钥授权与轮换

### 4.1 添加 Bob 的授权，保留旧接收者

```bash
python stream_encrypt.py rotate shared.fcs4 \
  --private alice_private.pem \
  --public bob_public.pem \
  -o shared_plus_bob.fcs4
```

### 4.2 替换授权列表，仅保留 Bob

```bash
python stream_encrypt.py rotate shared.fcs4 \
  --private alice_private.pem \
  --public bob_public.pem \
  --replace \
  -o bob_only.fcs4
```

`--replace` 后可以重复 `--public` 指定完整的新接收者集合。`rotate` 只认证旧授权表并复制密文，**不逐块验证源数据**。如需验证，使用受信任私钥在隔离目录执行完整解密校验。请先验证新文件可解密，再考虑处理旧文件副本。

**真正的泄露应急轮换**：如果旧 DEK 可能已经泄露，必须用新的随机 DEK 重新加密原始明文；仅 `rotate` 不够。

## 5. 100 GiB 及更大文件

解密默认限制：单文件不超过 1024 GiB、全部解压数据不超过 1024 GiB、压缩流不超过 1024 GiB、归档成员数不超过 100000。可以按需降低或调整：

```bash
python stream_encrypt.py decrypt large.fcs4 --private alice_private.pem \
  -o ./large_restored \
  --max-file-gib 200 \
  --max-total-gib 300 \
  --max-packed-gib 200 \
  --max-files 100000
```

该工具使用流式处理，不会一次把100 GiB读入内存。实际吞吐取决于 CPU、磁盘、压缩级别和文件内容；zstd 高级别可能消耗大量内存。当前实现为单压缩流，不提供 zstd 多线程压缩开关。

## 6. Python API

```python
from fcs4 import encrypt, decrypt, rotate, recipients

encrypt(["./mydata"], "data.fcs4", ["alice_public.pem", "bob_public.pem"],
        compression="zstd", compression_level=6)

# decrypt() 和 rotate() 会交互式提示输入私钥口令
decrypt("data.fcs4", "./restored", "alice_private.pem")
rotate("data.fcs4", "data_new.fcs4", "alice_private.pem", ["bob_public.pem"], replace=True)
print(recipients("data_new.fcs4"))
```

目前不支持通过 API 传入口令、KMS 或硬件安全模块，也没有随机访问解密接口。

## 7. 注意事项与已知限制

1. 不允许输入符号链接、归档内符号链接、设备文件等非普通文件；不要把输出放进待打包目录。
2. 输出文件、输出解压目录已存在时拒绝覆盖，避免误删数据。
3. **加密端读取文件时没有制作不可变快照**。如源文件被其他进程同时修改，归档内容可能不一致；建议先做快照或暂停写入。
4. 解压时会拒绝绝对路径、`..`、重复归档路径及非普通文件/目录；解压目录临时阶段权限由系统创建。请不要把未受信任的文件用于高权限执行环境。
5. zstd 默认依赖 Python `zstandard` 第三方包。若未安装，可以使用 `--compression gzip` 或安装依赖。
6. `rotate` 生成新文件，至少需要新文件大小的可用磁盘空间；不会就地覆盖。
7. FCS3 文件可以解密/轮换，但轮换不会自动把旧 FCS3 格式升级为 FCS4。要转换格式，需先解密，再使用 FCS4 重新加密。
8. FCS4 文件头可暴露压缩算法、压缩级别、分块大小、公钥指纹及接收者数量；**业务文件名和内容**位于加密数据中。
9. AES-GCM 的安全性依赖于随机密钥和 Nonce 唯一性。该实现每个文件独立随机生成密钥与 Nonce 前缀。
10. 对于敏感数据，建议开展第三方密码学与文件系统安全审计，并在实际业务数据上测试压缩率、吞吐和异常恢复。

## 8. 验证

```bash
python -m py_compile stream_encrypt.py
python -m unittest -v test_stream_encrypt.py
```

自动测试包括 gzip/none 的加密解密、多接收者授权、轮换、授权撤销、密文篡改检测；如果已安装 zstandard，还会测试 zstd -6 的往返。测试不代替生产环境安全审计或100 GiB压力测试。
