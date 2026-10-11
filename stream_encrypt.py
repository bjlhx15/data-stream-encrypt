#!/usr/bin/env python3
"""FCS4: multi-recipient RSA-OAEP, AES-256-GCM, gzip/zstd streaming, key rewrapping."""
import argparse
import getpass
import gzip
import contextlib
import hashlib
import hmac
import json
import os
import stat
import shutil
import struct
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"FCS4"
LEGACY_MAGIC = b"FCS3"
ALGO = {"none": 0, "gzip": 1, "zstd": 2}
ALGO_BY_ID = {v: k for k, v in ALGO.items()}
U32 = struct.Struct(">I")
U64 = struct.Struct(">Q")
MIN_CHUNK, MAX_CHUNK = 64*1024, 8*1024*1024
DEFAULT_CHUNK = 1024*1024
TAG_LEN = 16
MAX_SLOTS_BYTES = 1024*1024
MAX_RECIPIENTS = 64
IMMUTABLE_LEN = 4+4+4+32+2  # magic, chunk, nonce prefix, file identifier, compression id/level


def exact(fp, n):
    out = bytearray()
    while len(out) < n:
        part = fp.read(n-len(out))
        if not part:
            raise ValueError("文件截断")
        out.extend(part)
    return bytes(out)


def oaep(label):
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label)


def key_id(key):
    pub = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def keygen(private_path, public_path):
    private_path, public_path = Path(private_path), Path(public_path)
    if private_path.resolve() == public_path.resolve() or private_path.exists() or public_path.exists():
        raise ValueError("密钥路径相同或文件已存在")
    password = getpass.getpass("设置私钥密码：")
    if len(password) < 12 or password != getpass.getpass("再次确认："):
        raise ValueError("密码至少12字符且两次一致")
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_bytes = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.BestAvailableEncryption(password.encode()))
    public_bytes = key.public_key().public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(private_bytes)
        with open(public_path, "xb") as f:
            f.write(public_bytes)
    except BaseException:
        private_path.unlink(missing_ok=True)
        raise


def load_public(path):
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072:
        raise ValueError("RSA公钥必须至少3072位")
    return key


def load_private(path):
    password = getpass.getpass(f"私钥密码 ({path})：").encode()
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=password)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 3072:
        raise ValueError("RSA私钥必须至少3072位")
    return key


def mac_key(aes_key, immutable):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=immutable[12:],
                info=b"FCS3 recipient table authentication").derive(aes_key)


def encode_slots(slots):
    return json.dumps(slots, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def table_mac(aes_key, immutable, slot_bytes):
    return hmac.digest(mac_key(aes_key, immutable), immutable + U32.pack(len(slot_bytes)) + slot_bytes, "sha256")


def make_slots(public_paths, aes_key, immutable):
    if not 1 <= len(public_paths) <= MAX_RECIPIENTS:
        raise ValueError("接收者数量必须为1到64")
    keys = {}
    for path in public_paths:
        pub = load_public(path)
        keys[key_id(pub)] = pub
    if not 1 <= len(keys) <= MAX_RECIPIENTS:
        raise ValueError("没有有效公钥")
    slots = [{"kid": kid, "wrapped": pub.encrypt(aes_key, oaep(immutable[12:])).hex()}
             for kid, pub in sorted(keys.items())]
    return slots


def write_envelope(fp, immutable, slots, aes_key):
    data = encode_slots(slots)
    if len(data) > MAX_SLOTS_BYTES:
        raise ValueError("密钥授权表过大")
    fp.write(immutable + U32.pack(len(data)) + data + table_mac(aes_key, immutable, data))


def valid_level(algorithm, level):
    return (algorithm == "none" and level == 0 or
            algorithm == "gzip" and 1 <= level <= 9 or
            algorithm == "zstd" and 1 <= level <= 22)


def compression_from_header(immutable):
    if immutable[:4] == LEGACY_MAGIC:
        return "gzip", 9
    return ALGO_BY_ID[immutable[-2]], immutable[-1]


def zstd_module():
    try:
        import zstandard
        return zstandard
    except ImportError as exc:
        raise RuntimeError("zstd 需要先安装: python3 -m pip install zstandard") from exc


@contextlib.contextmanager
def compression_writer(writer, algorithm, level):
    if algorithm == "none":
        yield writer
    elif algorithm == "gzip":
        with gzip.GzipFile(fileobj=writer, mode="wb", compresslevel=level, mtime=0) as stream:
            yield stream
    else:
        zstd = zstd_module()
        with zstd.ZstdCompressor(level=level).stream_writer(writer, closefd=False) as stream:
            yield stream


@contextlib.contextmanager
def compression_reader(reader, algorithm):
    if algorithm == "none":
        yield reader
    elif algorithm == "gzip":
        with gzip.GzipFile(fileobj=reader, mode="rb") as stream:
            yield stream
    else:
        zstd = zstd_module()
        with zstd.ZstdDecompressor().stream_reader(reader, closefd=False) as stream:
            yield stream


def read_envelope(fp):
    magic = exact(fp, 4)
    if magic not in (MAGIC, LEGACY_MAGIC):
        raise ValueError("不是FCS3/FCS4格式")
    immutable = magic + exact(fp, (IMMUTABLE_LEN if magic == MAGIC else IMMUTABLE_LEN - 2) - 4)
    if magic == MAGIC:
        algorithm_id, level = immutable[-2:]
        if algorithm_id not in ALGO_BY_ID:
            raise ValueError("未知压缩算法")
        if not valid_level(ALGO_BY_ID[algorithm_id], level):
            raise ValueError("压缩级别不合法")
    chunk_size = U32.unpack(immutable[4:8])[0]
    if not MIN_CHUNK <= chunk_size <= MAX_CHUNK:
        raise ValueError("非法分块大小")
    length = U32.unpack(exact(fp, 4))[0]
    if not 1 <= length <= MAX_SLOTS_BYTES:
        raise ValueError("非法授权表大小")
    data = exact(fp, length)
    signature = exact(fp, 32)
    slots = json.loads(data)
    if not isinstance(slots, list) or not 1 <= len(slots) <= MAX_RECIPIENTS:
        raise ValueError("非法授权表")
    if encode_slots(slots) != data:
        raise ValueError("授权表编码不规范")
    ids = set()
    for slot in slots:
        if not isinstance(slot, dict) or set(slot) != {"kid", "wrapped"}:
            raise ValueError("非法密钥记录")
        kid, wrapped = slot["kid"], slot["wrapped"]
        if not isinstance(kid, str) or len(kid) != 64 or not isinstance(wrapped, str) or len(wrapped) > 16384:
            raise ValueError("非法密钥记录")
        if kid in ids:
            raise ValueError("重复接收者")
        ids.add(kid)
    return immutable, chunk_size, slots, data, signature, fp.tell()


def unlock(private, envelope):
    immutable, _, slots, data, signature, _ = envelope
    kid = key_id(private)
    match = next((s for s in slots if s["kid"] == kid), None)
    if match is None:
        raise ValueError("当前私钥不在授权列表中")
    aes_key = private.decrypt(bytes.fromhex(match["wrapped"]), oaep(immutable[12:]))
    if len(aes_key) != 32 or not hmac.compare_digest(signature, table_mac(aes_key, immutable, data)):
        raise ValueError("授权表认证失败")
    return aes_key


class EncryptedWriter:
    def __init__(self, fp, key, immutable, chunk_size):
        self.fp, self.header, self.chunk_size = fp, immutable, chunk_size
        self.aes = AESGCM(key)
        self.prefix = immutable[8:12]
        self.buf = bytearray()
        self.count = self.total = self.pos = 0
        self.done = False

    def writable(self):
        return True

    def tell(self):
        return self.pos

    def flush(self):
        self.fp.flush()

    def write(self, data):
        if self.done:
            raise ValueError("加密已结束")
        data = memoryview(data)
        length = len(data)
        self.pos += length
        while data:
            n = min(self.chunk_size-len(self.buf), len(data))
            self.buf.extend(data[:n])
            data = data[n:]
            if len(self.buf) == self.chunk_size:
                self.emit()
        return length

    def emit(self):
        if not self.buf:
            return
        if self.count >= 2**64-1:
            raise ValueError("分块序号溢出")
        plain = bytes(self.buf)
        self.buf.clear()
        index = U64.pack(self.count)
        aad = self.header + b"\x00" + index + U32.pack(len(plain))
        ct = self.aes.encrypt(self.prefix+index, plain, aad)
        self.fp.write(b"\x00" + U32.pack(len(ct)) + ct)
        self.count += 1
        self.total += len(plain)

    def finish(self):
        if self.done:
            return
        self.emit()
        index = U64.pack(self.count)
        aad = self.header + b"\x01" + index + U64.pack(self.total)
        tag = self.aes.encrypt(self.prefix+index, b"", aad)
        self.fp.write(b"\x01" + U32.pack(len(tag)) + tag)
        self.done = True


class DecryptedReader:
    def __init__(self, fp, key, immutable, chunk_size, max_packed_bytes):
        self.fp, self.header, self.chunk_size = fp, immutable, chunk_size
        self.prefix = immutable[8:12]
        self.aes = AESGCM(key)
        self.count = self.total = self.offset = 0
        self.max_packed_bytes = max_packed_bytes
        self.buf = b""
        self.done = False

    def readable(self):
        return True

    def next_record(self):
        flag = exact(self.fp, 1)
        ct_len = U32.unpack(exact(self.fp, 4))[0]
        index = U64.pack(self.count)
        if flag == b"\x00":
            if self.count >= 2**64-1 or not TAG_LEN < ct_len <= self.chunk_size+TAG_LEN:
                raise ValueError("非法数据块长度")
            length = ct_len-TAG_LEN
            if self.total+length > self.max_packed_bytes:
                raise ValueError("压缩数据超限")
            aad = self.header+flag+index+U32.pack(length)
            self.buf = self.aes.decrypt(self.prefix+index, exact(self.fp, ct_len), aad)
            self.offset = 0
            self.count += 1
            self.total += length
        elif flag == b"\x01":
            if ct_len != TAG_LEN:
                raise ValueError("非法结束标记")
            aad = self.header+flag+index+U64.pack(self.total)
            self.aes.decrypt(self.prefix+index, exact(self.fp, TAG_LEN), aad)
            if self.fp.read(1):
                raise ValueError("结束标记后有额外数据")
            self.done = True
        else:
            raise ValueError("非法记录类型")

    def read(self, size=-1):
        if size == 0:
            return b""
        if size is None or size < 0:
            return b"".join(iter(lambda: self.read(65536), b""))
        result = bytearray()
        while len(result) < size:
            if self.offset < len(self.buf):
                n = min(size-len(result), len(self.buf)-self.offset)
                result.extend(self.buf[self.offset:self.offset+n])
                self.offset += n
            elif self.done:
                break
            else:
                self.next_record()
        return bytes(result)

    def verify_end(self):
        while self.read(65536):
            pass
        if not self.done:
            raise ValueError("缺少结束认证")

def safe_name(name):
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        raise ValueError("非法归档路径")
    parts = name.rstrip("/").split("/")
    if any(p in ("", ".", "..") for p in parts) or ":" in parts[0]:
        raise ValueError("非法归档路径")
    return PurePosixPath(*parts)


def encrypt(inputs, destination, public_key_paths, chunk_size=DEFAULT_CHUNK,
            compression="zstd", compression_level=None):
    if compression not in ALGO:
        raise ValueError("压缩类型仅支持 zstd、gzip、none")
    if compression_level is None:
        compression_level = {"zstd": 6, "gzip": 9, "none": 0}[compression]
    if not valid_level(compression, compression_level):
        raise ValueError("压缩级别不合法：zstd 1..22，gzip 1..9，none 0")
    if not MIN_CHUNK <= chunk_size <= MAX_CHUNK:
        raise ValueError("非法分块大小")
    for item in inputs:
        if Path(item).is_symlink():
            raise ValueError(f"不支持符号链接输入：{item}")
    sources = [Path(p).resolve(strict=True) for p in inputs]
    dest = Path(destination).resolve()
    if dest.exists():
        raise FileExistsError("目标文件已存在")
    if len({p.name for p in sources}) != len(sources):
        raise ValueError("输入顶层文件名重复")
    for src in sources:
        if not (src.is_file() or src.is_dir()):
            raise ValueError(f"不支持的输入：{src}")
        if src == dest or (src.is_dir() and src in dest.parents):
            raise ValueError("输出不能位于输入目录中")
    aes_key = os.urandom(32)
    immutable = (MAGIC + U32.pack(chunk_size) + os.urandom(4) + os.urandom(32)
                 + bytes([ALGO[compression], compression_level]))
    slots = make_slots(public_key_paths, aes_key, immutable)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=dest.parent, prefix=".fcs4-", delete=False) as f:
            tmp = Path(f.name)
            write_envelope(f, immutable, slots, aes_key)
            writer = EncryptedWriter(f, aes_key, immutable, chunk_size)
            with compression_writer(writer, compression, compression_level) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as tf:
                    for src in sources:
                        if src.is_file():
                            tf.add(src, arcname=src.name, recursive=False)
                        else:
                            tf.add(src, arcname=src.name, recursive=False)
                            for root, dirs, files in os.walk(src, followlinks=False):
                                for name in dirs + files:
                                    child = Path(root) / name
                                    if child.is_symlink() or not (child.is_file() or child.is_dir()):
                                        raise ValueError(f"不支持的文件类型：{child}")
                                    tf.add(child, arcname=child.relative_to(src.parent).as_posix(), recursive=False)
            writer.finish()
            f.flush()
            os.fsync(f.fileno())
        os.link(tmp, dest)
        return dest
    finally:
        if tmp:
            tmp.unlink(missing_ok=True)


def decrypt(source, destination, private_key_path, *,
            max_files=100000, max_total_bytes=1024*1024**3,
            max_file_bytes=1024*1024**3, max_packed_bytes=1024*1024**3):
    private = load_private(private_key_path)
    dest = Path(destination).resolve()
    if dest.exists():
        raise FileExistsError("输出目录已存在")
    dest.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".fcs4-unpack-", dir=dest.parent))
    success = False
    try:
        count = total = 0
        seen = set()
        with open(source, "rb") as f:
            envelope = read_envelope(f)
            aes_key = unlock(private, envelope)
            reader = DecryptedReader(f, aes_key, envelope[0], envelope[1], max_packed_bytes)
            algorithm, _ = compression_from_header(envelope[0])
            with compression_reader(reader, algorithm) as compressed:
                with tarfile.open(fileobj=compressed, mode="r|") as tf:
                    for member in tf:
                        count += 1
                        if count > max_files:
                            raise ValueError("文件数量超限")
                        rel = safe_name(member.name)
                        if rel in seen:
                            raise ValueError("归档路径重复")
                        seen.add(rel)
                        target = stage.joinpath(*rel.parts)
                        if member.isdir():
                            target.mkdir(parents=True, exist_ok=True)
                        elif member.isfile():
                            if member.size > max_file_bytes or total + member.size > max_total_bytes:
                                raise ValueError("解压大小超限")
                            total += member.size
                            target.parent.mkdir(parents=True, exist_ok=True)
                            with tf.extractfile(member) as inp, open(target, "xb") as out:
                                remaining = member.size
                                while remaining:
                                    part = inp.read(min(1024*1024, remaining))
                                    if not part:
                                        raise ValueError("归档内容截断")
                                    out.write(part)
                                    remaining -= len(part)
                        else:
                            raise ValueError("不支持的归档成员类型")
            reader.verify_end()
        os.rename(stage, dest)
        success = True
        return dest
    finally:
        if not success:
            shutil.rmtree(stage)



def recipients(source):
    with open(source, "rb") as f:
        envelope = read_envelope(f)
    return [s["kid"] for s in envelope[2]]


def rotate(source, destination, private_path, public_paths, *, replace=False):
    """Rewrap existing DEK for a new recipient set, copying ciphertext without decrypting payload."""
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if source == destination or destination.exists():
        raise ValueError("轮换输出必须是一个尚不存在的新文件")
    private = load_private(private_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        with open(source, "rb") as inp:
            envelope = read_envelope(inp)
            aes_key = unlock(private, envelope)
            immutable = envelope[0]
            old_slots = {s["kid"]: s for s in envelope[2]}
            if replace:
                new_slots = make_slots(public_paths, aes_key, immutable)
            else:
                new_slots = list(old_slots.values())
                for slot in make_slots(public_paths, aes_key, immutable):
                    old_slots[slot["kid"]] = slot
                new_slots = [old_slots[k] for k in sorted(old_slots)]
            with tempfile.NamedTemporaryFile(mode="wb", dir=destination.parent,
                                             prefix=".fcs4-rotate-", delete=False) as out:
                tmp = Path(out.name)
                write_envelope(out, immutable, new_slots, aes_key)
                shutil.copyfileobj(inp, out, length=1024*1024)
                out.flush()
                os.fsync(out.fileno())
        os.link(tmp, destination)
    finally:
        if tmp:
            tmp.unlink(missing_ok=True)


def main():
    p = argparse.ArgumentParser(description="FCS4 RSA多公钥授权、密钥轮换、AES-GCM流式文件加密")
    subs = p.add_subparsers(dest="cmd", required=True)
    kg = subs.add_parser("keygen")
    kg.add_argument("--private", default="private.pem")
    kg.add_argument("--public", default="public.pem")
    enc = subs.add_parser("encrypt")
    enc.add_argument("inputs", nargs="+")
    enc.add_argument("-o", "--output", required=True)
    enc.add_argument("--public", action="append", required=True, help="可重复指定")
    enc.add_argument("--chunk-mib", type=int, default=1, choices=range(1, 9))
    enc.add_argument("--compression", choices=["zstd", "gzip", "none"], default="zstd",
                     help="默认 zstd")
    enc.add_argument("--compression-level", type=int, default=None,
                     help="zstd: 1-22 (默认6); gzip: 1-9 (默认9); none: 0")
    dec = subs.add_parser("decrypt")
    dec.add_argument("input")
    dec.add_argument("-o", "--output", required=True)
    dec.add_argument("--private", required=True)
    dec.add_argument("--max-file-gib", type=int, default=1024, help="单文件最大解压大小，默认1024 GiB")
    dec.add_argument("--max-total-gib", type=int, default=1024, help="全部文件最大解压大小，默认1024 GiB")
    dec.add_argument("--max-packed-gib", type=int, default=1024, help="最大压缩流大小，默认1024 GiB")
    dec.add_argument("--max-files", type=int, default=100000)
    rot = subs.add_parser("rotate")
    rot.add_argument("input")
    rot.add_argument("-o", "--output", required=True)
    rot.add_argument("--private", required=True, help="当前已授权私钥")
    rot.add_argument("--public", action="append", required=True, help="新增公钥或替换后的完整公钥列表")
    rot.add_argument("--replace", action="store_true", help="用--public完全替换现有授权（撤销旧授权）")
    ls = subs.add_parser("recipients")
    ls.add_argument("input")
    args = p.parse_args()
    if args.cmd == "keygen":
        keygen(args.private, args.public)
    elif args.cmd == "encrypt":
        encrypt(args.inputs, args.output, args.public, args.chunk_mib*1024**2, args.compression, args.compression_level)
    elif args.cmd == "decrypt":
        if min(args.max_file_gib, args.max_total_gib, args.max_packed_gib, args.max_files) <= 0:
            p.error("解压限制必须为正整数")
        decrypt(args.input, args.output, args.private,
                max_file_bytes=args.max_file_gib * 1024**3,
                max_total_bytes=args.max_total_gib * 1024**3,
                max_packed_bytes=args.max_packed_gib * 1024**3,
                max_files=args.max_files)
    elif args.cmd == "rotate":
        rotate(args.input, args.output, args.private, args.public, replace=args.replace)
    else:
        for kid in recipients(args.input):
            print(kid)
    if args.cmd != "recipients":
        print("完成")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, InvalidTag, tarfile.TarError, KeyError, TypeError) as e:
        raise SystemExit(f"失败：{e}") from e
