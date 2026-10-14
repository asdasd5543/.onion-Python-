#!/usr/bin/env python3
"""Generate a Tor v3 onion service identity and Tor-compatible key files."""

from __future__ import annotations

import argparse
import base64
import ctypes
import ctypes.util
import hashlib
import os
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

ONION_VERSION = b"\x03"
ONION_CHECKSUM_PREFIX = b".onion checksum"
SECRET_KEY_HEADER = b"== ed25519v1-secret: type0 ==\x00\x00\x00"
PUBLIC_KEY_HEADER = b"== ed25519v1-public: type0 ==\x00\x00\x00"
_ED25519_NID = 1087
_OPENSSL = None


@dataclass(frozen=True)
class OnionKeypair:
    """An Ed25519 identity and its corresponding Tor v3 onion address."""

    seed: bytes
    public_key: bytes
    address: str

    @property
    def secret_key(self) -> bytes:
        """Tor's 64-byte Ed25519 secret key representation (seed + public key)."""
        return self.seed + self.public_key


def address_from_public_key(public_key: bytes) -> str:
    """Derive the 56-character v3 onion address for a 32-byte Ed25519 key."""
    if len(public_key) != 32:
        raise ValueError("Ed25519 public keys must be exactly 32 bytes")
    checksum = hashlib.sha3_256(
        ONION_CHECKSUM_PREFIX + public_key + ONION_VERSION
    ).digest()[:2]
    encoded = base64.b32encode(public_key + checksum + ONION_VERSION)
    return encoded.decode("ascii").lower().rstrip("=") + ".onion"


def validate_onion_address(address: str) -> bool:
    """Return whether address has a valid Tor v3 length, version, and checksum."""
    if not isinstance(address, str) or not address.endswith(".onion"):
        return False
    label = address[:-6]
    if len(label) != 56 or label.lower() != label:
        return False
    try:
        decoded = base64.b32decode(label.upper(), casefold=False)
    except (ValueError, base64.binascii.Error):
        return False
    if len(decoded) != 35:
        return False
    public_key, checksum, version = decoded[:32], decoded[32:34], decoded[34:]
    expected = hashlib.sha3_256(
        ONION_CHECKSUM_PREFIX + public_key + version
    ).digest()[:2]
    return version == ONION_VERSION and checksum == expected


def _load_openssl():
    """Load the OpenSSL runtime shipped with CPython (or the system runtime)."""
    global _OPENSSL
    if _OPENSSL is not None:
        return _OPENSSL

    candidates = []
    if os.name == "nt":
        import _ssl

        candidates = sorted(
            Path(_ssl.__file__).resolve().parent.glob("libcrypto-*.dll"),
            reverse=True,
        )
    else:
        library_name = ctypes.util.find_library("crypto")
        if library_name:
            candidates.append(library_name)

    for candidate in candidates:
        try:
            if os.name == "nt":
                library = ctypes.WinDLL(str(candidate))
            else:
                library = ctypes.CDLL(str(candidate))
            library.OBJ_txt2nid.argtypes = [ctypes.c_char_p]
            library.OBJ_txt2nid.restype = ctypes.c_int
            library.EVP_PKEY_new_raw_private_key.argtypes = [
                ctypes.c_int,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
            ]
            library.EVP_PKEY_new_raw_private_key.restype = ctypes.c_void_p
            library.EVP_PKEY_get_raw_public_key.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_size_t),
            ]
            library.EVP_PKEY_get_raw_public_key.restype = ctypes.c_int
            library.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
            library.EVP_PKEY_free.restype = None
            if library.OBJ_txt2nid(b"ED25519") != _ED25519_NID:
                continue
            _OPENSSL = library
            return library
        except (AttributeError, OSError):
            continue

    raise RuntimeError(
        "找不到支持 Ed25519 的 OpenSSL。请使用自带 OpenSSL 1.1.1 或更新版本的 "
        "CPython；无需安装 PyNaCl 或其他 Python 包。"
    )


def ed25519_public_key(seed: bytes) -> bytes:
    """Derive an Ed25519 public key with the interpreter's OpenSSL runtime."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seeds must be exactly 32 bytes")
    openssl = _load_openssl()
    seed_buffer = ctypes.create_string_buffer(seed, len(seed))
    private_key = openssl.EVP_PKEY_new_raw_private_key(
        _ED25519_NID, None, seed_buffer, len(seed)
    )
    if not private_key:
        raise RuntimeError("OpenSSL 无法创建 Ed25519 私钥")
    try:
        public_buffer = ctypes.create_string_buffer(32)
        public_length = ctypes.c_size_t(len(public_buffer))
        result = openssl.EVP_PKEY_get_raw_public_key(
            private_key, public_buffer, ctypes.byref(public_length)
        )
        if result != 1 or public_length.value != 32:
            raise RuntimeError("OpenSSL 无法导出 Ed25519 公钥")
        return public_buffer.raw
    finally:
        openssl.EVP_PKEY_free(private_key)


def generate_keypair() -> OnionKeypair:
    """Generate a cryptographically random Ed25519 identity."""
    seed = secrets.token_bytes(32)
    public_key = ed25519_public_key(seed)
    return OnionKeypair(
        seed=seed,
        public_key=public_key,
        address=address_from_public_key(public_key),
    )


def _write_key_file(path: Path, header: bytes, key: bytes) -> None:
    contents = base64.b64encode(header + key)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as key_file:
            key_file.write(contents)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def save_tor_keys(
    keypair: OnionKeypair, output_dir: Path
) -> Tuple[Path, Path]:
    """Create a new service directory containing Tor v3 private/public key files."""
    if len(keypair.seed) != 32 or len(keypair.public_key) != 32:
        raise ValueError("Ed25519 seed and public key must each be 32 bytes")
    if ed25519_public_key(keypair.seed) != keypair.public_key:
        raise ValueError("Ed25519 seed does not match the public key")
    if keypair.address != address_from_public_key(keypair.public_key):
        raise ValueError("onion address does not match the public key")

    output_dir = Path(output_dir)
    output_dir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output_dir.mkdir(mode=0o700)
    secret_path = output_dir / "hs_ed25519_secret_key"
    public_path = output_dir / "hs_ed25519_public_key"
    try:
        _write_key_file(secret_path, SECRET_KEY_HEADER, keypair.secret_key)
        _write_key_file(public_path, PUBLIC_KEY_HEADER, keypair.public_key)
    except BaseException:
        for path in (secret_path, public_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        output_dir.rmdir()
        raise
    return secret_path, public_path


def wait_for_return() -> bool:
    """Wait for Enter before resuming the main menu."""
    try:
        input("按回车返回主菜单...")
        return True
    except EOFError:
        return False
    except KeyboardInterrupt:
        print("\n继续返回主菜单。")
        return True


def read_positive_count() -> Optional[int]:
    """Read a positive batch size, or return None if the prompt is interrupted."""
    while True:
        try:
            value = input("请输入生成数量（正整数）：").strip()
        except EOFError:
            return None
        except KeyboardInterrupt:
            print("\n已取消数量输入。")
            return None
        if value.isascii() and value.isdecimal():
            try:
                count = int(value)
            except ValueError:
                count = 0
            if count > 0:
                return count
        print("输入无效，请输入大于 0 的整数。")


def generate_batch(output_dir: Path, limit: Optional[int]) -> int:
    """Generate and save up to limit identities; None means continue until Ctrl+C."""
    generated = 0
    while limit is None or generated < limit:
        keypair = generate_keypair()
        service_dir = Path(output_dir) / keypair.address[:-6]
        secret_path, public_path = save_tor_keys(keypair, service_dir)
        generated += 1
        print(f"\n第 {generated} 个 .onion 地址：{keypair.address}")
        print(f"保存目录：{service_dir}")
        print(f"私钥文件：{secret_path}")
        print(f"公钥文件：{public_path}")
        if limit is None:
            time.sleep(1)
    return generated


def run_interactive(output_dir: Path) -> int:
    print(".onion地址生成器")
    print("点击Enter继续")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        return 0

    while True:
        print("\n主菜单")
        print("1. 无限生成")
        print("2. 自己选择生成数量")
        print("0. 退出")
        try:
            choice = input("请选择：").strip()
        except (EOFError, KeyboardInterrupt):
            return 0

        if choice in ("0", "q", "Q"):
            return 0
        if choice not in ("1", "2"):
            print("无效选项，请重新选择。")
            continue

        limit = None if choice == "1" else read_positive_count()
        if choice == "2" and limit is None:
            continue

        try:
            generated = generate_batch(output_dir, limit)
        except KeyboardInterrupt:
            print("\n已停止当前生成流程。")
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"生成失败，当前流程已停止：{exc}")
        else:
            print(f"\n本次生成完成，共生成 {generated} 个地址。")

        if not wait_for_return():
            return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a random Tor v3 onion address and service keypair."
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("onion_service"),
        help="new directory for Tor-compatible keys (default: ./onion_service)",
    )
    args = parser.parse_args(argv)
    return run_interactive(args.output_dir)


if __name__ == "__main__":
    raise SystemExit(main())
