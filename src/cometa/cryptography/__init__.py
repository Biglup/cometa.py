# pylint: disable=undefined-all-variable
"""
Copyright 2025 Biglup Labs.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from typing import Any

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "Blake2bHash": (".blake2b_hash", "Blake2bHash"),
    "Blake2bHashSize": (".blake2b_hash_size", "Blake2bHashSize"),
    "Blake2bHashSet": (".blake2b_hash_set", "Blake2bHashSet"),
    "Ed25519Signature": (".ed25519_signature", "Ed25519Signature"),
    "Ed25519PublicKey": (".ed25519_public_key", "Ed25519PublicKey"),
    "Ed25519PrivateKey": (".ed25519_private_key", "Ed25519PrivateKey"),
    "Bip32PublicKey": (".bip32_public_key", "Bip32PublicKey"),
    "Bip32PrivateKey": (".bip32_private_key", "Bip32PrivateKey"),
    "harden": (".bip32_private_key", "harden"),
    "crc32": (".crc32", "crc32"),
    "pbkdf2_hmac_sha512": (".pbkdf2", "pbkdf2_hmac_sha512"),
    "emip3_encrypt": (".emip3", "emip3_encrypt"),
    "emip3_decrypt": (".emip3", "emip3_decrypt"),
}

_cache: dict[str, Any] = {}


def __getattr__(name: str) -> Any:
    if name in _cache:
        return _cache[name]

    if name in _LAZY_IMPORTS:
        module_path, attr_name = _LAZY_IMPORTS[name]
        from importlib import import_module
        module = import_module(module_path, __name__)
        value = getattr(module, attr_name)
        _cache[name] = value
        globals()[name] = value
        return value

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return list(__all__)


__all__ = [
    "Bip32PrivateKey",
    "Bip32PublicKey",
    "Blake2bHash",
    "Blake2bHashSet",
    "Blake2bHashSize",
    "Ed25519PrivateKey",
    "Ed25519PublicKey",
    "Ed25519Signature",
    "crc32",
    "emip3_decrypt",
    "emip3_encrypt",
    "harden",
    "pbkdf2_hmac_sha512",
]
