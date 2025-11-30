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

from __future__ import annotations
from typing import List, Union

from .._ffi import ffi, lib
from ..errors import CardanoError


def entropy_to_mnemonic(entropy: Union[bytes, bytearray]) -> List[str]:
    """
    Converts entropy into a BIP-39 mnemonic word sequence.

    Takes entropy bytes and converts them into a corresponding BIP-39 mnemonic
    phrase using the English wordlist.

    Args:
        entropy: The entropy bytes. Supported sizes are:
            - 16 bytes (128 bits) -> 12 words
            - 20 bytes (160 bits) -> 15 words
            - 24 bytes (192 bits) -> 18 words
            - 28 bytes (224 bits) -> 21 words
            - 32 bytes (256 bits) -> 24 words

    Returns:
        List of mnemonic words from the English BIP-39 wordlist.

    Raises:
        CardanoError: If the entropy size is invalid.

    Example:
        >>> entropy = bytes(16)
        >>> words = entropy_to_mnemonic(entropy)
        >>> len(words)
        12
    """
    entropy_size = len(entropy)

    words = ffi.new("const char*[24]")
    word_count = ffi.new("size_t*")

    c_entropy = ffi.from_buffer("byte_t[]", entropy)

    err = lib.cardano_bip39_entropy_to_mnemonic_words(
        c_entropy, entropy_size, words, word_count
    )

    if err != 0:
        raise CardanoError(f"Failed to convert entropy to mnemonic (error code: {err})")

    result = []
    for i in range(word_count[0]):
        word = ffi.string(words[i]).decode("utf-8")
        result.append(word)

    return result


def mnemonic_to_entropy(words: List[str]) -> bytes:
    """
    Converts a BIP-39 mnemonic word sequence back into entropy.

    Takes a mnemonic phrase and converts it back into the original entropy bytes.
    The words must be valid English BIP-39 words with a correct checksum.

    Args:
        words: List of BIP-39 English mnemonic words. Supported lengths are:
            - 12 words -> 16 bytes (128-bit entropy)
            - 15 words -> 20 bytes (160-bit entropy)
            - 18 words -> 24 bytes (192-bit entropy)
            - 21 words -> 28 bytes (224-bit entropy)
            - 24 words -> 32 bytes (256-bit entropy)

    Returns:
        The entropy bytes corresponding to the mnemonic.

    Raises:
        CardanoError: If the word count is invalid, words are not in the
            wordlist, or the checksum is incorrect.

    Example:
        >>> words = ["abandon"] * 11 + ["about"]
        >>> entropy = mnemonic_to_entropy(words)
        >>> len(entropy)
        16
    """
    word_count = len(words)

    encoded_words = [w.encode("utf-8") for w in words]
    c_words = ffi.new("const char*[]", [ffi.from_buffer(w) for w in encoded_words])

    entropy_buf = ffi.new("byte_t[32]")
    entropy_size = ffi.new("size_t*")

    err = lib.cardano_bip39_mnemonic_words_to_entropy(
        c_words, word_count, entropy_buf, 32, entropy_size
    )

    if err != 0:
        raise CardanoError(f"Failed to convert mnemonic to entropy (error code: {err})")

    return bytes(ffi.buffer(entropy_buf, entropy_size[0]))
