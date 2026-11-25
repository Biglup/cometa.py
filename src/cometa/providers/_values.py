"""Strict decoding shared by provider wire formats."""
# Copyright 2026 Biglup Labs. SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import re
from fractions import Fraction
from decimal import Decimal

from ..address import Address
from ..cbor import CborReader, CborWriter
from ..common import UnitInterval
from ..errors import CardanoError
from ..plutus_data import PlutusData
from ..transaction import Transaction


def invalid():
    """Reject malformed or inconsistent data without echoing server content."""
    raise CardanoError("Invalid provider response")


def obj(value):
    """Require a JSON object."""
    if not isinstance(value, dict):
        invalid()
    return value


def array(value):
    """Require a JSON array."""
    if not isinstance(value, list):
        invalid()
    return value


def integer(value, minimum=0, maximum=2**63 - 1):
    """Decode an exact bounded integer, never a boolean or floating-point value."""
    if isinstance(value, str) and len(value) <= 21 and re.fullmatch(r"-?(0|[1-9][0-9]*)", value):
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        invalid()
    return value


def hex_text(value, size=None, empty=False):
    """Validate and normalize whole bytes, optionally of a fixed length."""
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2})*", value):
        invalid()
    if (not value and not empty) or (size is not None and len(value) != size * 2):
        invalid()
    return value.lower()


def asset_text(value):
    """Accept a native asset ID; lovelace is not a native NFT identifier."""
    unit = hex_text(value if isinstance(value, str) else value.to_hex())
    if not 56 <= len(unit) <= 120:
        raise ValueError("Invalid native asset identifier")
    return unit


def hash_text(value):
    """Normalize a datum or transaction hash."""
    return hex_text(value if isinstance(value, str) else value.hex() if isinstance(value, bytes) else value.to_hex(), 32)


def address_text(value):
    """Validate an address with the native ledger decoder."""
    return str(Address.from_string(value if isinstance(value, str) else str(value)))


def ratio(value, unit=False):
    """Preserve exact rational values and bound native numerator/denominator."""
    try:
        if isinstance(value, (bool, float)):
            invalid()
        if isinstance(value, str) and len(value) > 128:
            invalid()
        if isinstance(value, Decimal) and (not value.is_finite() or abs(value.as_tuple().exponent) > 100):
            invalid()
        result = Fraction(value)
    except (ValueError, TypeError, ZeroDivisionError, OverflowError):
        invalid()
    numerator = integer(result.numerator, 0, 2**64 - 1)
    denominator = integer(result.denominator, 1, 2**64 - 1)
    if unit and numerator > denominator:
        invalid()
    return UnitInterval.new(numerator, denominator)


def cbor(value):
    """Encode a native CBOR object without changing its cached original bytes."""
    writer = CborWriter()
    value.to_cbor(writer)
    return writer.to_hex()


def datum_bytes(value, expected=None):
    """Validate datum CBOR and hash the original encoding."""
    encoded = hex_text(value)
    PlutusData.from_cbor(CborReader.from_hex(encoded))
    if expected is not None and hashlib.blake2b(bytes.fromhex(encoded), digest_size=32).hexdigest() != hash_text(expected):
        invalid()
    return encoded


def transaction(value):
    """Decode a transaction before hashing, submitting or evaluating it."""
    return Transaction.from_cbor(CborReader.from_hex(hex_text(value)))


def input_key(value):
    """Canonical identity for a native transaction input."""
    return f"{hash_text(value.transaction_id)}#{integer(value.index, 0, 65535)}"


def unique(outputs):
    """Reject duplicate outputs rather than silently losing conflicting data."""
    seen = set()
    for output in outputs:
        key = input_key(output.input)
        if key in seen:
            invalid()
        seen.add(key)
    return outputs


def resolve_order(requested, outputs):
    """Preserve first-request order, omit missing inputs and reject extras."""
    keys = dict.fromkeys(input_key(item) for item in requested)
    indexed = {input_key(item.input): item for item in unique(outputs)}
    if indexed.keys() - keys.keys():
        invalid()
    return [indexed[key] for key in keys if key in indexed]
