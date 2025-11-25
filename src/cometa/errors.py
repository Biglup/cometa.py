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

from ._ffi import ffi

class CardanoError(Exception):
    """Generic error raised when a libcardano-c call fails."""

def check_error(err: int, get_last_error_fn, ctx_ptr) -> None:
    """Raise CardanoError if err != 0, using the given get_last_error_fn."""
    if err != 0:
        msg_ptr = get_last_error_fn(ctx_ptr)
        if msg_ptr:
            msg = ffi.string(msg_ptr).decode("utf-8")
        else:
            msg = "Unknown libcardano-c error"
        raise CardanoError(msg)
