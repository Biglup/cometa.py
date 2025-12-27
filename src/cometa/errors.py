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

from ._ffi import ffi, lib

class CardanoError(Exception):
    """
    Generic error raised when a libcardano-c call fails.

    This exception is raised by the check_error function when an error code
    indicates a failure in the underlying C library. The exception message
    contains the human-readable error description from the C library.
    """

def check_error(err: int, get_last_error_fn, ctx_ptr) -> None:
    """
    Raise CardanoError if err != 0, using the given get_last_error_fn.

    This is a helper function used throughout the bindings to check for errors
    from libcardano-c function calls. When an error is detected (err != 0), it
    retrieves the error message from the context object and raises a CardanoError.

    Args:
        err: Error code from a libcardano-c function call (0 = success).
        get_last_error_fn: Function pointer to retrieve error message from context.
        ctx_ptr: Pointer to the C context object containing error details.

    Raises:
        CardanoError: If err is non-zero, with the error message from the context.

    Example:
        >>> check_error(result, lib.some_get_last_error, ctx)
    """
    if err != 0:
        msg_ptr = get_last_error_fn(ctx_ptr)
        if msg_ptr:
            msg = ffi.string(msg_ptr).decode("utf-8")
        else:
            msg = "Unknown libcardano-c error"
        raise CardanoError(msg)

def cardano_error_to_string(err: int) -> str:
    """
    Convert an error code to its human-readable string representation.

    This function wraps the C library's cardano_error_to_string function to
    convert numeric error codes into descriptive error messages.

    Args:
        err: A Cardano error code integer (e.g., CARDANO_SUCCESS = 0).

    Returns:
        A human-readable string describing the error. Returns "Unknown error."
        if the error code is not recognized.

    Example:
        >>> cardano_error_to_string(0)
        'Successful operation'
        >>> cardano_error_to_string(1)
        'Generic error'
        >>> cardano_error_to_string(99999)
        'Unknown error.'
    """
    result = lib.cardano_error_to_string(err)
    if result == ffi.NULL:
        return "Unknown error."

    return ffi.string(result).decode("utf-8")
