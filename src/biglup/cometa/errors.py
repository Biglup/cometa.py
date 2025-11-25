from ._ffi import ffi


class CardanoError(Exception):
    """Generic error raised when a libcardano-c call fails."""
    pass


def check_error(err: int, get_last_error_fn, ctx_ptr) -> None:
    """Raise CardanoError if err != 0, using the given get_last_error_fn."""
    if err != 0:
        msg_ptr = get_last_error_fn(ctx_ptr)
        if msg_ptr:
            msg = ffi.string(msg_ptr).decode("utf-8")
        else:
            msg = "Unknown libcardano-c error"
        raise CardanoError(msg)
