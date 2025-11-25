from cffi import FFI
import sys
import platform
from importlib import resources as importlib_resources
from pathlib import Path

ffi = FFI()

def _load_all_cdef() -> str:
    """
    Load the generated cardano-c.cdef file from the package.
    """
    # biglup/cometa/_cdef/all.cdef
    cdef_path = importlib_resources.files("biglup.cometa") / "_cdef" / "cardano-c.cdef"
    return cdef_path.read_text(encoding="utf-8")


ffi.cdef(_load_all_cdef())

def _normalize_arch(machine: str) -> str:
    m = machine.lower()
    if m in ("x86_64", "amd64"):
        return "x86_64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    return m

def _detect_platform_dir() -> str:
    plat = sys.platform
    arch = _normalize_arch(platform.machine())

    if plat.startswith("linux"):
        return f"linux-{arch}"
    elif plat == "darwin":
        return f"macos-{arch}"
    elif plat in ("win32", "cygwin", "msys"):
        return f"windows-{arch}-msvc"
    else:
        raise RuntimeError(f"Unsupported platform: {plat!r} arch: {arch!r}")

def _find_native_lib() -> Path:
    plat_dir = _detect_platform_dir()

    base = importlib_resources.files("biglup.cometa") / "_native" / plat_dir

    candidates = []
    if sys.platform.startswith("linux"):
        candidates = ["libcardano-c.so"]
    elif sys.platform == "darwin":
        candidates = ["libcardano-c.dylib"]
    elif sys.platform in ("win32", "cygwin", "msys"):
        candidates = ["cardano-c.dll"]
    else:
        raise RuntimeError(f"Unsupported platform: {sys.platform!r}")

    for name in candidates:
        lib_path = base / name
        if lib_path.is_file():
            return lib_path

    raise FileNotFoundError(
        f"Could not find native libcardano-c in {base} "
        f"(platform dir: {plat_dir}, candidates: {candidates})"
    )

_lib_path = _find_native_lib()
lib = ffi.dlopen(str(_lib_path))
