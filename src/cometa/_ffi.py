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

import importlib.util
import os
import sys
import platform


def _find_package_dir() -> str:
    """Find the cometa package directory, works with .pyc-only installations."""
    spec = importlib.util.find_spec("cometa")
    if spec is None:
        raise ImportError("Cannot find cometa package")

    if spec.origin and spec.origin != "namespace":
        return os.path.dirname(spec.origin)

    if spec.submodule_search_locations:
        return spec.submodule_search_locations[0]

    raise ImportError("Cannot determine cometa package location")


def _get_ffi():
    """
    Get the CFFI FFI instance, trying pre-compiled first, then falling back to runtime parsing.
    """
    try:
        from cometa._cardano_cffi import ffi as precompiled_ffi
        return precompiled_ffi
    except ImportError:
        pass

    from cffi import FFI
    runtime_ffi = FFI()

    def _load_all_cdef() -> str:
        """Load the generated cardano-c.cdef file from the package."""
        cdef_path = os.path.join(_find_package_dir(), "_cdef", "cardano-c.cdef")
        with open(cdef_path, encoding="utf-8") as cdef_file:
            return cdef_file.read()

    runtime_ffi.cdef(_load_all_cdef())
    return runtime_ffi


ffi = _get_ffi()


def _normalize_arch(machine: str) -> str:
    machine_lower = machine.lower()
    if machine_lower in ("x86_64", "amd64"):
        return "x86_64"
    if machine_lower in ("aarch64", "arm64"):
        return "arm64"
    if machine_lower.startswith("armv7"):
        return "armv7"
    if machine_lower.startswith("armv6"):
        return "armv6"
    return machine_lower


def _detect_platform_dir() -> str:
    plat = sys.platform
    arch = _normalize_arch(platform.machine())

    if plat.startswith("linux"):
        return f"linux-{arch}"

    if plat == "darwin":
        return f"macos-{arch}"

    if plat in ("win32", "cygwin", "msys"):
        return f"windows-{arch}-msvc"

    raise RuntimeError(f"Unsupported platform: {plat!r} arch: {arch!r}")


def _find_native_lib() -> str:
    plat_dir = _detect_platform_dir()
    pkg_dir = _find_package_dir()
    base = os.path.join(pkg_dir, "_native", plat_dir)

    if sys.platform.startswith("linux"):
        candidates = ["libcardano-c.so"]
    elif sys.platform == "darwin":
        candidates = ["libcardano-c.dylib"]
    elif sys.platform in ("win32", "cygwin", "msys"):
        candidates = ["cardano-c.dll"]
    else:
        raise RuntimeError(f"Unsupported platform: {sys.platform!r}")

    for name in candidates:
        lib_path = os.path.join(base, name)
        if os.path.isfile(lib_path):
            return lib_path

    raise FileNotFoundError(
        f"Could not find native libcardano-c in {base} "
        f"(platform dir: {plat_dir}, candidates: {candidates})"
    )


_lib_path = _find_native_lib()
lib = ffi.dlopen(_lib_path)
