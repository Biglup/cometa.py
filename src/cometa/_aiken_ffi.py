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

# System library search paths (for distro/Buildroot packages)
_SYSTEM_LIB_PATHS = [
    "/usr/lib",
    "/usr/local/lib",
    "/lib",
    "/usr/lib64",
    "/usr/local/lib64",
]


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


def _get_aiken_ffi():
    """
    Get the CFFI FFI instance for Aiken, trying pre-compiled first, then falling back to runtime parsing.
    """
    try:
        from cometa._aiken_cffi import ffi
        return ffi
    except ImportError:
        pass

    from cffi import FFI
    ffi = FFI()

    def _load_aiken_cdef() -> str:
        """Load the generated aiken-c.cdef file from the package."""
        cdef_path = os.path.join(_find_package_dir(), "_cdef", "aiken-c.cdef")
        with open(cdef_path, encoding="utf-8") as cdef_file:
            return cdef_file.read()

    ffi.cdef(_load_aiken_cdef())
    return ffi


aiken_ffi = _get_aiken_ffi()


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


def _get_lib_name() -> str:
    """Get the library filename for the current platform."""
    if sys.platform.startswith("linux"):
        return "libaiken_c.so"
    if sys.platform == "darwin":
        return "libaiken_c.dylib"
    if sys.platform in ("win32", "cygwin", "msys"):
        return "aiken_c.dll"
    raise RuntimeError(f"Unsupported platform: {sys.platform!r}")


def _find_system_lib() -> str | None:
    """
    Search for system-installed libaiken_c.

    This allows distro packages (Buildroot, Debian, etc.) to install
    libaiken_c separately and have cometa link against it.
    """
    lib_name = _get_lib_name()

    # Check standard system library paths
    for lib_dir in _SYSTEM_LIB_PATHS:
        lib_path = os.path.join(lib_dir, lib_name)
        if os.path.isfile(lib_path):
            return lib_path

    # Check LD_LIBRARY_PATH (Linux) or DYLD_LIBRARY_PATH (macOS)
    env_var = "DYLD_LIBRARY_PATH" if sys.platform == "darwin" else "LD_LIBRARY_PATH"
    extra_paths = os.environ.get(env_var, "").split(os.pathsep)
    for lib_dir in extra_paths:
        if lib_dir:
            lib_path = os.path.join(lib_dir, lib_name)
            if os.path.isfile(lib_path):
                return lib_path

    return None


def _find_bundled_lib() -> str | None:
    """Search for bundled library in the package's _native directory."""
    try:
        plat_dir = _detect_platform_dir()
        pkg_dir = _find_package_dir()
        lib_path = os.path.join(pkg_dir, "_native", plat_dir, _get_lib_name())
        if os.path.isfile(lib_path):
            return lib_path
    except (RuntimeError, ImportError):
        pass
    return None


def _find_aiken_lib() -> str:
    """
    Find the native libaiken_c library.

    Search order:
    1. System-installed library (for distro/Buildroot packages)
    2. Bundled library in package (for pip wheel installs)

    This allows verifiable builds where libaiken_c is compiled from source,
    while still supporting convenient pip installs with pre-built binaries.
    """
    # First, check for system-installed library
    system_lib = _find_system_lib()
    if system_lib:
        return system_lib

    # Fall back to bundled library
    bundled_lib = _find_bundled_lib()
    if bundled_lib:
        return bundled_lib

    # Neither found - provide helpful error message
    lib_name = _get_lib_name()
    plat_dir = _detect_platform_dir()
    raise FileNotFoundError(
        f"Could not find {lib_name}. Searched:\n"
        f"  - System paths: {_SYSTEM_LIB_PATHS}\n"
        f"  - Bundled path: _native/{plat_dir}/{lib_name}\n"
        f"\n"
        f"To fix this:\n"
        f"  1. Install pre-built wheel: pip install biglup-cometa\n"
        f"  2. Or build libaiken_c from source (https://github.com/Biglup/aiken-c-ffi)\n"
        f"     and install to /usr/lib or set LD_LIBRARY_PATH"
    )


_aiken_lib_path = _find_aiken_lib()
aiken_lib = aiken_ffi.dlopen(_aiken_lib_path)
