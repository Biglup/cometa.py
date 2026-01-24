"""
CFFI build script for pre-compiling FFI bindings.

This script is run at wheel build time to pre-parse the cdef files,
eliminating the 70+ second parsing delay on slow devices like Pi Zero.

Copyright 2025 Biglup Labs.
Licensed under the Apache License, Version 2.0
"""

import shutil
import tempfile
from pathlib import Path

from cffi import FFI

# Get the directory containing this script
_THIS_DIR = Path(__file__).parent.resolve()


def _load_cdef(filename: str) -> str:
    """Load a cdef file from the _cdef directory."""
    cdef_path = _THIS_DIR / "_cdef" / filename
    return cdef_path.read_text(encoding="utf-8")


# === Cardano FFI ===
cardano_ffi = FFI()
cardano_ffi.cdef(_load_cdef("cardano-c.cdef"))

# ABI mode with pre-compilation: set_source with None means no C code to compile,
# but ffi.compile() will serialize the parsed cdef for fast loading at runtime
cardano_ffi.set_source("cometa._cardano_cffi", None)


# === Aiken FFI ===
aiken_ffi = FFI()
aiken_ffi.cdef(_load_cdef("aiken-c.cdef"))
aiken_ffi.set_source("cometa._aiken_cffi", None)


def compile_all(output_dir: str = None):
    """Compile all FFI modules to the specified directory."""
    if output_dir is None:
        output_dir = str(_THIS_DIR)

    output_path = Path(output_dir)
    print(f"Compiling CFFI modules to {output_dir}...")

    # Use a temporary directory for compilation, then move files
    # This is necessary because ffi.compile() creates a nested directory structure
    # based on the module name (e.g., cometa/_cardano_cffi.py)
    with tempfile.TemporaryDirectory() as tmpdir:
        # Compile cardano FFI
        cardano_ffi.compile(tmpdir=tmpdir, verbose=True)
        print("  - _cardano_cffi compiled")

        # Compile aiken FFI
        aiken_ffi.compile(tmpdir=tmpdir, verbose=True)
        print("  - _aiken_cffi compiled")

        # Move generated files to output directory
        # The files are created in tmpdir/cometa/_*_cffi.py
        generated_dir = Path(tmpdir) / "cometa"
        for cffi_file in generated_dir.glob("*_cffi.py"):
            dest = output_path / cffi_file.name
            shutil.copy(cffi_file, dest)
            print(f"  - Copied {cffi_file.name} to {dest}")

    print("CFFI compilation complete!")


def main():
    """Entry point for command-line invocation."""
    import sys
    output = sys.argv[1] if len(sys.argv) > 1 else None
    compile_all(output)


if __name__ == "__main__":
    main()
