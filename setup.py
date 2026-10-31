#!/usr/bin/env python3
# Copyright 2025 Biglup Labs.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Setup script for cometa.

This script handles CFFI compilation during installation.
The pre-compiled CFFI modules load instantly instead of taking ~70 seconds
to parse on slow devices like Pi Zero.
"""

import os
import sys
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.develop import develop
from wheel.bdist_wheel import bdist_wheel


def compile_cffi_modules():
    """Compile CFFI modules to the source directory."""
    src_dir = Path(__file__).parent / "src" / "cometa"
    build_script = src_dir / "_ffi_build.py"

    if not build_script.exists():
        print("Warning: _ffi_build.py not found, skipping CFFI compilation")
        return

    print("Compiling CFFI modules for fast loading...")

    # Import and run the build script
    import importlib.util
    spec = importlib.util.spec_from_file_location("_ffi_build", build_script)
    ffi_build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ffi_build)

    # Compile to source directory
    ffi_build.compile_all(str(src_dir))
    print("CFFI compilation complete!")


class BuildPyWithCFFI(build_py):
    """Custom build_py that compiles CFFI modules."""

    def run(self):
        compile_cffi_modules()
        super().run()


class DevelopWithCFFI(develop):
    """Custom develop that compiles CFFI modules for editable installs."""

    def run(self):
        compile_cffi_modules()
        super().run()


class PlatformWheel(bdist_wheel):
    """Tag wheels containing the ABI-mode native library for their target OS."""

    def finalize_options(self):
        super().finalize_options()
        native = Path(__file__).parent / "src" / "cometa" / "_native"
        if os.environ.get("COMETA_WHEEL_PLATFORM") or any(native.rglob("*.so")) or any(native.rglob("*.dylib")) or any(native.rglob("*.dll")):
            self.root_is_pure = False

    def get_tag(self):
        target = os.environ.get("COMETA_WHEEL_PLATFORM")
        if target:
            return "py3", "none", target
        if not self.root_is_pure:
            return "py3", "none", super().get_tag()[2]
        return super().get_tag()


# Only run setup() if this file is executed directly
# (pyproject.toml is the primary config, this is just for CFFI hooks)
if __name__ == "__main__":
    setup(
        cmdclass={
            "build_py": BuildPyWithCFFI,
            "bdist_wheel": PlatformWheel,
            "develop": DevelopWithCFFI,
        },
    )
