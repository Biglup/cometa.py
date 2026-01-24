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
Build and publish platform-specific wheels for cometa.

Usage:
    python scripts/build_wheels.py build                    # Build all platform wheels
    python scripts/build_wheels.py build --platform linux-x86_64  # Build specific platform
    python scripts/build_wheels.py build --current          # Build for current platform only
    python scripts/build_wheels.py publish                  # Publish to PyPI
    python scripts/build_wheels.py publish --test           # Publish to TestPyPI
    python scripts/build_wheels.py all                      # Build all + publish to PyPI
    python scripts/build_wheels.py all --test               # Build all + publish to TestPyPI

Requirements:
    pip install build twine
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PLATFORMS = {
    "linux-x86_64": "manylinux_2_17_x86_64.manylinux2014_x86_64",
    "linux-arm64": "manylinux_2_17_aarch64.manylinux2014_aarch64",
    "linux-armv7": "linux_armv7l",
    "linux-armv6": "linux_armv6l",
    "macos-x86_64": "macosx_10_9_x86_64",
    "macos-arm64": "macosx_11_0_arm64",
    "windows-x86_64-msvc": "win_amd64",
}


def get_current_platform() -> str:
    import platform as plat

    system = sys.platform
    machine = plat.machine().lower()

    if machine in ("x86_64", "amd64"):
        arch = "x86_64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    elif machine.startswith("armv7"):
        arch = "armv7"
    elif machine.startswith("armv6"):
        arch = "armv6"
    else:
        arch = machine

    if system.startswith("linux"):
        return f"linux-{arch}"
    elif system == "darwin":
        return f"macos-{arch}"
    elif system in ("win32", "cygwin", "msys"):
        return f"windows-{arch}-msvc"
    else:
        raise RuntimeError(f"Unsupported platform: {system}")


def compile_cffi(src_dir: Path, output_dir: Path) -> None:
    """
    Compile CFFI modules to the output directory.
    """
    print("  Compiling CFFI modules...")

    # Import and run the build script
    import importlib.util
    build_script = src_dir / "src" / "cometa" / "_ffi_build.py"

    spec = importlib.util.spec_from_file_location("_ffi_build", build_script)
    ffi_build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ffi_build)

    # Compile to output directory
    ffi_build.compile_all(str(output_dir))


def build_wheel(src_dir: Path, platform_name: str, wheel_tag: str, output_dir: Path) -> Path:
    native_dir = src_dir / "src" / "cometa" / "_native" / platform_name

    if not native_dir.exists():
        raise FileNotFoundError(f"Native directory not found: {native_dir}")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        build_dir = tmp_path / "build"
        build_src = build_dir / "src" / "cometa"

        build_src.mkdir(parents=True)

        # Copy native directory for this platform only
        shutil.copytree(native_dir, build_src / "_native" / platform_name)

        # Copy cdef files
        shutil.copytree(src_dir / "src" / "cometa" / "_cdef", build_src / "_cdef")

        # Copy Python files
        for py_file in (src_dir / "src" / "cometa").glob("*.py"):
            shutil.copy(py_file, build_src / py_file.name)

        # Compile CFFI modules (generates _cardano_cffi.py and _aiken_cffi.py)
        compile_cffi(src_dir, build_src)

        # Copy subpackages
        for subdir in (src_dir / "src" / "cometa").iterdir():
            if subdir.is_dir() and subdir.name not in ("_native", "_cdef", "__pycache__"):
                shutil.copytree(subdir, build_src / subdir.name)

        # Copy metadata files
        shutil.copy(src_dir / "pyproject.toml", build_dir / "pyproject.toml")
        if (src_dir / "README.md").exists():
            shutil.copy(src_dir / "README.md", build_dir / "README.md")
        if (src_dir / "LICENSE").exists():
            shutil.copy(src_dir / "LICENSE", build_dir / "LICENSE")

        # Build wheel
        subprocess.run(
            [sys.executable, "-m", "build", "--wheel"],
            cwd=build_dir,
            check=True,
        )

        # Find and rename wheel
        dist_dir = build_dir / "dist"
        wheels = list(dist_dir.glob("*.whl"))
        if not wheels:
            raise RuntimeError("No wheel was built")

        wheel = wheels[0]
        base_name = wheel.name.replace("-py3-none-any.whl", "")
        new_name = f"{base_name}-py3-none-{wheel_tag}.whl"

        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / new_name
        shutil.copy(wheel, output_path)

        return output_path


def build_sdist(src_dir: Path, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        [sys.executable, "-m", "build", "--sdist", "--outdir", str(output_dir)],
        cwd=src_dir,
        check=True,
    )

    sdists = list(output_dir.glob("*.tar.gz"))
    if not sdists:
        raise RuntimeError("No sdist was built")

    return sdists[0]


def cmd_build(args, src_dir: Path) -> list[Path]:
    if args.current:
        current = get_current_platform()
        if current not in PLATFORMS:
            raise RuntimeError(f"Current platform {current} not supported")
        platforms_to_build = {current: PLATFORMS[current]}
    elif args.platform:
        platforms_to_build = {args.platform: PLATFORMS[args.platform]}
    else:
        platforms_to_build = PLATFORMS

    # Clean output directory if requested
    if args.clean and args.output.exists():
        print(f"Cleaning {args.output}...")
        shutil.rmtree(args.output)

    print(f"Building wheels for: {', '.join(platforms_to_build.keys())}")
    print(f"Output directory: {args.output.resolve()}")
    print()

    built_files = []

    # Build platform wheels
    for platform_name, wheel_tag in platforms_to_build.items():
        print(f"Building wheel for {platform_name}...")
        try:
            wheel_path = build_wheel(src_dir, platform_name, wheel_tag, args.output)
            built_files.append(wheel_path)
            print(f"  -> {wheel_path.name}")
        except FileNotFoundError as e:
            print(f"  -> Skipped: {e}")
        except subprocess.CalledProcessError as e:
            print(f"  -> Failed: {e}")

    # Build sdist if building all platforms
    if not args.current and not args.platform and args.sdist:
        print("Building source distribution...")
        try:
            sdist_path = build_sdist(src_dir, args.output)
            built_files.append(sdist_path)
            print(f"  -> {sdist_path.name}")
        except subprocess.CalledProcessError as e:
            print(f"  -> Failed: {e}")

    print()
    print(f"Built {len(built_files)} file(s):")
    for f in built_files:
        print(f"  {f}")

    return built_files


def cmd_publish(args, src_dir: Path):
    dist_dir = args.output

    if not dist_dir.exists():
        print(f"Error: {dist_dir} does not exist. Run 'build' first.")
        sys.exit(1)

    files = list(dist_dir.glob("*.whl")) + list(dist_dir.glob("*.tar.gz"))
    if not files:
        print(f"Error: No wheels or sdists found in {dist_dir}")
        sys.exit(1)

    print(f"Publishing {len(files)} file(s) to {'TestPyPI' if args.test else 'PyPI'}:")
    for f in files:
        print(f"  {f.name}")
    print()

    # Build twine command
    cmd = [sys.executable, "-m", "twine", "upload"]

    if args.test:
        cmd.extend(["--repository", "testpypi"])

    if args.skip_existing:
        cmd.append("--skip-existing")

    cmd.extend(str(f) for f in files)

    # Run twine
    subprocess.run(cmd, check=True)
    print()
    print("Published successfully!")


def cmd_all(args, src_dir: Path):
    # Build all
    args.current = False
    args.platform = None
    args.sdist = True
    built_files = cmd_build(args, src_dir)

    if not built_files:
        print("No files were built. Aborting publish.")
        sys.exit(1)

    # Publish
    print()
    print("=" * 60)
    print()
    cmd_publish(args, src_dir)


def main():
    parser = argparse.ArgumentParser(
        description="Build and publish platform-specific wheels for cometa",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s build                     Build all platform wheels + sdist
  %(prog)s build --current           Build wheel for current platform only
  %(prog)s build --platform linux-x86_64  Build specific platform
  %(prog)s publish                   Publish dist/ to PyPI
  %(prog)s publish --test            Publish dist/ to TestPyPI
  %(prog)s all                       Build all + publish to PyPI
  %(prog)s all --test                Build all + publish to TestPyPI
        """,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Build command
    build_parser = subparsers.add_parser("build", help="Build wheels")
    build_parser.add_argument(
        "--platform",
        choices=list(PLATFORMS.keys()),
        help="Build wheel for specific platform only",
    )
    build_parser.add_argument(
        "--current",
        action="store_true",
        help="Build wheel for current platform only",
    )
    build_parser.add_argument(
        "--output",
        type=Path,
        default=Path("dist"),
        help="Output directory (default: dist)",
    )
    build_parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean output directory before building",
    )
    build_parser.add_argument(
        "--no-sdist",
        action="store_false",
        dest="sdist",
        help="Skip building source distribution",
    )

    # Publish command
    publish_parser = subparsers.add_parser("publish", help="Publish to PyPI")
    publish_parser.add_argument(
        "--test",
        action="store_true",
        help="Publish to TestPyPI instead of PyPI",
    )
    publish_parser.add_argument(
        "--output",
        type=Path,
        default=Path("dist"),
        help="Directory containing wheels to publish (default: dist)",
    )
    publish_parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip files that already exist on PyPI",
    )

    # All command (build + publish)
    all_parser = subparsers.add_parser("all", help="Build all wheels and publish")
    all_parser.add_argument(
        "--test",
        action="store_true",
        help="Publish to TestPyPI instead of PyPI",
    )
    all_parser.add_argument(
        "--output",
        type=Path,
        default=Path("dist"),
        help="Output directory (default: dist)",
    )
    all_parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean output directory before building",
    )
    all_parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip files that already exist on PyPI",
    )

    args = parser.parse_args()
    src_dir = Path(__file__).parent.parent.resolve()

    # Check dependencies
    try:
        import build  # noqa: F401
    except ImportError:
        print("Error: 'build' package not installed. Run: pip install build")
        sys.exit(1)

    if args.command in ("publish", "all"):
        try:
            import twine  # noqa: F401
        except ImportError:
            print("Error: 'twine' package not installed. Run: pip install twine")
            sys.exit(1)

    if args.command == "build":
        cmd_build(args, src_dir)
    elif args.command == "publish":
        cmd_publish(args, src_dir)
    elif args.command == "all":
        cmd_all(args, src_dir)


if __name__ == "__main__":
    main()
