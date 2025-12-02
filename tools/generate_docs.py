#!/usr/bin/env python3
import os
import sys
import shutil
import inspect
import importlib
import re
from enum import Enum
from pathlib import Path

# 1. Setup Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

OUTPUT_DIR = PROJECT_ROOT / "docs" / "api"
INDEX_FILE = PROJECT_ROOT / "docs" / "index.rst"

ASSETS_DIR = PROJECT_ROOT / "assets"
# Copy to docs/assets so Sphinx finds them as source files
DOCS_ASSETS_DIR = PROJECT_ROOT / "docs" / "assets"

# Source README and the temporary one we will create for docs
README_SRC = PROJECT_ROOT / "README.md"
README_DOCS = PROJECT_ROOT / "docs" / "README_docs.md"

# Magic methods we explicitly want to document if they exist
MAGIC_WHITELIST = {
    "__init__", "__len__", "__getitem__", "__setitem__",
    "__iter__", "__eq__", "__add__", "__bytes__",
    "__enter__", "__exit__", "__str__", "__repr__",
    "__int__", "__float__", "__bool__", "__index__", "__format__",
    "__contains__", "__hash__", "__call__", "__sub__", "__mul__",
    "__truediv__", "__floordiv__", "__mod__", "__divmod__", "__pow__",
    "__abs__", "__neg__", "__pos__", "__invert__", "__lshift__", "__rshift__",
    "__lt__", "__le__", "__gt__", "__ge__", "__and__", "__or__", "__xor__"
}

def discover_modules():
    """
    Recursively finds all public python modules in the package.
    Returns a list of module strings (e.g., 'cometa.common.buffer').
    """
    base_path = PROJECT_ROOT / "src" / "cometa"
    modules = []

    if not base_path.exists():
        return []

    for path in base_path.rglob("*.py"):
        if path.name.startswith("_"):
            continue
        rel_path = path.relative_to(PROJECT_ROOT / "src")
        module_name = ".".join(rel_path.with_suffix("").parts)
        modules.append(module_name)

    return sorted(modules)


def get_project_info():
    """Parses pyproject.toml to get the package name and version."""
    pyproject_path = PROJECT_ROOT / "pyproject.toml"
    name = "biglup-cometa"
    version = "0.0.0"

    if pyproject_path.exists():
        with open(pyproject_path, "r", encoding="utf-8") as f:
            content = f.read()
            v_match = re.search(r'^version\s*=\s*"(.*)"', content, re.MULTILINE)
            n_match = re.search(r'^name\s*=\s*"(.*)"', content, re.MULTILINE)

            if v_match: version = v_match.group(1)
            if n_match: name = n_match.group(1)

    return name, version


def camel_to_snake(name):
    name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()


def get_members_in_order(cls):
    """Returns (name, object, kind) tuples sorted by source line number."""
    members = []

    # Handle Enums specifically: __members__ preserves definition order
    if issubclass(cls, Enum):
        for name, member in cls.__members__.items():
            # For Enums, we treat members as attributes
            members.append((0, name, member))
        return members

    # Handle Standard Classes
    for name, kind in inspect.getmembers(cls):
        if name.startswith("_") and name not in MAGIC_WHITELIST:
            continue

        if not (inspect.isfunction(kind) or inspect.ismethod(kind) or isinstance(kind, property)):
            continue

        try:
            line_no = inspect.getsourcelines(kind)[1]
        except (OSError, TypeError):
            line_no = float('inf')

        members.append((line_no, name, kind))

    members.sort(key=lambda x: x[0])
    return members


def generate_rst_for_class(cls, module_name):
    """
    Generates a standard Sphinx .rst file for a class.
    Uses :members: to document properties and methods as part of the class body.
    """
    filename = OUTPUT_DIR / f"{camel_to_snake(cls.__name__)}.rst"
    content = []

    title = cls.__name__
    content.append(title)
    content.append("=" * len(title))
    content.append("")
    content.append(f".. currentmodule:: {module_name}")
    content.append("")

    # Join magic methods for the :special-members: option
    special_members_list = ", ".join(sorted(MAGIC_WHITELIST))

    content.append(f".. autoclass:: {cls.__name__}")
    content.append("   :members:")  # Include all public members
    content.append("   :undoc-members:")  # Include members even if they don't have docstrings
    content.append("   :show-inheritance:")  # Show base classes
    # Include the specific magic methods we care about
    content.append(f"   :special-members: {special_members_list}")

    print(f"Generating {filename}...")
    with open(filename, "w") as f:
        f.write("\n".join(content))
    return filename


def prepare_assets_and_readme():
    """
    Copies assets to docs/assets and patches README_docs.md to use MyST image syntax.
    """
    # 1. Copy Assets to docs/assets (Source directory for Sphinx)
    if ASSETS_DIR.exists():
        print(f"Copying assets from {ASSETS_DIR} to {DOCS_ASSETS_DIR}...")
        if DOCS_ASSETS_DIR.exists():
            shutil.rmtree(DOCS_ASSETS_DIR)
        # Parent should exist, but good to be safe
        if not DOCS_ASSETS_DIR.parent.exists():
            DOCS_ASSETS_DIR.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(ASSETS_DIR, DOCS_ASSETS_DIR)
    else:
        print(f"Warning: Assets directory {ASSETS_DIR} not found.")

    # 2. Patch README
    if README_SRC.exists():
        print(f"Processing README from {README_SRC} -> {README_DOCS}...")
        with open(README_SRC, "r", encoding="utf-8") as f:
            content = f.read()

        # Regex to replace the specific HTML image block with MyST directive.
        html_img_pattern = r'<div align="center">\s*<a[^>]*>\s*<img[^>]*src="assets/([^"]+)"[^>]*>\s*</a>\s*</div>'

        def myst_replacement(match):
            filename = match.group(1)
            return f"""
```{{image}} assets/{filename}
:width: 300px
:align: center
```
"""

        # Apply regex replacement
        new_content = re.sub(html_img_pattern, myst_replacement, content, flags=re.DOTALL)

        if new_content == content:
            print("Info: No HTML image blocks found to replace in README.")

        with open(README_DOCS, "w", encoding="utf-8") as f:
            f.write(new_content)
    else:
        print(f"Error: Source README not found at {README_SRC}")


def generate_index(generated_files):
    entries = []
    for p in generated_files:
        rel_path = p.relative_to(PROJECT_ROOT / "docs").with_suffix('')
        entries.append(str(rel_path))

    entries.sort()
    toctree_content = "\n   ".join(entries)
    name, version = get_project_info()

    content = f"""
{name} {version}
{'=' * (len(name) + len(version) + 1)}

.. include:: README_docs.md
   :parser: myst_parser.sphinx_

.. toctree::
   :maxdepth: 1
   :caption: API Reference
   :titlesonly:
   :hidden:

   {toctree_content}
"""

    print(f"Updating {INDEX_FILE}...")
    with open(INDEX_FILE, "w") as f:
        f.write(content.strip())


def update_conf_py():
    """
    Updates docs/conf.py with the version from pyproject.toml.
    Writing to the file invalidates the Sphinx cache, forcing a rebuild
    of the index which includes the README.
    """
    conf_path = PROJECT_ROOT / "docs" / "conf.py"
    if conf_path.exists():
        _, version = get_project_info()
        print(f"Updating {conf_path} release to {version}...")

        with open(conf_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Regex to update release = '...'
        new_content = re.sub(
            r"^release\s*=\s*['\"].*['\"]",
            f"release = '{version}'",
            content,
            flags=re.MULTILINE
        )

        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(new_content)


def main():
    if not OUTPUT_DIR.exists():
        os.makedirs(OUTPUT_DIR)

    prepare_assets_and_readme()
    update_conf_py()

if __name__ == "__main__":
    main()