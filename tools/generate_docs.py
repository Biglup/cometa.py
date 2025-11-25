#!/usr/bin/env python3
import os
import sys
import shutil
import inspect
import importlib
import re
from pathlib import Path

# 1. Setup Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

OUTPUT_DIR = PROJECT_ROOT / "docs" / "api"
INDEX_FILE = PROJECT_ROOT / "docs" / "index.rst"
ASSETS_DIR = PROJECT_ROOT / "assets"
# Copy assets to _static/assets so Sphinx picks them up during build
DOCS_ASSETS_DIR = PROJECT_ROOT / "docs" / "_build" / "html" / "assets"

# Magic methods we explicitly want to document if they exist
MAGIC_WHITELIST = {
    "__init__", "__len__", "__getitem__", "__setitem__",
    "__iter__", "__eq__", "__add__", "__bytes__",
    "__enter__", "__exit__", "__str__", "__repr__",
    "__int__", "__float__", "__bool__", "__index__", "__format__"
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
        # Skip __init__.py and private files starting with _
        if path.name.startswith("_"):
            continue

        # Convert path to module notation
        # e.g., src/cometa/cbor/cbor_reader.py -> cometa.cbor.cbor_reader
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
            # Simple regex to find name and version
            # Note: This assumes standard TOML formatting (version = "x.y.z")
            v_match = re.search(r'^version\s*=\s*"(.*)"', content, re.MULTILINE)
            n_match = re.search(r'^name\s*=\s*"(.*)"', content, re.MULTILINE)

            if v_match: version = v_match.group(1)
            if n_match: name = n_match.group(1)

    return name, version


def camel_to_snake(name):
    """Converts CamelCase to snake_case for filenames."""
    name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()


def get_members_in_order(cls):
    """Returns (name, object, kind) tuples sorted by source line number."""
    members = []

    for name, kind in inspect.getmembers(cls):
        # Filter privates unless whitelisted
        if name.startswith("_") and name not in MAGIC_WHITELIST:
            continue

        # We only want functions, methods, and properties
        if not (inspect.isfunction(kind) or inspect.ismethod(kind) or isinstance(kind, property)):
            continue

        # Get source line for sorting
        try:
            line_no = inspect.getsourcelines(kind)[1]
        except (OSError, TypeError):
            line_no = float('inf')

        members.append((line_no, name, kind))

    # Sort by line number
    members.sort(key=lambda x: x[0])
    return members


def generate_rst_for_class(cls, module_name):
    """Generates a .rst file for a specific class and returns the Path."""
    filename = OUTPUT_DIR / f"{camel_to_snake(cls.__name__)}.rst"

    content = []

    # 1. Header
    title = cls.__name__
    content.append(title)
    content.append("=" * len(title))
    content.append("")
    content.append(f".. currentmodule:: {module_name}")
    content.append("")

    # 2. Class Definition
    content.append(f".. autoclass:: {cls.__name__}")
    content.append("   :no-members:")
    content.append("   :show-inheritance:")
    content.append("")

    # 3. Separator
    content.append("------------")
    content.append("")

    # 4. Iterate Members
    members = get_members_in_order(cls)

    for _, name, kind in members:
        directive = "automethod"
        if isinstance(kind, property):
            directive = "autoattribute"

        content.append(f".. {directive}:: {cls.__name__}.{name}")
        content.append("")
        content.append("------------")
        content.append("")

    print(f"Generating {filename}...")
    with open(filename, "w") as f:
        f.write("\n".join(content))

    return filename


def generate_index(generated_files):
    """Generates the root index.rst file including README and API listing."""

    # 1. Fix Image Paths: Copy assets to docs folder so relative links in README work
    if ASSETS_DIR.exists():
        print(f"Copying assets from {ASSETS_DIR} to {DOCS_ASSETS_DIR}...")

        # Ensure _static exists
        if not DOCS_ASSETS_DIR.parent.exists():
            DOCS_ASSETS_DIR.parent.mkdir(parents=True, exist_ok=True)

        if DOCS_ASSETS_DIR.exists():
            shutil.rmtree(DOCS_ASSETS_DIR)
        shutil.copytree(ASSETS_DIR, DOCS_ASSETS_DIR)

    # 2. Build ToC
    # Convert absolute paths to relative paths for toctree (e.g., api/buffer)
    # Sort alphabetically for a clean menu
    entries = []
    for p in generated_files:
        # Path relative to docs/ folder, strip .rst suffix
        rel_path = p.relative_to(PROJECT_ROOT / "docs").with_suffix('')
        entries.append(str(rel_path))

    entries.sort()
    toctree_content = "\n   ".join(entries)

    # 3. Get Version Info
    name, version = get_project_info()
    title = f"{name} {version}"

    # 4. Create Index Content
    content = f"""
{title}
{'=' * len(title)}

.. include:: ../README.md
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


def main():
    if not OUTPUT_DIR.exists():
        os.makedirs(OUTPUT_DIR)

    generated_files = []
    modules = discover_modules()

    for mod_name in modules:
        try:
            mod = importlib.import_module(mod_name)
            classes = [
                obj for name, obj in inspect.getmembers(mod, inspect.isclass)
                if obj.__module__ == mod_name
            ]

            for cls in classes:
                file_path = generate_rst_for_class(cls, mod_name)
                generated_files.append(file_path)

        except ImportError as e:
            print(f"Error importing {mod_name}: {e}")

    # Update the main index
    if generated_files:
        generate_index(generated_files)


if __name__ == "__main__":
    main()