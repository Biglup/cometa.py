#!/usr/bin/env python3
import os
import sys
import shutil
import re
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


def update_index_version():
    """
    Updates the header (Title and Version) of docs/index.rst without
    regenerating the rest of the file.
    """
    if not INDEX_FILE.exists():
        print(f"Error: {INDEX_FILE} not found. Cannot update version header.")
        return

    name, version = get_project_info()
    new_title = f"{name} {version}"
    new_underline = "=" * len(new_title)

    print(f"Checking {INDEX_FILE}...")
    with open(INDEX_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if not lines:
        print("Error: index.rst is empty.")
        return

    # Check if update is actually needed
    current_title_line = lines[0].strip()
    if current_title_line == new_title:
        print(f"Index header already up to date: {new_title}")
        return

    print(f"Updating index header to: {new_title}")

    # Replace the first two lines (Title + Underline)
    # We assume standard RST format where line 0 is title and line 1 is underline
    if len(lines) >= 2:
        lines[0] = new_title + "\n"
        lines[1] = new_underline + "\n"
    else:
        # Edge case: file is too short, just prepend/overwrite
        lines = [new_title + "\n", new_underline + "\n"] + lines

    with open(INDEX_FILE, "w", encoding="utf-8") as f:
        f.writelines(lines)


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
    update_index_version()
    update_conf_py()


if __name__ == "__main__":
    main()