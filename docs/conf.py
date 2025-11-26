# Configuration file for the Sphinx documentation builder.
import os
import sys
import shutil
import re
from pathlib import Path

# -- Path setup --------------------------------------------------------------

sys.path.insert(0, os.path.abspath('../src'))
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# -- Project information -----------------------------------------------------
project = 'Cometa'
copyright = '2025, Biglup Labs'
author = 'Biglup Labs'
release = '0.1.3'

# -- General configuration ---------------------------------------------------
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
    'sphinx.ext.intersphinx',
    'myst_parser',
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# -- Options for HTML output -------------------------------------------------
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

# Theme options for sphinx-book-theme
html_theme_options = {
    "repository_url": "https://github.com/Biglup/cometa.py",
    "use_repository_button": True,
    "use_download_button": False,
    "home_page_in_toc": True,
}

# -- Autodoc configuration ---------------------------------------------------
autodoc_member_order = 'bysource'
autodoc_typehints = 'description'


# -- Post-process ------------------------------------------------------------

def get_project_info():
    """Parses pyproject.toml to get the package name and version."""
    pyproject_path = PROJECT_ROOT / "pyproject.toml"
    version = "0.0.0"

    if pyproject_path.exists():
        with open(pyproject_path, "r", encoding="utf-8") as f:
            content = f.read()
            v_match = re.search(r'^version\s*=\s*"(.*)"', content, re.MULTILINE)

            if v_match: version = v_match.group(1)

    return version

def on_build_finished(app, exception):
    """
    Post-process the generated HTML files.
    1. Removes the duplicate <h1> tag (Project Title) from index.html.
    2. Removes the RTD status badge from index.html.
    3. Fixes broken asset links by rewriting paths and copying files to _static.
    """
    if exception is not None:
        return

    import re

    out_dir = app.outdir
    index_path = os.path.join(out_dir, 'index.html')

    # 1. Copy assets to _static/assets in the build directory
    # This ensures raw HTML <img> tags in README have a valid target.
    src_assets = os.path.abspath(os.path.join(os.path.dirname(__file__), '../assets'))
    dst_assets = os.path.join(out_dir, '_static', 'assets')

    if os.path.exists(src_assets):
        print(f"[Post-Process] Copying assets from {src_assets} to {dst_assets}...")
        if os.path.exists(dst_assets):
            shutil.rmtree(dst_assets)
        shutil.copytree(src_assets, dst_assets)

    # 2. Patch index.html
    if os.path.exists(index_path):
        print(f"[Post-Process] Patching {index_path}...")
        with open(index_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Remove the H1 containing the project name (The duplicate title)
        # Matches: <h1 ...> ... Cometa ... </h1>
        pattern = r'<h1[^>]*>.*?' + re.escape(project) + r'.*?</h1>'
        content, count = re.subn(pattern, '', content, count=1, flags=re.DOTALL | re.IGNORECASE)

        if count > 0:
            print(f"[Post-Process] Removed {count} duplicate title(s) from index.html")
        else:
            print(f"[Post-Process] WARNING: Could not find H1 title matching '{project}' to remove.")
        # Remove the RTD Badge (Documentation Status)
        # Matches: <a ... readthedocs.io ...><img ... badge ... alt="Documentation Status"></a>
        badge_pattern = r'<a class="reference external"[^>]*href\="https:\/\/cometapy\.readthedocs.io\/en\/latest\/\?badge\=latest"[^>]*>.*?</a>'
        content = re.sub(badge_pattern, '', content, flags=re.DOTALL | re.IGNORECASE)

        # Fix broken image links (Fall back for raw HTML in README)
        # We redirect them to the _static/assets folder we just created.
        content = content.replace('src="assets/', 'src="_static/assets/')
        content = content.replace('href="assets/', 'href="_static/assets/')

        version = get_project_info()
        content = content.replace('biglup-cometa 0.1.1', 'biglup-cometa ' + version)

        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(content)


def setup(app):
    app.connect('build-finished', on_build_finished)