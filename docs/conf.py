# Configuration file for the Sphinx documentation builder.
import os
import sys

# -- Path setup --------------------------------------------------------------
sys.path.insert(0, os.path.abspath('../src'))

# -- Project information -----------------------------------------------------
project = 'Cometa'
copyright = '2024, Biglup Labs'
author = 'Biglup Labs'
release = '0.1.0'

# -- General configuration ---------------------------------------------------
extensions = [
    'sphinx.ext.autodoc',      # Core library for html generation from docstrings
    'sphinx.ext.napoleon',     # Support for NumPy and Google style docstrings
    'sphinx.ext.viewcode',     # Add links to highlighted source code
    'sphinx.ext.intersphinx',  # Link to other project's documentation
    'myst_parser',             # Support for Markdown (.md) files
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# -- Options for HTML output -------------------------------------------------
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

# -- Autodoc configuration ---------------------------------------------------
autodoc_member_order = 'bysource'
autodoc_typehints = 'description'

# -- Manual Setup ------------------------------------------------------------
# We removed the run_apidoc function to prevent auto-generation.
# You now control the structure manually via index.rst.