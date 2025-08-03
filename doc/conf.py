import datetime
import os
import sys
from importlib import metadata

sys.path.insert(0, os.path.abspath(".."))
sys.path.insert(0, os.path.abspath("../scim2_client"))

# -- General configuration ------------------------------------------------

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.doctest",
    "sphinx.ext.graphviz",
    "sphinx.ext.intersphinx",
    "sphinx.ext.todo",
    "sphinx.ext.viewcode",
    "sphinx_issues",
    "sphinx_paramlinks",
    "sphinxcontrib.autodoc_pydantic",
    "myst_parser",
]

templates_path = ["_templates"]
master_doc = "index"
project = "scim2-client"
year = datetime.datetime.now().strftime("%Y")
copyright = f"{year}, Yaal Coop"
author = "Yaal Coop"
source_suffix = {
    ".rst": "restructuredtext",
    ".txt": "markdown",
    ".md": "markdown",
}

version = metadata.version("scim2_client")
language = "en"
pygments_style = "sphinx"
todo_include_todos = True
toctree_collapse = False

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "scim2_models": ("https://scim2-models.readthedocs.io/en/latest/", None),
    "werkzeug": ("https://werkzeug.palletsprojects.com", None),
}

# -- Options for HTML output ----------------------------------------------

html_theme = "shibuya"
# html_static_path = ["_static"]
html_baseurl = "https://scim2-client.readthedocs.io"
html_theme_options = {
    "globaltoc_expand_depth": 2,
    "accent_color": "lime",
    "github_url": "https://github.com/python-scim/scim2-client",
    "mastodon_url": "https://toot.aquilenet.fr/@yaal",
    "nav_links": [
        {"title": "scim2-models", "url": "https://scim2-models.readthedocs.io"},
        {"title": "scim2-tester", "url": "https://scim2-tester.readthedocs.io"},
        {
            "title": "scim2-cli",
            "url": "https://scim2-cli.readthedocs.io",
        },
        {
            "title": "scim2-server",
            "url": "https://github.com/python-scim/scim2-server",
        },
        {
            "title": "pytest-scim2-server",
            "url": "https://github.com/pytest-dev/pytest-scim2-server",
        },
    ],
}
html_context = {
    "source_type": "github",
    "source_user": "python-scim",
    "source_repo": "scim2-client",
    "source_version": "main",
    "source_docs_path": "/doc/",
}

# -- Options for sphinx-issues -------------------------------------

issues_github_path = "python-scim/scim2-client"
