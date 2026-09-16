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
    "sphinx_design",
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
autosectionlabel_prefix_document = True
suppress_warnings = ["autosectionlabel.changelog"]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "scim2_models": ("https://scim2-models.readthedocs.io/en/latest/", None),
    "scim2_tester": ("https://scim2-tester.readthedocs.io/en/latest/", None),
    "scim2_cli": ("https://scim2-cli.readthedocs.io/en/latest/", None),
    "werkzeug": ("https://werkzeug.palletsprojects.com", None),
}

# -- Sibling projects ------------------------------------------------------

# Kept identical in the scim2-models, scim2-client, scim2-cli and scim2-tester
# documentations, so that any divergence shows up in a diff.
NAV_LINKS = [
    {
        "title": "Libraries",
        "children": [
            {
                "title": "scim2-models",
                "url": "https://scim2-models.readthedocs.io",
                "summary": "SCIM resources and messages as Pydantic models",
            },
            {
                "title": "scim2-client",
                "url": "https://scim2-client.readthedocs.io",
                "summary": "Pythonically build SCIM requests and parse SCIM responses",
            },
        ],
    },
    {
        "title": "Tools",
        "children": [
            {
                "title": "scim2-tester",
                "url": "https://scim2-tester.readthedocs.io",
                "summary": "Check a SCIM server for RFC compliance",
            },
            {
                "title": "scim2-cli",
                "url": "https://scim2-cli.readthedocs.io",
                "summary": "Query a SCIM server from the command line",
            },
            {
                "title": "scim2-server",
                "url": "https://github.com/python-scim/scim2-server",
                "summary": "A lightweight SCIM2 server prototype",
            },
            {
                "title": "pytest-scim2-server",
                "url": "https://github.com/pytest-dev/pytest-scim2-server",
                "summary": "A SCIM2 server fixture for pytest",
            },
        ],
    },
    {
        "title": "Integrations",
        "children": [
            {
                "title": "scim2-flask",
                "url": "https://scim2-flask.readthedocs.io",
                "summary": "Painless SCIM integration for Flask",
            },
            {
                "title": "scim2-django",
                "url": "https://scim2-django.readthedocs.io",
                "summary": "Painless SCIM integration for Django",
            },
            {
                "title": "scim2-fastapi",
                "url": "https://scim2-fastapi.readthedocs.io",
                "summary": "Painless SCIM integration for FastAPI",
            },
        ],
    },
]

# -- Options for HTML output ----------------------------------------------

html_theme = "shibuya"
# html_static_path = ["_static"]
html_baseurl = "https://scim2-client.readthedocs.io"
html_logo = "_static/python-scim.svg"
html_theme_options = {
    "globaltoc_expand_depth": 2,
    "accent_color": "lime",
    "github_url": "https://github.com/python-scim/scim2-client",
    "mastodon_url": "https://toot.aquilenet.fr/@yaal",
    "nav_links": NAV_LINKS,
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
