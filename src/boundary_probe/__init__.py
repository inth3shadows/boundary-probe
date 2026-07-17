__all__ = ["__version__"]

# Version is derived from the git tag by setuptools-scm (see pyproject `[tool.setuptools_scm]`).
# A build writes the resolved value to `_version.py`; prefer it. In a raw source tree that was
# never built, fall back to the installed dist metadata, then a sentinel — never a hand-edited
# literal (that is the drift class this scheme removes).
try:
    from ._version import __version__
except ImportError:
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _dist_version

    try:
        __version__ = _dist_version("boundary-probe")
    except PackageNotFoundError:
        __version__ = "0.0.0+unknown"

